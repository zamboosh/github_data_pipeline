import json
import os
import time
from concurrent import futures
from datetime import datetime
from typing import Any, Dict, List, Optional

import grpc
from google.protobuf.timestamp_pb2 import Timestamp
from loguru import logger
from models.github_models import (
    PolicyRule,
    PolicyViolation,
    Repository,
    RepositoryAccess,
)
from policy_engine.engine import PolicyEngine
from policy_engine.rules import generate_sample_rules
from storage.storage_manager import StorageManager, create_storage_manager

# Import generated gRPC modules
# These will be generated from the proto file
import github_data_pipeline.proto.github_service_pb2 as github_pb2
import github_data_pipeline.proto.github_service_pb2_grpc as github_pb2_grpc


class GitHubDataServicer(github_pb2_grpc.GitHubDataServiceServicer):
    """Implementation of the gRPC GitHubDataService."""

    def __init__(self, storage_manager: StorageManager, policy_engine: PolicyEngine):
        """
        Initialize the service with storage and policy engine.

        Args:
            storage_manager: Storage manager for data access
            policy_engine: Policy engine for rule evaluation
        """
        self.storage_manager = storage_manager
        self.policy_engine = policy_engine

        # Load policy rules
        self.policy_engine.load_rules(generate_sample_rules())

    def ListRepositories(self, request, context):
        """
        List repositories with filtering options.

        Args:
            request: ListRepositoriesRequest with filter options
            context: gRPC context

        Returns:
            ListRepositoriesResponse with repositories list
        """
        try:
            # Get all repositories from storage
            repositories = self.storage_manager.get_all_repositories()

            # Apply filters if provided
            if request.name_filter:
                repositories = [
                    repo
                    for repo in repositories
                    if request.name_filter.lower() in repo.name.lower()
                ]

            if request.HasField("is_private"):
                repositories = [
                    repo
                    for repo in repositories
                    if repo.is_private == request.is_private
                ]

            if request.HasField("is_archived"):
                repositories = [
                    repo
                    for repo in repositories
                    if repo.is_archived == request.is_archived
                ]

            # Calculate total count before pagination
            total_count = len(repositories)

            # Apply pagination
            offset = request.offset if request.offset > 0 else 0
            limit = request.limit if request.limit > 0 else 100
            repositories = repositories[offset : offset + limit]

            # Convert to protobuf message
            response = github_pb2.ListRepositoriesResponse(total_count=total_count)

            for repo in repositories:
                pb_repo = github_pb2.Repository(
                    id=repo.id,
                    name=repo.name,
                    full_name=repo.full_name,
                    description=repo.description or "",
                    is_private=repo.is_private,
                    is_archived=repo.is_archived,
                    is_template=repo.is_template,
                    default_branch=repo.default_branch,
                    forks_count=repo.forks_count,
                    stargazers_count=repo.stargazers_count,
                    watchers_count=repo.watchers_count,
                    open_issues_count=repo.open_issues_count,
                )

                # Add timestamps if available
                if repo.created_at:
                    created_at = Timestamp()
                    created_at.FromDatetime(repo.created_at)
                    pb_repo.created_at.CopyFrom(created_at)

                if repo.updated_at:
                    updated_at = Timestamp()
                    updated_at.FromDatetime(repo.updated_at)
                    pb_repo.updated_at.CopyFrom(updated_at)

                if repo.pushed_at:
                    pushed_at = Timestamp()
                    pushed_at.FromDatetime(repo.pushed_at)
                    pb_repo.pushed_at.CopyFrom(pushed_at)

                response.repositories.append(pb_repo)

            return response

        except Exception as e:
            logger.error(f"Error in ListRepositories: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Internal error: {str(e)}")
            return github_pb2.ListRepositoriesResponse()

    def GetRepositoryAccess(self, request, context):
        """
        Get access details for a specific repository.

        Args:
            request: GetRepositoryAccessRequest with repository identifier
            context: gRPC context

        Returns:
            GetRepositoryAccessResponse with access details
        """
        try:
            # Get repository access data
            repository_name = request.repository_identifier
            access_data = self.storage_manager.get_repository_access(repository_name)

            if not access_data:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details(f"Repository not found: {repository_name}")
                return github_pb2.GetRepositoryAccessResponse()

            # Convert to protobuf message
            pb_access = github_pb2.RepositoryAccess(
                repository_id=access_data.repository_id,
                repository_name=access_data.repository_name,
            )

            # Add user access
            for user_access in access_data.user_access:
                pb_user_access = github_pb2.UserAccess(
                    user_id=user_access.user_id,
                    user_login=user_access.user_login,
                    permission=_convert_access_level_to_proto(user_access.permission),
                )
                pb_access.user_access.append(pb_user_access)

            # Add team access
            for team_access in access_data.team_access:
                pb_team_access = github_pb2.TeamAccess(
                    team_id=team_access.team_id,
                    team_name=team_access.team_name,
                    team_slug=team_access.team_slug,
                    permission=_convert_access_level_to_proto(team_access.permission),
                )
                pb_access.team_access.append(pb_team_access)

            return github_pb2.GetRepositoryAccessResponse(access=pb_access)

        except Exception as e:
            logger.error(f"Error in GetRepositoryAccess: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Internal error: {str(e)}")
            return github_pb2.GetRepositoryAccessResponse()

    def EvaluatePolicy(self, request, context):
        """
        Evaluate policies and return violations.

        Args:
            request: EvaluatePolicyRequest with filter options
            context: gRPC context

        Returns:
            EvaluatePolicyResponse with policy violations
        """
        try:
            # Convert request fields to appropriate types
            rule_ids = list(request.rule_ids) if request.rule_ids else None
            repository_ids = (
                list(request.repository_ids) if request.repository_ids else None
            )
            user_ids = list(request.user_ids) if request.user_ids else None
            team_ids = list(request.team_ids) if request.team_ids else None

            # Evaluate policies
            violations = self.policy_engine.evaluate_all_policies(
                rule_ids=rule_ids,
                repository_ids=repository_ids,
                user_ids=user_ids,
                team_ids=team_ids,
            )

            # Convert to protobuf message
            response = github_pb2.EvaluatePolicyResponse(
                total_evaluated=len(violations), total_violations=len(violations)
            )

            for violation in violations:
                pb_violation = github_pb2.PolicyViolation(
                    rule_id=violation.rule_id,
                    rule_name=violation.rule_name,
                    entity_type=violation.entity_type,
                    entity_id=violation.entity_id,
                    message=violation.message,
                    severity=violation.severity,
                )
                response.violations.append(pb_violation)

            return response

        except Exception as e:
            logger.error(f"Error in EvaluatePolicy: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Internal error: {str(e)}")
            return github_pb2.EvaluatePolicyResponse()

    def ListPolicyRules(self, request, context):
        """
        List available policy rules with filtering.

        Args:
            request: ListPolicyRulesRequest with filter options
            context: gRPC context

        Returns:
            ListPolicyRulesResponse with policy rules
        """
        try:
            # Get all rules from the policy engine
            rules = list(self.policy_engine.rules_cache.values())

            # Apply filters if provided
            if request.HasField("severity"):
                rules = [rule for rule in rules if rule.severity == request.severity]

            if request.HasField("policy_language"):
                rules = [
                    rule
                    for rule in rules
                    if rule.policy_language == request.policy_language
                ]

            # Convert to protobuf message
            response = github_pb2.ListPolicyRulesResponse()

            for rule in rules:
                pb_rule = github_pb2.PolicyRule(
                    id=rule.id,
                    name=rule.name,
                    description=rule.description,
                    policy_language=rule.policy_language,
                    policy_code=rule.policy_code,
                    severity=rule.severity,
                )
                response.rules.append(pb_rule)

            return response

        except Exception as e:
            logger.error(f"Error in ListPolicyRules: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Internal error: {str(e)}")
            return github_pb2.ListPolicyRulesResponse()


def _convert_access_level_to_proto(access_level):
    """Convert access level enum to proto enum value."""
    access_map = {
        "none": github_pb2.AccessLevel.NONE,
        "read": github_pb2.AccessLevel.READ,
        "triage": github_pb2.AccessLevel.TRIAGE,
        "write": github_pb2.AccessLevel.WRITE,
        "maintain": github_pb2.AccessLevel.MAINTAIN,
        "admin": github_pb2.AccessLevel.ADMIN,
    }
    return access_map.get(access_level.value, github_pb2.AccessLevel.NONE)


def serve(port, storage_manager: StorageManager):
    """
    Start the gRPC server.

    Args:
        port: Port to listen on
        storage_manager: Storage manager for data access
    """
    policy_engine = PolicyEngine(storage_manager)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    github_pb2_grpc.add_GitHubDataServiceServicer_to_server(
        GitHubDataServicer(storage_manager, policy_engine), server
    )
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    logger.info(f"Server started, listening on port {port}")

    try:
        # Keep thread alive
        while True:
            time.sleep(86400)  # Sleep for 1 day
    except KeyboardInterrupt:
        server.stop(0)
        logger.info("Server stopped")


if __name__ == "__main__":
    # Parse environment variables
    import os

    from dotenv import load_dotenv

    # Load environment variables
    load_dotenv()

    # Get configuration
    storage_type = os.getenv("STORAGE_TYPE", "duckdb")
    storage_path = os.getenv("STORAGE_PATH", "data/github_data.db")
    port = int(os.getenv("GRPC_SERVER_PORT", "50051"))

    # Configure logging
    log_level = os.getenv("LOG_LEVEL", "INFO")
    logger.remove()
    logger.add(sys.stderr, level=log_level)

    # Create storage manager
    storage_manager = create_storage_manager(storage_type, storage_path)

    # Start server
    serve(port, storage_manager)
