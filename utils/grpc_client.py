from typing import Tuple

import grpc

# Import generated gRPC modules
from github_data_pipeline.proto import github_service_pb2_grpc


def create_client(
    server_address: str = "localhost:50051",
) -> Tuple[grpc.Channel, github_service_pb2_grpc.GitHubDataServiceStub]:
    """
    Create a gRPC client for GitHubDataService.

    Args:
        server_address: gRPC server address in the format "host:port"

    Returns:
        Tuple of (channel, stub) for interacting with the service
    """
    # Create a gRPC channel
    channel = grpc.insecure_channel(server_address)

    # Create a stub (client)
    stub = github_service_pb2_grpc.GitHubDataServiceStub(channel)

    return channel, stub


class GitHubServiceClient:
    """Client wrapper for GitHubDataService gRPC service."""

    def __init__(self, server_address: str = "localhost:50051"):
        """
        Initialize the client.

        Args:
            server_address: gRPC server address in the format "host:port"
        """
        self.channel, self.stub = create_client(server_address)

    def close(self):
        """Close the gRPC channel."""
        self.channel.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

    # Helper methods for common operations
    def list_repositories(
        self, name_filter=None, is_private=None, is_archived=None, limit=100, offset=0
    ):
        """List repositories with filtering."""
        from github_data_pipeline.proto import github_service_pb2

        request = github_service_pb2.ListRepositoriesRequest(limit=limit, offset=offset)

        if name_filter:
            request.name_filter = name_filter

        if is_private is not None:
            request.is_private = is_private

        if is_archived is not None:
            request.is_archived = is_archived

        return self.stub.ListRepositories(request)

    def get_repository_access(self, repository_name):
        """Get access details for a repository."""
        from github_data_pipeline.proto import github_service_pb2

        request = github_service_pb2.GetRepositoryAccessRequest(
            repository_identifier=repository_name
        )

        return self.stub.GetRepositoryAccess(request)

    def evaluate_policy(
        self, rule_ids=None, repository_ids=None, user_ids=None, team_ids=None
    ):
        """Evaluate policies and get violations."""
        from github_data_pipeline.proto import github_service_pb2

        request = github_service_pb2.EvaluatePolicyRequest()

        if rule_ids:
            request.rule_ids.extend(rule_ids)

        if repository_ids:
            request.repository_ids.extend(repository_ids)

        if user_ids:
            request.user_ids.extend(user_ids)

        if team_ids:
            request.team_ids.extend(team_ids)

        return self.stub.EvaluatePolicy(request)

    def list_policy_rules(self, severity=None, policy_language=None):
        """List available policy rules."""
        from github_data_pipeline.proto import github_service_pb2

        request = github_service_pb2.ListPolicyRulesRequest()

        if severity:
            request.severity = severity

        if policy_language:
            request.policy_language = policy_language

        return self.stub.ListPolicyRules(request)
