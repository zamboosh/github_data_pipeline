#!/usr/bin/env python3
"""
Example client script for GitHub Data Pipeline gRPC API.

This script demonstrates how to use the gRPC API to interact with the
GitHub Data Pipeline service.
"""

import argparse
import json
import os
import sys

from dotenv import load_dotenv

# Helper function to convert protobuf to dict
from google.protobuf.json_format import MessageToDict
from loguru import logger
from utils.grpc_client import GitHubServiceClient
from utils.logging import configure_logging


def list_repositories(client, args):
    """List repositories with optional filtering."""
    response = client.list_repositories(
        name_filter=args.name,
        is_private=args.private,
        is_archived=args.archived,
        limit=args.limit,
        offset=args.offset,
    )

    repos = MessageToDict(response)

    # Print the results
    print(f"Found {response.total_count} repositories")

    if "repositories" not in repos or not repos["repositories"]:
        print("No repositories match the filter criteria")
        return

    for repo in repos["repositories"]:
        print(f"Repository: {repo.get('name', 'Unknown')}")
        print(f"  ID: {repo.get('id', 'Unknown')}")
        print(f"  Private: {repo.get('isPrivate', False)}")
        print(f"  Archived: {repo.get('isArchived', False)}")
        print(f"  Description: {repo.get('description', 'No description')}")
        print("")


def get_repository_access(client, args):
    """Get access details for a repository."""
    response = client.get_repository_access(args.repo)

    access = MessageToDict(response)

    if "access" not in access:
        print(f"Repository '{args.repo}' not found")
        return

    access = access["access"]

    print(f"Access details for repository: {access.get('repositoryName', args.repo)}")

    # Print user access
    print("\nUser Access:")
    if "userAccess" not in access or not access["userAccess"]:
        print("  No user access found")
    else:
        for user in access["userAccess"]:
            print(
                f"  {user.get('userLogin', 'Unknown')} - {user.get('permission', 'Unknown')}"
            )

    # Print team access
    print("\nTeam Access:")
    if "teamAccess" not in access or not access["teamAccess"]:
        print("  No team access found")
    else:
        for team in access["teamAccess"]:
            print(
                f"  {team.get('teamName', 'Unknown')} - {team.get('permission', 'Unknown')}"
            )


def evaluate_policy(client, args):
    """Evaluate policies and print violations."""
    response = client.evaluate_policy(
        rule_ids=args.rule_ids.split(",") if args.rule_ids else None,
        repository_ids=args.repo_ids.split(",") if args.repo_ids else None,
        user_ids=args.user_ids.split(",") if args.user_ids else None,
        team_ids=args.team_ids.split(",") if args.team_ids else None,
    )

    violations = MessageToDict(response)

    print(
        f"Evaluated {response.total_evaluated} policies, found {response.total_violations} violations"
    )

    if "violations" not in violations or not violations["violations"]:
        print("No policy violations found")
        return

    for violation in violations["violations"]:
        severity = violation.get("severity", "Unknown")
        severity_marker = {
            "info": "🔵",
            "warning": "🟡",
            "error": "🔴",
            "critical": "⛔",
        }.get(severity.lower(), "•")

        print(f"{severity_marker} {violation.get('message', 'Unknown violation')}")
        print(f"  Rule: {violation.get('ruleName', 'Unknown')}")
        print(
            f"  Entity: {violation.get('entityType', 'Unknown')} {violation.get('entityId', '')}"
        )
        print(f"  Severity: {severity}")
        print("")


def list_policy_rules(client, args):
    """List available policy rules."""
    response = client.list_policy_rules(
        severity=args.severity, policy_language=args.language
    )

    rules = MessageToDict(response)

    print("Available Policy Rules:")

    if "rules" not in rules or not rules["rules"]:
        print("No policy rules found")
        return

    for rule in rules["rules"]:
        severity = rule.get("severity", "Unknown")
        severity_marker = {
            "info": "🔵",
            "warning": "🟡",
            "error": "🔴",
            "critical": "⛔",
        }.get(severity.lower(), "•")

        print(f"{severity_marker} {rule.get('name', 'Unknown')}")
        print(f"  Description: {rule.get('description', 'No description')}")
        print(f"  Language: {rule.get('policyLanguage', 'Unknown')}")
        print(f"  Severity: {severity}")
        print("")


def export_json(client, args):
    """Export data to JSON format."""
    data = {}

    # Get repositories
    if args.repos:
        response = client.list_repositories(limit=1000)
        data["repositories"] = MessageToDict(response).get("repositories", [])

    # Get policy rules
    if args.rules:
        response = client.list_policy_rules()
        data["policy_rules"] = MessageToDict(response).get("rules", [])

    # Get policy violations
    if args.violations:
        response = client.evaluate_policy()
        data["policy_violations"] = MessageToDict(response).get("violations", [])

    # Write to file or stdout
    if args.output:
        with open(args.output, "w") as f:
            json.dump(data, f, indent=2)
        print(f"Data exported to {args.output}")
    else:
        print(json.dumps(data, indent=2))


def main():
    """Main entry point for the example client."""
    # Load environment variables
    load_dotenv()

    # Configure logging
    log_level = os.getenv("LOG_LEVEL", "INFO")
    configure_logging(log_level)

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="GitHub Data Pipeline API Client")
    parser.add_argument(
        "--server",
        default="localhost:50051",
        help="gRPC server address (default: localhost:50051)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # List repositories command
    list_repos_parser = subparsers.add_parser("list-repos", help="List repositories")
    list_repos_parser.add_argument("--name", help="Filter by name (substring match)")
    list_repos_parser.add_argument(
        "--private", action="store_true", help="Filter by private repositories"
    )
    list_repos_parser.add_argument(
        "--archived", action="store_true", help="Filter by archived repositories"
    )
    list_repos_parser.add_argument(
        "--limit", type=int, default=10, help="Maximum number of results to return"
    )
    list_repos_parser.add_argument(
        "--offset", type=int, default=0, help="Offset for pagination"
    )

    # Get repository access command
    get_access_parser = subparsers.add_parser(
        "get-access", help="Get repository access details"
    )
    get_access_parser.add_argument("repo", help="Repository name")

    # Evaluate policy command
    evaluate_parser = subparsers.add_parser("evaluate", help="Evaluate policies")
    evaluate_parser.add_argument(
        "--rule-ids", help="Comma-separated list of rule IDs to evaluate"
    )
    evaluate_parser.add_argument(
        "--repo-ids", help="Comma-separated list of repository IDs to evaluate against"
    )
    evaluate_parser.add_argument(
        "--user-ids", help="Comma-separated list of user IDs to evaluate against"
    )
    evaluate_parser.add_argument(
        "--team-ids", help="Comma-separated list of team IDs to evaluate against"
    )

    # List policy rules command
    list_rules_parser = subparsers.add_parser("list-rules", help="List policy rules")
    list_rules_parser.add_argument("--severity", help="Filter by severity")
    list_rules_parser.add_argument("--language", help="Filter by policy language")

    # Export data command
    export_parser = subparsers.add_parser("export", help="Export data to JSON")
    export_parser.add_argument(
        "--repos", action="store_true", help="Export repositories"
    )
    export_parser.add_argument(
        "--rules", action="store_true", help="Export policy rules"
    )
    export_parser.add_argument(
        "--violations", action="store_true", help="Export policy violations"
    )
    export_parser.add_argument("--output", help="Output file path (default: stdout)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Create client
    with GitHubServiceClient(args.server) as client:
        try:
            # Dispatch to appropriate command handler
            if args.command == "list-repos":
                list_repositories(client, args)
            elif args.command == "get-access":
                get_repository_access(client, args)
            elif args.command == "evaluate":
                evaluate_policy(client, args)
            elif args.command == "list-rules":
                list_policy_rules(client, args)
            elif args.command == "export":
                export_json(client, args)
        except Exception as e:
            logger.error(f"Error: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
