import argparse
import os
import sys

from api.server import serve as grpc_serve
from dotenv import load_dotenv
from ingestor.pipeline import GithubDataPipeline
from loguru import logger
from storage.storage_manager import create_storage_manager
from utils.logging import configure_logging


def main():
    """Main entry point for the GitHub data pipeline application."""

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="GitHub Data Pipeline and API Server")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Ingest command
    ingest_parser = subparsers.add_parser("ingest", help="Ingest data from GitHub")
    ingest_parser.add_argument(
        "--full",
        action="store_true",
        help="Run full pipeline (users, teams, repos, access)",
    )
    ingest_parser.add_argument(
        "--repo", type=str, help="Update data for a specific repository"
    )
    ingest_parser.add_argument("--users", action="store_true", help="Update user data")
    ingest_parser.add_argument("--teams", action="store_true", help="Update team data")
    ingest_parser.add_argument(
        "--repos", action="store_true", help="Update repository data"
    )

    # Serve command
    serve_parser = subparsers.add_parser("serve", help="Start gRPC API server")
    serve_parser.add_argument(
        "--port", type=int, help="Port to listen on (default from .env)"
    )

    # Combined command
    combined_parser = subparsers.add_parser(
        "run", help="Run both ingestion and API server"
    )
    combined_parser.add_argument(
        "--full", action="store_true", help="Run full pipeline before starting server"
    )
    combined_parser.add_argument(
        "--port", type=int, help="Port to listen on (default from .env)"
    )

    args = parser.parse_args()

    # Load environment variables
    load_dotenv()

    # Configure logging
    log_level = os.getenv("LOG_LEVEL", "INFO")
    configure_logging(log_level)

    # Get configuration from environment
    github_token = os.getenv("GITHUB_TOKEN")
    github_org = os.getenv("GITHUB_ORG")
    storage_type = os.getenv("STORAGE_TYPE", "duckdb")
    storage_path = os.getenv("STORAGE_PATH", "data/github_data.db")
    default_port = int(os.getenv("GRPC_SERVER_PORT", "50051"))

    # Validate configuration
    if not github_token or not github_org:
        logger.error("GITHUB_TOKEN and GITHUB_ORG must be set in environment variables")
        sys.exit(1)

    # Create storage manager
    storage_manager = create_storage_manager(storage_type, storage_path)

    # Create data pipeline
    pipeline = GithubDataPipeline(
        github_token=github_token,
        github_organization=github_org,
        storage_manager=storage_manager,
    )

    # Execute the command
    if args.command == "ingest":
        logger.info("Starting data ingestion process")

        if args.full:
            pipeline.run_full_pipeline()
        elif args.repo:
            pipeline.update_repository_data(args.repo)
        elif args.users:
            pipeline.update_user_data()
        elif args.teams:
            pipeline.update_team_data()
        elif args.repos:
            pipeline.update_repository_data()
        else:
            logger.error(
                "No ingestion option specified. Use --full, --users, --teams, --repos, or --repo"
            )
            sys.exit(1)

        logger.info("Data ingestion completed")

    elif args.command == "serve":
        port = args.port or default_port
        logger.info(f"Starting gRPC server on port {port}")
        grpc_serve(port, storage_manager)

    elif args.command == "run":
        if args.full:
            logger.info("Running full pipeline before starting server")
            pipeline.run_full_pipeline()

        port = args.port or default_port
        logger.info(f"Starting gRPC server on port {port}")
        grpc_serve(port, storage_manager)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
