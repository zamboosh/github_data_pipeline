from datetime import datetime
from typing import Any, Dict, Optional

from ingestor.github_client import GitHubClient
from loguru import logger
from models.github_models import Repository, RepositoryAccess, Team, User
from storage.storage_manager import StorageManager


class GithubDataPipeline:
    """Pipeline for fetching GitHub data and storing it in the target storage."""

    def __init__(
        self,
        github_token: str,
        github_organization: str,
        storage_manager: StorageManager,
    ):
        """
        Initialize the GitHub data pipeline.

        Args:
            github_token: GitHub API token
            github_organization: GitHub organization name
            storage_manager: Storage manager instance for persisting data
        """
        self.github_client = GitHubClient(
            token=github_token, organization=github_organization
        )
        self.storage_manager = storage_manager

    def run_full_pipeline(self) -> None:
        """
        Run the complete data pipeline to extract and store all GitHub data.
        """
        logger.info("Starting GitHub data pipeline execution")

        # Fetch and store users
        logger.info("Fetching users")
        users = self.github_client.get_users()
        self.storage_manager.store_users(users)
        logger.info(f"Stored {len(users)} users")

        # Fetch and store teams
        logger.info("Fetching teams")
        teams = self.github_client.get_teams()
        self.storage_manager.store_teams(teams)
        logger.info(f"Stored {len(teams)} teams")

        # Fetch and store repositories
        logger.info("Fetching repositories")
        repositories = self.github_client.get_repositories()
        self.storage_manager.store_repositories(repositories)
        logger.info(f"Stored {len(repositories)} repositories")

        # Fetch and store repository access details
        logger.info("Fetching repository access data")
        access_data = self.github_client.get_all_repository_access()
        self.storage_manager.store_repository_access(access_data)
        logger.info(f"Stored access data for {len(access_data)} repositories")

        logger.info("GitHub data pipeline execution completed successfully")

    def update_repository_data(self, repository_name: Optional[str] = None) -> None:
        """
        Update data for a specific repository or all repositories.

        Args:
            repository_name: Name of repository to update, or None to update all
        """
        logger.info(
            f"Updating repository data for {'all repositories' if repository_name is None else repository_name}"
        )

        if repository_name:
            # Update a single repository
            try:
                repo = self.github_client.org.get_repo(repository_name)
                repository = self.github_client._convert_to_repository_model(repo)
                access = self.github_client.get_repository_access(repository_name)

                # Store the updated data
                self.storage_manager.store_repositories([repository])
                self.storage_manager.store_repository_access([access])

                logger.info(f"Updated data for repository: {repository_name}")
            except Exception as e:
                logger.error(f"Error updating repository {repository_name}: {e}")
        else:
            # Update all repositories
            repositories = self.github_client.get_repositories()
            access_data = self.github_client.get_all_repository_access()

            # Store the updated data
            self.storage_manager.store_repositories(repositories)
            self.storage_manager.store_repository_access(access_data)

            logger.info(f"Updated data for {len(repositories)} repositories")

    def update_user_data(self) -> None:
        """Update user data for the organization."""
        logger.info("Updating user data")

        users = self.github_client.get_users()
        self.storage_manager.store_users(users)

        logger.info(f"Updated data for {len(users)} users")

    def update_team_data(self) -> None:
        """Update team data for the organization."""
        logger.info("Updating team data")

        teams = self.github_client.get_teams()
        self.storage_manager.store_teams(teams)

        logger.info(f"Updated data for {len(teams)} teams")

    def extract_repository_statistics(self) -> Dict[str, Any]:
        """
        Extract statistics about repositories in the organization.

        Returns:
            Dictionary with repository statistics
        """
        logger.info("Extracting repository statistics")

        repositories = self.storage_manager.get_all_repositories()

        # Calculate statistics
        total_repos = len(repositories)
        private_repos = sum(1 for repo in repositories if repo.is_private)
        archived_repos = sum(1 for repo in repositories if repo.is_archived)

        # Most active repositories (by recent updates)
        active_repos = sorted(
            repositories, key=lambda r: r.updated_at or datetime.min, reverse=True
        )[:10]

        # Repositories with most stars
        starred_repos = sorted(
            repositories, key=lambda r: r.stargazers_count, reverse=True
        )[:10]

        stats = {
            "total_repositories": total_repos,
            "private_repositories": private_repos,
            "archived_repositories": archived_repos,
            "most_active_repositories": [
                {"name": repo.name, "updated_at": repo.updated_at}
                for repo in active_repos
            ],
            "most_starred_repositories": [
                {"name": repo.name, "stars": repo.stargazers_count}
                for repo in starred_repos
            ],
        }

        return stats
