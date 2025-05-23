import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from github import Github, GithubException
from github.NamedUser import NamedUser
from github.Repository import Repository as GithubRepo
from github.Team import Team as GithubTeam
from loguru import logger
from models.github_models import (
    AccessLevel,
    Repository,
    RepositoryAccess,
    Team,
    TeamAccess,
    User,
    UserAccess,
)


class GitHubClient:
    """Client for interacting with GitHub API to fetch organization data."""

    def __init__(self, token: str, organization: str):
        """
        Initialize GitHub client.

        Args:
            token: GitHub API token
            organization: GitHub organization name
        """
        self.token = token
        self.organization = organization
        self.github_client = Github(token)

        try:
            self.org = self.github_client.get_organization(organization)
            logger.info(
                f"Successfully connected to GitHub organization: {organization}"
            )
        except GithubException as e:
            logger.error(
                f"Failed to connect to GitHub organization {organization}: {e}"
            )
            raise

    def get_repositories(self) -> List[Repository]:
        """
        Fetch all repositories from the organization.

        Returns:
            List of Repository objects
        """
        logger.info(f"Fetching repositories for organization: {self.organization}")

        repositories = []
        for repo in self.org.get_repos():
            try:
                repositories.append(self._convert_to_repository_model(repo))
                logger.debug(f"Fetched repository: {repo.name}")
            except Exception as e:
                logger.error(f"Error fetching repository {repo.name}: {e}")

        logger.info(f"Fetched {len(repositories)} repositories")
        return repositories

    def get_teams(self) -> List[Team]:
        """
        Fetch all teams from the organization.

        Returns:
            List of Team objects
        """
        logger.info(f"Fetching teams for organization: {self.organization}")

        teams = []
        for team in self.org.get_teams():
            try:
                teams.append(self._convert_to_team_model(team))
                logger.debug(f"Fetched team: {team.name}")
            except Exception as e:
                logger.error(f"Error fetching team {team.name}: {e}")

        logger.info(f"Fetched {len(teams)} teams")
        return teams

    def get_users(self) -> List[User]:
        """
        Fetch all users from the organization.

        Returns:
            List of User objects
        """
        logger.info(f"Fetching users for organization: {self.organization}")

        users = []
        for member in self.org.get_members():
            try:
                users.append(self._convert_to_user_model(member))
                logger.debug(f"Fetched user: {member.login}")
            except Exception as e:
                logger.error(f"Error fetching user {member.login}: {e}")

        logger.info(f"Fetched {len(users)} users")
        return users

    def get_repository_access(self, repository_name: str) -> RepositoryAccess:
        """
        Get access details for a specific repository.

        Args:
            repository_name: Name of the repository

        Returns:
            RepositoryAccess object with user and team access details
        """
        logger.info(f"Fetching access details for repository: {repository_name}")

        repo = self.org.get_repo(repository_name)
        repo_id = str(repo.id)

        # Get user access
        user_access = []
        for collaborator in repo.get_collaborators():
            try:
                permission = repo.get_collaborator_permission(collaborator)
                user_access.append(
                    UserAccess(
                        user_id=str(collaborator.id),
                        user_login=collaborator.login,
                        permission=self._convert_permission_string(permission),
                    )
                )
            except Exception as e:
                logger.error(
                    f"Error fetching user access for {collaborator.login}: {e}"
                )

        # Get team access
        team_access = []
        for team in repo.get_teams():
            try:
                permission = team.get_repo_permission(repo)
                team_access.append(
                    TeamAccess(
                        team_id=str(team.id),
                        team_name=team.name,
                        team_slug=team.slug,
                        permission=self._convert_permission_string(permission),
                    )
                )
            except Exception as e:
                logger.error(f"Error fetching team access for {team.name}: {e}")

        return RepositoryAccess(
            repository_id=repo_id,
            repository_name=repository_name,
            user_access=user_access,
            team_access=team_access,
        )

    def get_all_repository_access(self) -> List[RepositoryAccess]:
        """
        Get access details for all repositories in the organization.

        Returns:
            List of RepositoryAccess objects
        """
        logger.info(f"Fetching access details for all repositories")

        access_data = []
        for repo in self.org.get_repos():
            try:
                access_data.append(self.get_repository_access(repo.name))
                logger.debug(f"Fetched access for repository: {repo.name}")
            except Exception as e:
                logger.error(f"Error fetching access for repository {repo.name}: {e}")

        logger.info(f"Fetched access details for {len(access_data)} repositories")
        return access_data

    def _convert_to_repository_model(self, repo: GithubRepo) -> Repository:
        """Convert GitHub API repository to our model"""
        return Repository(
            id=str(repo.id),
            name=repo.name,
            full_name=repo.full_name,
            description=repo.description,
            is_private=repo.private,
            is_archived=repo.archived,
            is_template=repo.is_template,
            default_branch=repo.default_branch,
            forks_count=repo.forks_count,
            stargazers_count=repo.stargazers_count,
            watchers_count=repo.watchers_count,
            open_issues_count=repo.open_issues_count,
            created_at=repo.created_at,
            updated_at=repo.updated_at,
            pushed_at=repo.pushed_at,
        )

    def _convert_to_team_model(self, team: GithubTeam) -> Team:
        """Convert GitHub API team to our model"""
        # Fetch team members
        members = []
        for member in team.get_members():
            try:
                members.append(self._convert_to_user_model(member))
            except Exception as e:
                logger.error(f"Error fetching team member {member.login}: {e}")

        return Team(
            id=str(team.id),
            name=team.name,
            description=team.description,
            slug=team.slug,
            parent_team_id=str(team.parent.id) if team.parent else None,
            created_at=datetime.now(),  # GitHub API doesn't provide creation date for teams
            updated_at=datetime.now(),
            members=members,
        )

    def _convert_to_user_model(self, user: NamedUser) -> User:
        """Convert GitHub API user to our model"""
        # Check if MFA is enabled - note: requires admin scope
        has_mfa = False
        try:
            # This requires admin:org permission
            has_mfa = self.org.has_in_members_with_two_factor_auth(user)
        except GithubException:
            # If we don't have permission, just assume false
            logger.warning(f"Unable to check MFA status for user {user.login}")

        return User(
            id=str(user.id),
            login=user.login,
            name=user.name,
            email=user.email,
            has_mfa_enabled=has_mfa,
            created_at=user.created_at or datetime.now(),
            updated_at=user.updated_at or datetime.now(),
        )

    @staticmethod
    def _convert_permission_string(permission: str) -> AccessLevel:
        """Convert GitHub permission string to AccessLevel enum"""
        permission_map = {
            "admin": AccessLevel.ADMIN,
            "maintain": AccessLevel.MAINTAIN,
            "write": AccessLevel.WRITE,
            "triage": AccessLevel.TRIAGE,
            "read": AccessLevel.READ,
            "none": AccessLevel.NONE,
        }

        # Default to none if permission not recognized
        return permission_map.get(permission.lower(), AccessLevel.NONE)
