import json
import os
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import duckdb
import pandas as pd
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


class StorageManager(ABC):
    """Abstract base class for storage managers."""

    @abstractmethod
    def store_users(self, users: List[User]) -> None:
        """Store users in the storage."""
        pass

    @abstractmethod
    def store_teams(self, teams: List[Team]) -> None:
        """Store teams in the storage."""
        pass

    @abstractmethod
    def store_repositories(self, repositories: List[Repository]) -> None:
        """Store repositories in the storage."""
        pass

    @abstractmethod
    def store_repository_access(self, access_data: List[RepositoryAccess]) -> None:
        """Store repository access data in the storage."""
        pass

    @abstractmethod
    def get_all_users(self) -> List[User]:
        """Get all users from the storage."""
        pass

    @abstractmethod
    def get_all_teams(self) -> List[Team]:
        """Get all teams from the storage."""
        pass

    @abstractmethod
    def get_all_repositories(self) -> List[Repository]:
        """Get all repositories from the storage."""
        pass

    @abstractmethod
    def get_repository_access(self, repository_name: str) -> Optional[RepositoryAccess]:
        """Get access data for a specific repository."""
        pass

    @abstractmethod
    def get_all_repository_access(self) -> List[RepositoryAccess]:
        """Get access data for all repositories."""
        pass


class DuckDBStorageManager(StorageManager):
    """DuckDB storage manager implementation."""

    def __init__(self, db_path: str):
        """
        Initialize DuckDB storage manager.

        Args:
            db_path: Path to the DuckDB database file
        """
        self.db_path = db_path

        # Create parent directories if they don't exist
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)

        # Initialize database and create tables if they don't exist
        self.conn = duckdb.connect(db_path)
        self._create_tables()

        logger.info(f"Initialized DuckDB storage manager with database: {db_path}")

    def _create_tables(self) -> None:
        """Create database tables if they don't exist."""

        # Users table
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id VARCHAR PRIMARY KEY,
                login VARCHAR NOT NULL,
                name VARCHAR,
                email VARCHAR,
                has_mfa_enabled BOOLEAN,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
        """
        )

        # Teams table
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS teams (
                id VARCHAR PRIMARY KEY,
                name VARCHAR NOT NULL,
                description VARCHAR,
                slug VARCHAR NOT NULL,
                parent_team_id VARCHAR,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
        """
        )

        # Team members (many-to-many relationship)
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS team_members (
                team_id VARCHAR,
                user_id VARCHAR,
                PRIMARY KEY (team_id, user_id)
            )
        """
        )

        # Repositories table
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS repositories (
                id VARCHAR PRIMARY KEY,
                name VARCHAR NOT NULL,
                full_name VARCHAR NOT NULL,
                description VARCHAR,
                is_private BOOLEAN,
                is_archived BOOLEAN,
                is_template BOOLEAN,
                default_branch VARCHAR,
                forks_count INTEGER,
                stargazers_count INTEGER,
                watchers_count INTEGER,
                open_issues_count INTEGER,
                created_at TIMESTAMP,
                updated_at TIMESTAMP,
                pushed_at TIMESTAMP
            )
        """
        )

        # User repository access
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS user_repository_access (
                repository_id VARCHAR,
                user_id VARCHAR,
                user_login VARCHAR,
                permission VARCHAR,
                PRIMARY KEY (repository_id, user_id)
            )
        """
        )

        # Team repository access
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS team_repository_access (
                repository_id VARCHAR,
                team_id VARCHAR,
                team_name VARCHAR,
                team_slug VARCHAR,
                permission VARCHAR,
                PRIMARY KEY (repository_id, team_id)
            )
        """
        )

        logger.info("Database tables created/verified")

    def store_users(self, users: List[User]) -> None:
        """
        Store users in DuckDB.

        Args:
            users: List of User objects to store
        """
        if not users:
            logger.info("No users to store")
            return

        # Convert to DataFrame for efficient insertion
        df = pd.DataFrame([user.dict() for user in users])

        # Store users in database (upsert)
        self.conn.execute(
            """
            DELETE FROM users WHERE id IN (
                SELECT id FROM df
            )
        """
        )
        self.conn.execute("INSERT INTO users SELECT * FROM df")

        logger.info(f"Stored {len(users)} users in DuckDB")

    def store_teams(self, teams: List[Team]) -> None:
        """
        Store teams and their members in DuckDB.

        Args:
            teams: List of Team objects to store
        """
        if not teams:
            logger.info("No teams to store")
            return

        # Extract team data
        team_data = []
        team_members = []

        for team in teams:
            # Extract team data without members
            team_dict = team.dict(exclude={"members"})
            team_data.append(team_dict)

            # Extract team membership
            for member in team.members:
                team_members.append({"team_id": team.id, "user_id": member.id})

        # Convert to DataFrames
        teams_df = pd.DataFrame(team_data)

        # Store teams in database (upsert)
        self.conn.execute(
            """
            DELETE FROM teams WHERE id IN (
                SELECT id FROM teams_df
            )
        """
        )
        self.conn.execute("INSERT INTO teams SELECT * FROM teams_df")

        # Store team members if there are any
        if team_members:
            members_df = pd.DataFrame(team_members)

            # Delete existing team memberships for these teams
            self.conn.execute(
                """
                DELETE FROM team_members WHERE team_id IN (
                    SELECT id FROM teams_df
                )
            """
            )
            self.conn.execute("INSERT INTO team_members SELECT * FROM members_df")

        logger.info(f"Stored {len(teams)} teams with their members in DuckDB")

    def store_repositories(self, repositories: List[Repository]) -> None:
        """
        Store repositories in DuckDB.

        Args:
            repositories: List of Repository objects to store
        """
        if not repositories:
            logger.info("No repositories to store")
            return

        # Convert to DataFrame
        df = pd.DataFrame([repo.dict() for repo in repositories])

        # Store repositories in database (upsert)
        self.conn.execute(
            """
            DELETE FROM repositories WHERE id IN (
                SELECT id FROM df
            )
        """
        )
        self.conn.execute("INSERT INTO repositories SELECT * FROM df")

        logger.info(f"Stored {len(repositories)} repositories in DuckDB")

    def store_repository_access(self, access_data: List[RepositoryAccess]) -> None:
        """
        Store repository access data in DuckDB.

        Args:
            access_data: List of RepositoryAccess objects to store
        """
        if not access_data:
            logger.info("No repository access data to store")
            return

        # Extract user access data
        user_access = []
        for access in access_data:
            for user_access_item in access.user_access:
                user_access.append(
                    {
                        "repository_id": access.repository_id,
                        "user_id": user_access_item.user_id,
                        "user_login": user_access_item.user_login,
                        "permission": user_access_item.permission,
                    }
                )

        # Extract team access data
        team_access = []
        for access in access_data:
            for team_access_item in access.team_access:
                team_access.append(
                    {
                        "repository_id": access.repository_id,
                        "team_id": team_access_item.team_id,
                        "team_name": team_access_item.team_name,
                        "team_slug": team_access_item.team_slug,
                        "permission": team_access_item.permission,
                    }
                )

        # Delete existing access data for these repositories
        repo_ids = [access.repository_id for access in access_data]
        repo_ids_str = ", ".join(f"'{id}'" for id in repo_ids)

        if repo_ids:
            # Delete existing user access for these repositories
            self.conn.execute(
                f"""
                DELETE FROM user_repository_access 
                WHERE repository_id IN ({repo_ids_str})
            """
            )

            # Delete existing team access for these repositories
            self.conn.execute(
                f"""
                DELETE FROM team_repository_access 
                WHERE repository_id IN ({repo_ids_str})
            """
            )

        # Store new user access data
        if user_access:
            user_access_df = pd.DataFrame(user_access)
            self.conn.execute(
                "INSERT INTO user_repository_access SELECT * FROM user_access_df"
            )

        # Store new team access data
        if team_access:
            team_access_df = pd.DataFrame(team_access)
            self.conn.execute(
                "INSERT INTO team_repository_access SELECT * FROM team_access_df"
            )

        logger.info(f"Stored access data for {len(access_data)} repositories in DuckDB")

    def get_all_users(self) -> List[User]:
        """
        Get all users from DuckDB.

        Returns:
            List of User objects
        """
        query = "SELECT * FROM users"
        result = self.conn.execute(query).fetchdf()

        if result.empty:
            return []

        return [User(**row) for row in result.to_dict("records")]

    def get_all_teams(self) -> List[Team]:
        """
        Get all teams with their members from DuckDB.

        Returns:
            List of Team objects with their members
        """
        # Get all teams
        teams_query = "SELECT * FROM teams"
        teams_df = self.conn.execute(teams_query).fetchdf()

        if teams_df.empty:
            return []

        # Get all team members
        members_query = """
            SELECT tm.team_id, u.* 
            FROM team_members tm
            JOIN users u ON tm.user_id = u.id
        """
        members_df = self.conn.execute(members_query).fetchdf()

        # Convert to Team objects
        teams = []
        for _, team_row in teams_df.iterrows():
            team_dict = team_row.to_dict()
            team_id = team_dict["id"]

            # Find members for this team
            team_members = []
            if not members_df.empty:
                team_member_rows = members_df[members_df["team_id"] == team_id]
                for _, member_row in team_member_rows.iterrows():
                    member_dict = member_row.to_dict()
                    # Remove team_id from member dict
                    del member_dict["team_id"]
                    team_members.append(User(**member_dict))

            team_dict["members"] = team_members
            teams.append(Team(**team_dict))

        return teams

    def get_all_repositories(self) -> List[Repository]:
        """
        Get all repositories from DuckDB.

        Returns:
            List of Repository objects
        """
        query = "SELECT * FROM repositories"
        result = self.conn.execute(query).fetchdf()

        if result.empty:
            return []

        return [Repository(**row) for row in result.to_dict("records")]

    def get_repository_access(self, repository_name: str) -> Optional[RepositoryAccess]:
        """
        Get access data for a specific repository.

        Args:
            repository_name: Name of the repository

        Returns:
            RepositoryAccess object or None if not found
        """
        # Get repository ID from name
        repo_query = f"SELECT id FROM repositories WHERE name = '{repository_name}'"
        repo_result = self.conn.execute(repo_query).fetchone()

        if not repo_result:
            logger.warning(f"Repository not found: {repository_name}")
            return None

        repository_id = repo_result[0]

        # Get user access
        user_query = f"""
            SELECT * FROM user_repository_access 
            WHERE repository_id = '{repository_id}'
        """
        user_df = self.conn.execute(user_query).fetchdf()

        # Get team access
        team_query = f"""
            SELECT * FROM team_repository_access 
            WHERE repository_id = '{repository_id}'
        """
        team_df = self.conn.execute(team_query).fetchdf()

        # Convert to access objects
        user_access = []
        if not user_df.empty:
            for _, row in user_df.iterrows():
                user_access.append(
                    UserAccess(
                        user_id=row["user_id"],
                        user_login=row["user_login"],
                        permission=row["permission"],
                    )
                )

        team_access = []
        if not team_df.empty:
            for _, row in team_df.iterrows():
                team_access.append(
                    TeamAccess(
                        team_id=row["team_id"],
                        team_name=row["team_name"],
                        team_slug=row["team_slug"],
                        permission=row["permission"],
                    )
                )

        return RepositoryAccess(
            repository_id=repository_id,
            repository_name=repository_name,
            user_access=user_access,
            team_access=team_access,
        )

    def get_all_repository_access(self) -> List[RepositoryAccess]:
        """
        Get access data for all repositories.

        Returns:
            List of RepositoryAccess objects
        """
        # Get all repositories
        repos_query = "SELECT id, name FROM repositories"
        repos_df = self.conn.execute(repos_query).fetchdf()

        if repos_df.empty:
            return []

        # Get all access data
        access_data = []
        for _, repo_row in repos_df.iterrows():
            repo_id = repo_row["id"]
            repo_name = repo_row["name"]

            access = self.get_repository_access(repo_name)
            if access:
                access_data.append(access)

        return access_data

    def close(self) -> None:
        """Close the database connection."""
        self.conn.close()
        logger.info("Closed DuckDB connection")


class JSONLStorageManager(StorageManager):
    """Storage manager using JSONL files."""

    def __init__(self, storage_dir: str):
        """
        Initialize JSONL storage manager.

        Args:
            storage_dir: Directory for storing JSONL files
        """
        self.storage_dir = Path(storage_dir)

        # Create directories if they don't exist
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        # Define file paths
        self.users_file = self.storage_dir / "users.jsonl"
        self.teams_file = self.storage_dir / "teams.jsonl"
        self.repositories_file = self.storage_dir / "repositories.jsonl"
        self.access_file = self.storage_dir / "repository_access.jsonl"

        logger.info(f"Initialized JSONL storage manager with directory: {storage_dir}")

    def store_users(self, users: List[User]) -> None:
        """
        Store users in JSONL format.

        Args:
            users: List of User objects to store
        """
        if not users:
            logger.info("No users to store")
            return

        # Convert datetime objects to ISO format
        serialized_users = []
        for user in users:
            user_dict = user.dict()
            user_dict["created_at"] = (
                user.created_at.isoformat() if user.created_at else None
            )
            user_dict["updated_at"] = (
                user.updated_at.isoformat() if user.updated_at else None
            )
            serialized_users.append(user_dict)

        # Write to file (overwriting existing file)
        with open(self.users_file, "w") as f:
            for user in serialized_users:
                f.write(json.dumps(user) + "\n")

        logger.info(f"Stored {len(users)} users in JSONL format")

    def store_teams(self, teams: List[Team]) -> None:
        """
        Store teams in JSONL format.

        Args:
            teams: List of Team objects to store
        """
        if not teams:
            logger.info("No teams to store")
            return

        # Convert datetime objects to ISO format and handle members
        serialized_teams = []
        for team in teams:
            team_dict = team.dict(exclude={"members"})
            team_dict["created_at"] = (
                team.created_at.isoformat() if team.created_at else None
            )
            team_dict["updated_at"] = (
                team.updated_at.isoformat() if team.updated_at else None
            )

            # Add member IDs
            team_dict["member_ids"] = [member.id for member in team.members]
            serialized_teams.append(team_dict)

        # Write to file (overwriting existing file)
        with open(self.teams_file, "w") as f:
            for team in serialized_teams:
                f.write(json.dumps(team) + "\n")

        logger.info(f"Stored {len(teams)} teams in JSONL format")

    def store_repositories(self, repositories: List[Repository]) -> None:
        """
        Store repositories in JSONL format.

        Args:
            repositories: List of Repository objects to store
        """
        if not repositories:
            logger.info("No repositories to store")
            return

        # Convert datetime objects to ISO format
        serialized_repos = []
        for repo in repositories:
            repo_dict = repo.dict()
            repo_dict["created_at"] = (
                repo.created_at.isoformat() if repo.created_at else None
            )
            repo_dict["updated_at"] = (
                repo.updated_at.isoformat() if repo.updated_at else None
            )
            repo_dict["pushed_at"] = (
                repo.pushed_at.isoformat() if repo.pushed_at else None
            )
            serialized_repos.append(repo_dict)

        # Write to file (overwriting existing file)
        with open(self.repositories_file, "w") as f:
            for repo in serialized_repos:
                f.write(json.dumps(repo) + "\n")

        logger.info(f"Stored {len(repositories)} repositories in JSONL format")

    def store_repository_access(self, access_data: List[RepositoryAccess]) -> None:
        """
        Store repository access data in JSONL format.

        Args:
            access_data: List of RepositoryAccess objects to store
        """
        if not access_data:
            logger.info("No repository access data to store")
            return

        # Convert to serializable format
        serialized_access = []
        for access in access_data:
            access_dict = access.dict()

            # Serialize the access levels
            for user_access in access_dict["user_access"]:
                user_access["permission"] = user_access["permission"].value

            for team_access in access_dict["team_access"]:
                team_access["permission"] = team_access["permission"].value

            serialized_access.append(access_dict)

        # Write to file (overwriting existing file)
        with open(self.access_file, "w") as f:
            for access in serialized_access:
                f.write(json.dumps(access) + "\n")

        logger.info(
            f"Stored access data for {len(access_data)} repositories in JSONL format"
        )

    def get_all_users(self) -> List[User]:
        """
        Get all users from JSONL.

        Returns:
            List of User objects
        """
        if not self.users_file.exists():
            return []

        users = []
        with open(self.users_file, "r") as f:
            for line in f:
                user_dict = json.loads(line)

                # Convert ISO format strings back to datetime
                if user_dict.get("created_at"):
                    user_dict["created_at"] = datetime.fromisoformat(
                        user_dict["created_at"]
                    )
                if user_dict.get("updated_at"):
                    user_dict["updated_at"] = datetime.fromisoformat(
                        user_dict["updated_at"]
                    )

                users.append(User(**user_dict))

        return users

    def get_all_teams(self) -> List[Team]:
        """
        Get all teams from JSONL.

        Returns:
            List of Team objects with members
        """
        if not self.teams_file.exists() or not self.users_file.exists():
            return []

        # Load all users first for efficient lookup
        users_by_id = {user.id: user for user in self.get_all_users()}

        teams = []
        with open(self.teams_file, "r") as f:
            for line in f:
                team_dict = json.loads(line)

                # Convert ISO format strings back to datetime
                if team_dict.get("created_at"):
                    team_dict["created_at"] = datetime.fromisoformat(
                        team_dict["created_at"]
                    )
                if team_dict.get("updated_at"):
                    team_dict["updated_at"] = datetime.fromisoformat(
                        team_dict["updated_at"]
                    )

                # Get members from member_ids
                member_ids = team_dict.pop("member_ids", [])
                members = [users_by_id[id] for id in member_ids if id in users_by_id]

                team_dict["members"] = members
                teams.append(Team(**team_dict))

        return teams

    def get_all_repositories(self) -> List[Repository]:
        """
        Get all repositories from JSONL.

        Returns:
            List of Repository objects
        """
        if not self.repositories_file.exists():
            return []

        repositories = []
        with open(self.repositories_file, "r") as f:
            for line in f:
                repo_dict = json.loads(line)

                # Convert ISO format strings back to datetime
                if repo_dict.get("created_at"):
                    repo_dict["created_at"] = datetime.fromisoformat(
                        repo_dict["created_at"]
                    )
                if repo_dict.get("updated_at"):
                    repo_dict["updated_at"] = datetime.fromisoformat(
                        repo_dict["updated_at"]
                    )
                if repo_dict.get("pushed_at"):
                    repo_dict["pushed_at"] = datetime.fromisoformat(
                        repo_dict["pushed_at"]
                    )

                repositories.append(Repository(**repo_dict))

        return repositories

    def get_repository_access(self, repository_name: str) -> Optional[RepositoryAccess]:
        """
        Get access data for a specific repository.

        Args:
            repository_name: Name of the repository

        Returns:
            RepositoryAccess object or None if not found
        """
        if not self.access_file.exists():
            return None

        # Load all access data
        all_access = self.get_all_repository_access()

        # Find access data for the specified repository
        for access in all_access:
            if access.repository_name == repository_name:
                return access

        return None

    def get_all_repository_access(self) -> List[RepositoryAccess]:
        """
        Get access data for all repositories.

        Returns:
            List of RepositoryAccess objects
        """
        if not self.access_file.exists():
            return []

        access_data = []
        with open(self.access_file, "r") as f:
            for line in f:
                access_dict = json.loads(line)

                # Convert permission strings back to enum values
                for user_access in access_dict["user_access"]:
                    user_access["permission"] = AccessLevel(user_access["permission"])

                for team_access in access_dict["team_access"]:
                    team_access["permission"] = AccessLevel(team_access["permission"])

                access_data.append(RepositoryAccess(**access_dict))

        return access_data


def create_storage_manager(storage_type: str, storage_path: str) -> StorageManager:
    """
    Factory function to create the appropriate storage manager.

    Args:
        storage_type: Type of storage ("duckdb" or "jsonl")
        storage_path: Path to storage (DB file or directory)

    Returns:
        StorageManager instance
    """
    if storage_type.lower() == "duckdb":
        return DuckDBStorageManager(storage_path)
    elif storage_type.lower() == "jsonl":
        return JSONLStorageManager(storage_path)
    else:
        raise ValueError(f"Unsupported storage type: {storage_type}")
