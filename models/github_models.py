from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class AccessLevel(str, Enum):
    NONE = "none"
    READ = "read"
    TRIAGE = "triage"
    WRITE = "write"
    MAINTAIN = "maintain"
    ADMIN = "admin"


class User(BaseModel):
    """GitHub user model"""

    id: str
    login: str
    name: Optional[str] = None
    email: Optional[str] = None
    has_mfa_enabled: bool
    created_at: datetime
    updated_at: datetime


class Team(BaseModel):
    """GitHub team model"""

    id: str
    name: str
    description: Optional[str] = None
    slug: str
    parent_team_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    members: List["User"] = Field(default_factory=list)


class Repository(BaseModel):
    """GitHub repository model"""

    id: str
    name: str
    full_name: str
    description: Optional[str] = None
    is_private: bool
    is_archived: bool = False
    is_template: bool = False
    default_branch: str = "main"
    forks_count: int = 0
    stargazers_count: int = 0
    watchers_count: int = 0
    open_issues_count: int = 0
    created_at: datetime
    updated_at: datetime
    pushed_at: Optional[datetime] = None


class UserAccess(BaseModel):
    """User access to a repository"""

    user_id: str
    user_login: str
    permission: AccessLevel


class TeamAccess(BaseModel):
    """Team access to a repository"""

    team_id: str
    team_name: str
    team_slug: str
    permission: AccessLevel


class RepositoryAccess(BaseModel):
    """Access details for a repository"""

    repository_id: str
    repository_name: str
    user_access: List[UserAccess] = Field(default_factory=list)
    team_access: List[TeamAccess] = Field(default_factory=list)


class PolicyRule(BaseModel):
    """Policy rule definition"""

    id: str
    name: str
    description: str
    policy_language: str  # "opa", "cel", "custom"
    policy_code: str
    severity: str  # "info", "warning", "error", "critical"


class PolicyViolation(BaseModel):
    """Policy violation details"""

    rule_id: str
    rule_name: str
    entity_type: str  # "user", "repository", "team", "access"
    entity_id: str
    message: str
    severity: str
