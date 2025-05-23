import uuid
from typing import List

from models.github_models import PolicyRule


def generate_sample_rules() -> List[PolicyRule]:
    """Generate a set of sample policy rules for GitHub data."""

    rules = [
        # 1. Check for users with admin access outside a defined team
        PolicyRule(
            id=str(uuid.uuid4()),
            name="admin_access_outside_team",
            description="Identifies users with admin access to repositories but who are not members of admin teams",
            policy_language="cel",
            policy_code="""
            repository.user_access.exists(u, 
                u.permission == "admin" && 
                !admin_team_members.contains(u.user_id)
            )
            """,
            severity="warning",
        ),
        # 2. Check for user-example access to gitops repositories
        PolicyRule(
            id=str(uuid.uuid4()),
            name="user_example_gitops_access",
            description="Checks if user-example has access to repositories named 'gitops'",
            policy_language="cel",
            policy_code="""
            repository.name.contains("gitops") && 
            repository.user_access.exists(u, u.user_login == "user-example")
            """,
            severity="error",
        ),
        # 3. Check for users without MFA enabled
        PolicyRule(
            id=str(uuid.uuid4()),
            name="user_without_mfa",
            description="Identifies users without Multi-Factor Authentication enabled",
            policy_language="cel",
            policy_code="""
            !user.has_mfa_enabled
            """,
            severity="critical",
        ),
        # 4. Check for repositories with too many admins (potential security risk)
        PolicyRule(
            id=str(uuid.uuid4()),
            name="too_many_admins",
            description="Identifies repositories with more than 3 users having admin access",
            policy_language="cel",
            policy_code="""
            repository.user_access.filter(u, u.permission == "admin").size() > 3
            """,
            severity="warning",
        ),
        # 5. Check for private repositories with public access
        PolicyRule(
            id=str(uuid.uuid4()),
            name="private_with_public_access",
            description="Identifies private repositories that have public access through teams",
            policy_language="cel",
            policy_code="""
            repository.is_private && 
            repository.team_access.exists(t, t.team_name == "public")
            """,
            severity="error",
        ),
        # 6. Check for inactive repositories
        PolicyRule(
            id=str(uuid.uuid4()),
            name="inactive_repository",
            description="Identifies repositories that haven't been updated in the last 6 months",
            policy_language="cel",
            policy_code="""
            timestamp(repository.updated_at) < timestamp.now() - duration("4380h")
            """,
            severity="info",
        ),
        # 7. Check for team ownership (every repo should have a team assigned)
        PolicyRule(
            id=str(uuid.uuid4()),
            name="missing_team_ownership",
            description="Identifies repositories without any team access assigned",
            policy_language="cel",
            policy_code="""
            repository.team_access.size() == 0
            """,
            severity="warning",
        ),
    ]

    return rules
