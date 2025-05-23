from typing import Any, Dict, List, Optional, Set

import celpy
from celpy.celtypes import BoolType
from loguru import logger
from models.github_models import PolicyRule, PolicyViolation
from storage.storage_manager import StorageManager


class PolicyEngine:
    """
    Policy engine for evaluating rules against GitHub data.

    This engine supports CEL (Common Expression Language) rules.
    """

    def __init__(self, storage_manager: StorageManager):
        """
        Initialize the policy engine.

        Args:
            storage_manager: Storage manager for accessing GitHub data
        """
        self.storage_manager = storage_manager
        self.rules_cache: Dict[str, PolicyRule] = {}  # Cache rules by ID

    def load_rules(self, rules: List[PolicyRule]) -> None:
        """
        Load rules into the engine.

        Args:
            rules: List of policy rules to load
        """
        for rule in rules:
            if rule.policy_language.lower() != "cel":
                logger.warning(
                    f"Skipping rule {rule.id}: Only CEL language is supported"
                )
                continue
            self.rules_cache[rule.id] = rule

        logger.info(f"Loaded {len(self.rules_cache)} CEL policy rules")

    def evaluate_all_policies(
        self,
        rule_ids: Optional[List[str]] = None,
        repository_ids: Optional[List[str]] = None,
        user_ids: Optional[List[str]] = None,
        team_ids: Optional[List[str]] = None,
    ) -> List[PolicyViolation]:
        """
        Evaluate all policies against all entities or filtered subsets.

        Args:
            rule_ids: Optional list of rule IDs to evaluate (if None, evaluate all)
            repository_ids: Optional list of repository IDs to evaluate against
            user_ids: Optional list of user IDs to evaluate against
            team_ids: Optional list of team IDs to evaluate against

        Returns:
            List of policy violations
        """
        # Collect all violations
        violations = []

        # Determine which rules to evaluate
        rules_to_evaluate = []
        if rule_ids:
            rules_to_evaluate = [
                self.rules_cache[rule_id]
                for rule_id in rule_ids
                if rule_id in self.rules_cache
            ]
        else:
            rules_to_evaluate = list(self.rules_cache.values())

        if not rules_to_evaluate:
            logger.warning("No rules to evaluate")
            return []

        # Get data from storage
        repositories = self.storage_manager.get_all_repositories()
        users = self.storage_manager.get_all_users()
        teams = self.storage_manager.get_all_teams()
        access_data = self.storage_manager.get_all_repository_access()

        # Apply filters if provided
        if repository_ids:
            repositories = [r for r in repositories if r.id in repository_ids]
        if user_ids:
            users = [u for u in users if u.id in user_ids]
        if team_ids:
            teams = [t for t in teams if t.id in team_ids]

        # Create lookup mappings for faster access
        user_map = {user.id: user for user in users}
        team_map = {team.id: team for team in teams}
        repository_map = {repo.id: repo for repo in repositories}
        access_map = {access.repository_id: access for access in access_data}

        # Create team membership lookup
        team_members: Dict[str, Set[str]] = {}  # team_id -> set(user_ids)
        for team in teams:
            team_members[team.id] = {member.id for member in team.members}

        # Evaluate user-focused rules
        logger.info(f"Evaluating user-focused rules against {len(users)} users")
        for rule in rules_to_evaluate:
            if "user" in rule.policy_code.lower():
                for user in users:
                    try:
                        context = {
                            "user": user.model_dump(),
                            "teams": [
                                team.model_dump()
                                for team in teams
                                if user.id in team_members.get(team.id, set())
                            ],
                        }

                        result = self._evaluate_rule(rule, context)
                        if result:
                            violations.append(
                                PolicyViolation(
                                    rule_id=rule.id,
                                    rule_name=rule.name,
                                    entity_type="user",
                                    entity_id=user.id,
                                    message=f"User {user.login} violates policy {rule.name}",
                                    severity=rule.severity,
                                )
                            )
                    except Exception as e:
                        logger.error(
                            f"Error evaluating rule {rule.name} against user {user.login}: {e}"
                        )

        # Evaluate repository-focused rules
        logger.info(
            f"Evaluating repository-focused rules against {len(repositories)} repositories"
        )
        for rule in rules_to_evaluate:
            if "repository" in rule.policy_code.lower():
                for repo in repositories:
                    try:
                        # Get repository access data if available
                        repo_access = access_map.get(repo.id)

                        # Prepare admin team members list for admin access checks
                        admin_team_members = set()
                        for team_id, members in team_members.items():
                            team = team_map.get(team_id)
                            if team and "admin" in team.name.lower():
                                admin_team_members.update(members)

                        context = {
                            "repository": repo.model_dump(),
                            "access": (
                                repo_access.model_dump()
                                if repo_access
                                else {"user_access": [], "team_access": []}
                            ),
                            "admin_team_members": list(admin_team_members),
                        }

                        result = self._evaluate_rule(rule, context)
                        if result:
                            violations.append(
                                PolicyViolation(
                                    rule_id=rule.id,
                                    rule_name=rule.name,
                                    entity_type="repository",
                                    entity_id=repo.id,
                                    message=f"Repository {repo.name} violates policy {rule.name}",
                                    severity=rule.severity,
                                )
                            )
                    except Exception as e:
                        logger.error(
                            f"Error evaluating rule {rule.name} against repository {repo.name}: {e}"
                        )

        # Evaluate access-focused rules
        logger.info(
            f"Evaluating access-focused rules against {len(access_data)} repository access records"
        )
        for rule in rules_to_evaluate:
            if "access" in rule.policy_code.lower():
                for access in access_data:
                    try:
                        repo = repository_map.get(access.repository_id)
                        if not repo:
                            continue

                        context = {
                            "repository": repo.model_dump(),
                            "access": access.model_dump(),
                        }

                        result = self._evaluate_rule(rule, context)
                        if result:
                            violations.append(
                                PolicyViolation(
                                    rule_id=rule.id,
                                    rule_name=rule.name,
                                    entity_type="access",
                                    entity_id=f"{access.repository_id}",
                                    message=f"Access configuration for {repo.name} violates policy {rule.name}",
                                    severity=rule.severity,
                                )
                            )
                    except Exception as e:
                        logger.error(
                            f"Error evaluating rule {rule.name} against access for repository {access.repository_name}: {e}"
                        )

        logger.info(f"Policy evaluation completed. Found {len(violations)} violations.")
        return violations

    def _evaluate_rule(self, rule: PolicyRule, context: Dict[str, Any]) -> bool:
        """
        Evaluate a single rule against a context.

        Args:
            rule: Policy rule to evaluate
            context: Context data to evaluate against

        Returns:
            True if the rule is violated, False otherwise
        """
        if rule.policy_language.lower() == "cel":
            return self._evaluate_cel_rule(rule.policy_code, context)
        else:
            logger.warning(f"Unsupported policy language: {rule.policy_language}")
            return False

    def _evaluate_cel_rule(self, policy_code: str, context: Dict[str, Any]) -> bool:
        """
        Evaluate a CEL rule against a context.

        Args:
            policy_code: CEL expression
            context: Context data to evaluate against

        Returns:
            True if the rule is violated, False otherwise
        """
        try:
            env = celpy.Environment()
            ast = env.compile(policy_code)
            prog = env.program(ast)
            result = prog.evaluate(context)

            # CEL evaluation returns a cel data type, convert to Python bool
            return bool(result) if isinstance(result, BoolType) else False
        except Exception as e:
            logger.error(f"Error evaluating CEL rule: {e}")
            return False
