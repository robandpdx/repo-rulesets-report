#!/usr/bin/env python3
"""Export an organization's repository rulesets and configured bypass actors."""

import argparse
from pathlib import Path
import sys
from urllib.parse import quote

from ruleset_bypass_report import (
    GitHubClient,
    ReportError,
    get_token,
    organization,
    write_csv,
)


COLUMNS = (
    "organization",
    "repository_id",
    "repository_name",
    "repository_full_name",
    "repository_visibility",
    "repository_private",
    "repository_archived",
    "repository_fork",
    "repository_html_url",
    "record_type",
    "bypass_actors_status",
    "bypass_actor_type",
    "bypass_actor_id",
    "bypass_actor_name",
    "bypass_mode",
    "bypass_actor_json",
    "ruleset_id",
    "ruleset_name",
    "ruleset_target",
    "ruleset_source_type",
    "ruleset_source",
    "ruleset_enforcement",
    "ruleset_conditions",
    "ruleset_rules",
    "ruleset_bypass_actors",
    "ruleset_current_user_can_bypass",
    "ruleset_node_id",
    "ruleset_created_at",
    "ruleset_updated_at",
    "ruleset__links",
)


def require_id(value, context):
    if type(value) is not int or value <= 0:
        raise ReportError(f"{context}: expected a positive integer ID.")
    return value


def require_text(value, context):
    if not isinstance(value, str) or not value:
        raise ReportError(f"{context}: expected a nonempty string.")
    return value


class ActorNames:
    """Resolve optional actor names once per actor or organization directory."""

    def __init__(self, client, org):
        self.client = client
        self.org_path = f"/orgs/{quote(org, safe='')}"
        self.names = {}
        self.directories = {}

    def directory(self, actor_type):
        if actor_type not in self.directories:
            # A failed directory lookup must not be retried for every actor.
            self.directories[actor_type] = {}
            if actor_type == "Team":
                items = self.client.paginate(f"{self.org_path}/teams")
                id_field = "id"
            else:
                items = self.client.paginate(
                    f"{self.org_path}/installations", items_key="installations"
                )
                id_field = "app_id"
            directory = {}
            for item in items:
                actor_id = require_id(item.get(id_field), f"{actor_type} lookup")
                directory[actor_id] = item
            self.directories[actor_type] = directory
        return self.directories[actor_type]

    def lookup(self, actor_type, actor_id):
        if actor_type == "User":
            user = self.client.get(f"/user/{actor_id}")
            return user.get("login") or user.get("name")
        if actor_type in ("Team", "Integration"):
            item = self.directory(actor_type).get(actor_id)
            if item is None:
                raise ReportError("Actor was not returned by the organization lookup.")
            if actor_type == "Team":
                return item.get("name")
            slug = require_text(item.get("app_slug"), "App lookup: app_slug")
            app = self.client.get(f"/apps/{quote(slug, safe='')}")
            return app.get("name")
        if actor_type == "RepositoryRole":
            # These predefined bypass role IDs apply to GitHub.com.
            predefined = {2: "Maintain", 4: "Write", 5: "Admin"}
            if actor_id in predefined:
                return predefined[actor_id]
            role = self.client.get(
                f"{self.org_path}/custom-repository-roles/{actor_id}"
            )
            return role.get("name")
        return {
            "OrganizationAdmin": "Organization administrators",
            "EnterpriseOwner": "Enterprise owners",
            "DeployKey": "Deploy keys",
        }.get(actor_type)

    def resolve(self, actor):
        supplied = actor.get("actor_name") or actor.get("name") or actor.get("login")
        if isinstance(supplied, str) and supplied:
            return supplied
        actor_type, actor_id = actor["actor_type"], actor.get("actor_id")
        key = (actor_type, actor_id if type(actor_id) is int else None)
        if key not in self.names:
            try:
                name = require_text(
                    self.lookup(actor_type, actor_id), "Actor lookup: name"
                )
            except ReportError as exc:
                print(
                    f"Warning: could not resolve bypass actor name for "
                    f"{actor_type} {actor_id}: {exc} Leaving bypass_actor_name empty.",
                    file=sys.stderr,
                )
                name = None
            self.names[key] = name
        return self.names[key]


def ruleset_rows(repository, ruleset, context):
    for field in ("name", "source", "enforcement"):
        require_text(ruleset.get(field), f"{context}: {field}")
    if "rules" in ruleset and (
        not isinstance(ruleset["rules"], list)
        or any(not isinstance(rule, dict) for rule in ruleset["rules"])
    ):
        raise ReportError(f"{context}: rules must be an array of objects.")
    if "bypass_actors" not in ruleset:
        raise ReportError(
            f"{context}: GitHub did not expose bypass_actors. "
            "Write access to the ruleset is required to see bypass actors; "
            "missing data is not an empty bypass list. No report was written."
        )
    actors = ruleset["bypass_actors"]
    if not isinstance(actors, list):
        raise ReportError(f"{context}: bypass_actors must be an array.")
    row = {
        **repository,
        **{f"ruleset_{key}": value for key, value in ruleset.items()},
        "record_type": "ruleset",
        "bypass_actors_status": "configured" if actors else "none",
    }
    if not actors:
        return [row]
    rows = []
    for actor in actors:
        if not isinstance(actor, dict):
            raise ReportError(f"{context}: bypass actors must be objects.")
        actor_type = require_text(actor.get("actor_type"), f"{context}: actor_type")
        if actor_type in ("Integration", "RepositoryRole", "Team", "User"):
            require_id(actor.get("actor_id"), f"{context}: {actor_type} actor_id")
        rows.append({
            **row,
            "bypass_actor_type": actor_type,
            "bypass_actor_id": actor.get("actor_id"),
            "bypass_mode": actor.get("bypass_mode"),
            "bypass_actor_json": actor,
        })
    return rows


def collect_rulesets(client, org, repository_only=False):
    rows = []
    seen_repositories = set()
    repositories = client.paginate(
        f"/orgs/{quote(org, safe='')}/repos",
        {"type": "all", "sort": "full_name", "direction": "asc"},
    )
    for repo in repositories:
        repo_id = require_id(repo.get("id"), "Repository")
        if repo_id in seen_repositories:
            continue
        seen_repositories.add(repo_id)
        name = require_text(repo.get("name"), f"Repository {repo_id}: name")
        full_name = require_text(
            repo.get("full_name"), f"Repository {repo_id}: full_name"
        )
        repository = {
            "organization": org,
            **{f"repository_{key}": repo[key] for key in (
                "id", "name", "full_name", "visibility", "private",
                "archived", "fork", "html_url",
            ) if key in repo},
        }
        path = f"/repos/{quote(org, safe='')}/{quote(name, safe='')}/rulesets"
        params = {"includes_parents": "false" if repository_only else "true"}
        summaries = client.paginate(path, params)
        seen_rulesets = set()
        for summary in summaries:
            ruleset_id = require_id(summary.get("id"), f"{full_name}: ruleset")
            if ruleset_id in seen_rulesets:
                continue
            seen_rulesets.add(ruleset_id)
            context = f"{full_name}: ruleset {ruleset_id}"
            # Details include repository-specific fields and bypass visibility.
            detail = client.get(f"{path}/{ruleset_id}", params)
            if require_id(detail.get("id"), context) != ruleset_id:
                raise ReportError(f"{context}: detail ID does not match the listed ID.")
            # Never mistake an omitted detail bypass list for a summary's empty list.
            merged = {**summary, **detail}
            if "bypass_actors" not in detail:
                merged.pop("bypass_actors", None)
            rows.extend(ruleset_rows(repository, merged, context))
        if not seen_rulesets:
            rows.append({
                **repository,
                "record_type": "repository_without_rulesets",
                "bypass_actors_status": "not_applicable",
            })
    names = ActorNames(client, org)
    for row in rows:
        if row["bypass_actors_status"] == "configured":
            row["bypass_actor_name"] = names.resolve(row["bypass_actor_json"])
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-o", "--org", required=True, type=organization)
    parser.add_argument(
        "--repository-only", action="store_true",
        help="Exclude inherited organization and enterprise rulesets",
    )
    parser.add_argument(
        "--output", type=Path,
        help="CSV path (default: ORG-repo-rulesets.csv in the current directory)",
    )
    args = parser.parse_args(argv)
    output = args.output or Path(f"{args.org}-repo-rulesets.csv")
    try:
        rows = collect_rulesets(
            GitHubClient(get_token()), args.org, args.repository_only
        )
        write_csv(output, rows, COLUMNS)
    except ReportError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Wrote {len(rows)} row(s) to {output.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
