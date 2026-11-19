import csv
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

import repo_rulesets_report as report
import ruleset_bypass_report as shared
from test_ruleset_bypass_report import http_error, response


def repository(repo_id=1, name="one"):
    return {
        "id": repo_id, "name": name, "full_name": f"example/{name}",
        "visibility": "private", "private": True,
        "archived": False, "fork": False,
        "html_url": f"https://github.com/example/{name}",
    }


def ruleset(ruleset_id=10, **extra):
    return {
        "id": ruleset_id, "name": "Branch rules", "target": "branch",
        "source": "example/one", "source_type": "Repository",
        "enforcement": "active", "rules": [{"type": "deletion"}],
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "bypass_actors": [], **extra,
    }


class CollectionTests(unittest.TestCase):
    def client(self, details, summaries=None):
        client = Mock()
        client.paginate.side_effect = [
            [repository()],
            summaries if summaries is not None else [{"id": item["id"]} for item in details],
        ]
        client.get.side_effect = details
        return client

    def test_all_actor_types_and_all_ruleset_fields(self):
        actors = [
            {"actor_type": "Team", "actor_id": 11, "bypass_mode": "pull_request"},
            {"actor_type": "Integration", "actor_id": 12, "bypass_mode": "always"},
            {"actor_type": "RepositoryRole", "actor_id": 5, "bypass_mode": "always"},
            {"actor_type": "OrganizationAdmin", "actor_id": None, "bypass_mode": "always"},
            {"actor_type": "DeployKey", "actor_id": None, "bypass_mode": "always"},
            {"actor_type": "User", "actor_id": 13, "bypass_mode": "exempt",
             "future_actor_field": {"enabled": True}},
        ]
        detail = ruleset(bypass_actors=actors, future_detail={"nested": ["value"]})
        client = self.client(
            [detail], [{"id": 10, "future_summary": "retained"}]
        )
        client.paginate.side_effect = [
            [repository()], [{"id": 10, "future_summary": "retained"}],
            [{"id": 11, "name": "Release team"}],
            [{"app_id": 12, "app_slug": "release-app"}],
        ]
        client.get.side_effect = [
            detail, {"name": "Release app"}, {"login": "release-user"},
        ]
        rows = report.collect_rulesets(client, "example")
        self.assertEqual(len(rows), len(actors))
        self.assertEqual([row["bypass_actor_name"] for row in rows], [
            "Release team", "Release app", "Admin",
            "Organization administrators", "Deploy keys", "release-user",
        ])
        for actor, row in zip(actors, rows):
            self.assertEqual(row["bypass_actor_type"], actor["actor_type"])
            self.assertEqual(row["bypass_actor_id"], actor["actor_id"])
            self.assertEqual(row["bypass_mode"], actor["bypass_mode"])
            self.assertEqual(row["bypass_actor_json"], actor)
            self.assertEqual(row["bypass_actors_status"], "configured")
            for key, value in detail.items():
                self.assertEqual(row[f"ruleset_{key}"], value)
            self.assertEqual(row["ruleset_future_summary"], "retained")
        client.paginate.assert_any_call(
            "/repos/example/one/rulesets", {"includes_parents": "true"}
        )
        client.get.assert_any_call(
            "/repos/example/one/rulesets/10", {"includes_parents": "true"}
        )

    def test_no_bypass_actors_is_not_an_omitted_ruleset(self):
        rows = report.collect_rulesets(self.client([ruleset()]), "example")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ruleset_id"], 10)
        self.assertEqual(rows[0]["bypass_actors_status"], "none")
        self.assertNotIn("bypass_actor_type", rows[0])

    def test_repository_without_rulesets_and_empty_organization(self):
        client = self.client([], [])
        row, = report.collect_rulesets(client, "example")
        self.assertEqual(row["record_type"], "repository_without_rulesets")
        self.assertEqual(row["repository_full_name"], "example/one")
        client.get.assert_not_called()
        client.paginate.side_effect = [[]]
        self.assertEqual(report.collect_rulesets(client, "example"), [])

    def test_repository_only_requests_exclude_parents_on_list_and_detail(self):
        client = self.client([ruleset()])
        report.collect_rulesets(client, "example", repository_only=True)
        client.paginate.assert_any_call(
            "/repos/example/one/rulesets", {"includes_parents": "false"}
        )
        client.get.assert_called_once_with(
            "/repos/example/one/rulesets/10", {"includes_parents": "false"}
        )

    def test_all_targets_and_enforcement_states_include_archived_forks(self):
        details = [
            ruleset(10, target="branch", enforcement="active"),
            ruleset(11, target="tag", enforcement="evaluate"),
            ruleset(12, target="push", enforcement="disabled"),
            ruleset(13, target="repository", enforcement="active"),
        ]
        client = self.client(details)
        client.paginate.side_effect = [
            [{**repository(), "archived": True, "fork": True}],
            [{"id": detail["id"]} for detail in details],
        ]
        rows = report.collect_rulesets(client, "example")
        self.assertEqual([row["ruleset_target"] for row in rows],
                         ["branch", "tag", "push", "repository"])
        self.assertEqual([row["ruleset_enforcement"] for row in rows],
                         ["active", "evaluate", "disabled", "active"])
        self.assertTrue(all(row["repository_archived"] for row in rows))
        self.assertTrue(all(row["repository_fork"] for row in rows))
        client.paginate.assert_any_call(
            "/orgs/example/repos",
            {"type": "all", "sort": "full_name", "direction": "asc"},
        )

    def test_duplicate_repos_and_rulesets_do_not_trigger_duplicate_detail_calls(self):
        client = self.client([ruleset()], [{"id": 10}, {"id": 10}])
        client.paginate.side_effect = [
            [repository(), repository()], [{"id": 10}, {"id": 10}],
        ]
        rows = report.collect_rulesets(client, "example")
        self.assertEqual(len(rows), 1)
        self.assertEqual(client.paginate.call_count, 2)
        client.get.assert_called_once()

    def test_inherited_details_are_not_reused_across_repository_contexts(self):
        client = Mock()
        client.paginate.side_effect = [
            [repository(), repository(2, "two")], [{"id": 10}], [{"id": 10}],
        ]
        client.get.side_effect = [
            ruleset(source_type="Organization", source="example",
                    current_user_can_bypass="never"),
            ruleset(source_type="Organization", source="example",
                    current_user_can_bypass="always"),
        ]
        rows = report.collect_rulesets(client, "example")
        self.assertEqual([row["ruleset_source_type"] for row in rows],
                         ["Organization", "Organization"])
        self.assertEqual([row["ruleset_current_user_can_bypass"] for row in rows],
                         ["never", "always"])
        self.assertEqual(client.get.call_count, 2)

    def test_hidden_bypass_actors_fail_even_if_summary_has_empty_array(self):
        detail = ruleset()
        del detail["bypass_actors"]
        client = self.client([detail], [{"id": 10, "bypass_actors": []}])
        with self.assertRaisesRegex(shared.ReportError, "did not expose bypass_actors"):
            report.collect_rulesets(client, "example")

    def test_invalid_details_and_actors_fail_explicitly(self):
        for detail in (
            ruleset(99), ruleset(name=None), ruleset(rules={}),
            ruleset(bypass_actors=None), ruleset(bypass_actors=[1]),
            ruleset(bypass_actors=[{}]),
            ruleset(bypass_actors=[{"actor_type": "Team", "actor_id": True}]),
        ):
            with self.subTest(detail=detail):
                client = self.client([detail], [{"id": 10}])
                with self.assertRaises(shared.ReportError):
                    report.collect_rulesets(client, "example")


class IntegrationTests(unittest.TestCase):
    @patch.object(shared, "build_opener")
    def test_paginated_actor_directories_and_cached_names(self, build):
        actors = [
            {"actor_type": "Team", "actor_id": 11},
            {"actor_type": "Integration", "actor_id": 11},
            {"actor_type": "RepositoryRole", "actor_id": 99},
        ]
        detail = ruleset(bypass_actors=actors)
        build.return_value.open.side_effect = [
            response([repository(), repository(2, "two")]),
            response([{"id": 10}]), response(detail),
            response([{"id": 10}]), response(detail),
            response([{"id": 1, "name": "Other team"}],
                     '<https://api.github.com/orgs/example/teams?page=2>; rel="next"'),
            response([{"id": 11, "name": "Release team"}]),
            response({"installations": [{"app_id": 1, "app_slug": "other"}]},
                     '<https://api.github.com/orgs/example/installations?page=2>; rel="next"'),
            response({"installations": [{"app_id": 11, "app_slug": "release-app"}]}),
            response({"id": 11, "name": "Release app"}),
            response({"id": 99, "name": "Release manager"}),
        ]
        rows = report.collect_rulesets(shared.GitHubClient("fake-token"), "example")
        self.assertEqual([row["bypass_actor_name"] for row in rows], [
            "Release team", "Release app", "Release manager",
            "Release team", "Release app", "Release manager",
        ])
        calls = build.return_value.open.call_args_list
        self.assertEqual(len(calls), 11)
        for index in (6, 8):
            query = parse_qs(urlsplit(calls[index].args[0].full_url).query)
            self.assertEqual(query["page"], ["2"])
            self.assertEqual(query["per_page"], ["100"])
        self.assertEqual(urlsplit(calls[9].args[0].full_url).path, "/apps/release-app")
        self.assertEqual(urlsplit(calls[10].args[0].full_url).path,
                         "/orgs/example/custom-repository-roles/99")

    @patch.object(shared, "build_opener")
    def test_invalid_installation_envelopes_fail_explicitly(self, build):
        for payload in ([], {}, {"installations": {}}, {"installations": [1]}):
            with self.subTest(payload=payload):
                build.return_value.open.return_value = response(payload)
                with self.assertRaisesRegex(shared.ReportError, "invalid response"):
                    list(shared.GitHubClient("fake-token").paginate(
                        "/orgs/example/installations", items_key="installations"
                    ))

    @patch.object(shared.time, "sleep")
    @patch.object(shared, "build_opener")
    def test_paginated_repositories_rulesets_and_rate_limited_detail(self, build, sleep):
        detail_one = ruleset(bypass_actors=[
            {"actor_type": "User", "actor_id": 21, "bypass_mode": "exempt"},
        ])
        detail_two = ruleset(20, source_type="Organization", source="example")
        build.return_value.open.side_effect = [
            response([repository()], '<https://api.github.com/orgs/example/repos?page=2>; rel="next"'),
            response([{"id": 10}], '<https://api.github.com/repos/example/one/rulesets?page=2>; rel="next"'),
            response(detail_one),
            response([{"id": 20}]),
            http_error(429, {"Retry-After": "1"}),
            response(detail_two),
            response([repository(2, "two")]),
            response([]),
            response({"id": 21, "login": "release-user", "name": "Release User"}),
        ]
        with patch("sys.stderr", new=io.StringIO()):
            rows = report.collect_rulesets(shared.GitHubClient("fake-token"), "example")
        self.assertEqual(len(rows), 3)
        self.assertEqual([row["record_type"] for row in rows],
                         ["ruleset", "ruleset", "repository_without_rulesets"])
        calls = build.return_value.open.call_args_list
        self.assertEqual(len(calls), 9)
        self.assertEqual(rows[0]["bypass_actor_name"], "release-user")
        self.assertEqual(urlsplit(calls[8].args[0].full_url).path, "/user/21")
        self.assertEqual(calls[4].args[0].full_url, calls[5].args[0].full_url)
        sleep.assert_called_once_with(1)
        for call in calls:
            request = call.args[0]
            query = parse_qs(urlsplit(request.full_url).query)
            if request.full_url.split("?")[0].endswith(("/repos", "/rulesets")):
                self.assertEqual(query["per_page"], ["100"])
            if "/rulesets" in request.full_url:
                self.assertEqual(query["includes_parents"], ["true"])
        self.assertEqual(parse_qs(urlsplit(calls[6].args[0].full_url).query)["page"], ["2"])

    @patch.object(shared, "build_opener")
    def test_shared_detail_client_rejects_non_object(self, build):
        build.return_value.open.return_value = response([])
        with self.assertRaisesRegex(shared.ReportError, "expected an object"):
            shared.GitHubClient("fake-token").get("/repos/example/one/rulesets/10")


class CsvAndCliTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name) / "rulesets.csv"

    def test_csv_has_all_detail_fields_and_actor_json(self):
        client = Mock()
        client.paginate.side_effect = [[repository()], [{"id": 10}]]
        actor = {"actor_type": "Team", "actor_id": 11,
                 "name": 'Release, "team"',
                 "bypass_mode": "always", "extra": ["new"]}
        client.get.return_value = ruleset(
            name='Protection, "main"', bypass_actors=[actor],
            extra={"include": ["\u00e9\nbranch"]},
        )
        rows = report.collect_rulesets(client, "example")
        shared.write_csv(self.output, rows, report.COLUMNS)
        with self.output.open(encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            row, = list(reader)
            self.assertIn("ruleset_extra", reader.fieldnames)
            index = reader.fieldnames.index("bypass_actor_id")
            self.assertEqual(reader.fieldnames[index:index + 3], [
                "bypass_actor_id", "bypass_actor_name", "bypass_mode",
            ])
        self.assertEqual(row["bypass_actor_name"], 'Release, "team"')
        self.assertEqual(json.loads(row["bypass_actor_json"]), actor)
        self.assertEqual(json.loads(row["ruleset_extra"]), {"include": ["\u00e9\nbranch"]})
        self.assertEqual(json.loads(row["ruleset_bypass_actors"]), [actor])
        self.assertEqual(row["ruleset_name"], 'Protection, "main"')
        self.assertEqual(row["repository_private"], "true")

    @patch.object(report, "get_token", return_value="fake-token")
    @patch.object(shared, "build_opener")
    def test_unavailable_actor_names_warn_and_still_write_report(self, build, token):
        for status in (403, 404):
            with self.subTest(status=status):
                actor = {"actor_type": "User", "actor_id": 21, "bypass_mode": "always"}
                build.return_value.open.side_effect = [
                    response([repository()]), response([{"id": 10}]),
                    response(ruleset(bypass_actors=[actor, actor])),
                    http_error(status),
                ]
                with patch("sys.stderr", new=io.StringIO()) as stderr, \
                        patch("sys.stdout", new=io.StringIO()):
                    self.assertEqual(report.main([
                        "-o", "example", "--output", str(self.output),
                    ]), 0)
                self.assertIn(f"HTTP {status}", stderr.getvalue())
                self.assertEqual(stderr.getvalue().count("Warning:"), 1)
                with self.output.open(encoding="utf-8", newline="") as handle:
                    rows = list(csv.DictReader(handle))
                self.assertEqual(len(rows), 2)
                for row in rows:
                    self.assertEqual(row["bypass_actor_name"], "")
                    self.assertEqual(row["bypass_actor_id"], "21")
                    self.assertEqual(json.loads(row["bypass_actor_json"]), actor)

    @patch.object(report, "get_token", return_value="fake-token")
    @patch.object(report, "GitHubClient")
    def test_cli_options_and_empty_report(self, client, token):
        for option in ("-o", "--org"):
            with self.subTest(option=option):
                client.return_value.paginate.return_value = []
                with patch("sys.stdout", new=io.StringIO()):
                    self.assertEqual(report.main([
                        option, "example", "--repository-only",
                        "--output", str(self.output),
                    ]), 0)
                with self.output.open(encoding="utf-8", newline="") as handle:
                    self.assertEqual(list(csv.reader(handle)), [list(report.COLUMNS)])

    @patch.object(report, "get_token", return_value="fake-token")
    @patch.object(report, "GitHubClient")
    @patch.object(report, "write_csv")
    def test_cli_default_filename(self, write, client, token):
        client.return_value.paginate.return_value = []
        with patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(report.main(["-o", "example"]), 0)
        write.assert_called_once_with(Path("example-repo-rulesets.csv"), [], report.COLUMNS)

    @patch.object(report, "get_token", return_value="fake-token")
    @patch.object(shared, "build_opener")
    @patch.object(shared.time, "sleep")
    def test_detail_rate_limit_exhaustion_preserves_existing_report(self, sleep, build, token):
        self.output.write_text("existing", encoding="utf-8")
        build.return_value.open.side_effect = [
            response([repository()]), response([{"id": 10}]),
            *[http_error(429, {"Retry-After": "1"}) for _ in range(4)],
        ]
        with patch("sys.stderr", new=io.StringIO()) as stderr:
            self.assertEqual(report.main([
                "-o", "example", "--output", str(self.output),
            ]), 1)
        self.assertIn("retries exhausted", stderr.getvalue())
        self.assertIn("/repos/example/one/rulesets/10", stderr.getvalue())
        self.assertEqual(self.output.read_text(encoding="utf-8"), "existing")
        self.assertEqual(sleep.call_count, 3)

    @patch.object(report, "get_token", return_value="fake-token")
    @patch.object(report, "GitHubClient")
    def test_hidden_actor_list_does_not_create_report(self, client, token):
        client.return_value.paginate.side_effect = [[repository()], [{"id": 10}]]
        hidden = ruleset()
        del hidden["bypass_actors"]
        client.return_value.get.return_value = hidden
        with patch("sys.stderr", new=io.StringIO()) as stderr:
            self.assertEqual(report.main([
                "-o", "example", "--output", str(self.output),
            ]), 1)
        self.assertIn("Write access", stderr.getvalue())
        self.assertFalse(self.output.exists())

    def test_required_organization_and_invalid_options(self):
        for args in ([], ["-o", "../example"], ["-o", "example", "--time-period", "month"]):
            with self.subTest(args=args), patch("sys.stderr", new=io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    report.main(args)
                self.assertEqual(caught.exception.code, 2)


class ActorNameTests(unittest.TestCase):
    def test_failed_directory_is_not_retried_and_missing_names_warn(self):
        client = Mock()
        client.paginate.side_effect = shared.ReportError("HTTP 403: access denied")
        names = report.ActorNames(client, "example")
        with patch("sys.stderr", new=io.StringIO()) as stderr:
            for actor_id in (11, 12, 11):
                self.assertIsNone(names.resolve({
                    "actor_type": "Team", "actor_id": actor_id,
                }))
            self.assertIsNone(names.resolve({
                "actor_type": "FutureActor", "actor_id": {"future": True},
            }))
        self.assertIn("HTTP 403", stderr.getvalue())
        self.assertIn("FutureActor", stderr.getvalue())
        client.paginate.assert_called_once_with("/orgs/example/teams")
        client.get.assert_not_called()

    def test_embedded_name_avoids_lookup_and_is_preserved(self):
        client = Mock()
        names = report.ActorNames(client, "example")
        self.assertEqual(names.resolve({
            "actor_type": "Integration", "actor_id": 12,
            "actor_name": "Provided app",
        }), "Provided app")
        client.get.assert_not_called()
        client.paginate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
