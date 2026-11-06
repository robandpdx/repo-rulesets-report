import csv
from http.client import IncompleteRead
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlsplit

import ruleset_bypass_report as report


def response(payload, link=""):
    result = Mock()
    result.status = 200
    result.read.return_value = json.dumps(payload).encode()
    result.headers = {"Link": link}
    result.__enter__ = Mock(return_value=result)
    result.__exit__ = Mock(return_value=False)
    return result


def http_error(code, headers=None, message=""):
    return HTTPError(
        "https://api.github.com", code, "error", headers or {},
        io.BytesIO(json.dumps({"message": message}).encode()),
    )


def fetch_org_suites(org, token, time_period="month", evaluate_status="active"):
    return list(report.GitHubClient(token).paginate(
        f"/orgs/{org}/rulesets/rule-suites",
        {"rule_suite_result": "bypass", "time_period": time_period,
         "evaluate_status": evaluate_status},
    ))


class FetchTests(unittest.TestCase):
    @patch.object(report, "build_opener")
    def test_pagination_and_filters(self, build_opener):
        opener = build_opener.return_value
        opener.open.side_effect = [
            response([{"id": i} for i in range(100)]),
            response([{"id": 100, "additional": {"enabled": True}}]),
        ]
        suites = fetch_org_suites("example-org", "fake-token")
        self.assertEqual(len(suites), 101)
        self.assertEqual(suites[-1]["additional"], {"enabled": True})
        for page, call in enumerate(opener.open.call_args_list, 1):
            request = call.args[0]
            self.assertEqual(urlsplit(request.full_url).path,
                             "/orgs/example-org/rulesets/rule-suites")
            self.assertEqual(parse_qs(urlsplit(request.full_url).query), {
                "rule_suite_result": ["bypass"],
                "time_period": ["month"],
                "evaluate_status": ["active"],
                "per_page": ["100"],
                "page": [str(page)],
            })
            self.assertEqual(request.get_header("Authorization"), "Bearer fake-token")
            self.assertEqual(request.get_header("X-github-api-version"), report.API_VERSION)
            self.assertEqual(call.kwargs["timeout"], 30)

    @patch.object(report, "build_opener")
    def test_short_page_with_next_link(self, build_opener):
        build_opener.return_value.open.side_effect = [
            response([{"id": 1}], '<https://api.github.com/example?page=2>; rel="next"'),
            response([{"id": 2}]),
        ]
        self.assertEqual(fetch_org_suites("example", "fake-token"),
                         [{"id": 1}, {"id": 2}])

    @patch.object(report, "build_opener")
    def test_exact_page_size_and_empty_final_page(self, build_opener):
        build_opener.return_value.open.side_effect = [
            response([{"id": i} for i in range(100)]), response([]),
        ]
        self.assertEqual(len(fetch_org_suites("example", "fake-token")), 100)

    @patch.object(report, "build_opener")
    def test_full_final_page_with_link_does_not_make_an_extra_call(self, build_opener):
        opener = build_opener.return_value
        opener.open.side_effect = [
            response([{"id": 0}], '<https://api.github.com/example?page=2>; rel="next"'),
            response([{"id": i} for i in range(1, 101)],
                     '<https://api.github.com/example?page=1>; rel="prev"'),
        ]
        self.assertEqual(len(fetch_org_suites("example", "fake-token")), 101)
        self.assertEqual(opener.open.call_count, 2)

    @patch.object(report, "build_opener")
    def test_http_error_on_later_page_is_not_partial_success(self, build_opener):
        build_opener.return_value.open.side_effect = [
            response([{"id": i} for i in range(100)]),
            http_error(403, message="Resource not accessible"),
        ]
        with self.assertRaisesRegex(report.ReportError, "HTTP 403 on page 2"):
            fetch_org_suites("example", "fake-token")

    @patch.object(report, "build_opener")
    def test_network_and_invalid_response_errors(self, build_opener):
        opener = build_opener.return_value
        for error in (URLError("secret"), TimeoutError(), OSError(), IncompleteRead(b"x")):
            with self.subTest(error=type(error)):
                opener.open.side_effect = error
                with self.assertRaisesRegex(report.ReportError, "Network request"):
                    fetch_org_suites("example", "fake-token")
        opener.open.side_effect = None
        for payload in ({"message": "error"}, [1], [None], [True]):
            with self.subTest(payload=payload):
                opener.open.return_value = response(payload)
                with self.assertRaisesRegex(report.ReportError, "array of objects"):
                    fetch_org_suites("example", "fake-token")
        for raw in (b"not json", b"\xff", b'[{"id": NaN}]'):
            with self.subTest(raw=raw):
                invalid = response([])
                invalid.read.return_value = raw
                opener.open.return_value = invalid
                with self.assertRaisesRegex(report.ReportError, "Invalid JSON"):
                    fetch_org_suites("example", "fake-token")

    @patch.object(report, "build_opener")
    def test_invalid_pagination(self, build_opener):
        for result in (
            response([{"id": i} for i in range(101)]),
            response([], '<https://api.github.com/example?page=2>; rel="next"'),
        ):
            with self.subTest(result=result):
                build_opener.return_value.open.return_value = result
                with self.assertRaisesRegex(report.ReportError, "Invalid"):
                    fetch_org_suites("example", "fake-token")

    def test_redirects_are_disabled(self):
        self.assertIsNone(report.NoRedirects().redirect_request(
            None, None, 302, "", {}, "https://example.com"
        ))


@patch.object(report, "build_opener")
class CollectionTests(unittest.TestCase):
    def test_combines_scopes_deduplicates_and_preserves_fields(self, build):
        org_only = {"id": 1, "repository_id": 10, "repository_name": "first"}
        shared = {"id": 2, "repository_id": 10, "org_extra": "retained"}
        repo_only = {"id": 3, "repository_id": 10, "repo_extra": {"key": True}}
        other_repo = {"id": 1, "repository_id": 20}
        opener = build.return_value
        opener.open.side_effect = [
            response([org_only, shared]),
            response([{"name": "first", "archived": True}, {"name": "FIRST"},
                      {"name": "second", "fork": True}]),
            response([{"id": 2, "repository_id": 10, "repo_extra": "added"},
                      repo_only, repo_only]),
            response([other_repo]),
        ]
        suites = report.fetch_suites("example", "fake-token", "week", "all")
        self.assertEqual(suites, [
            org_only, {**shared, "repo_extra": "added"}, repo_only, other_repo,
        ])
        self.assertEqual(build.call_count, 1)
        paths = []
        for call in opener.open.call_args_list:
            request = call.args[0]
            url = urlsplit(request.full_url)
            self.assertEqual(url.netloc, "api.github.com")
            paths.append(url.path)
            query = parse_qs(url.query)
            if url.path.endswith("rule-suites"):
                self.assertEqual(query, {
                    "rule_suite_result": ["bypass"], "time_period": ["week"],
                    "evaluate_status": ["all"], "per_page": ["100"], "page": ["1"],
                })
            else:
                self.assertEqual(query, {
                    "type": ["all"], "sort": ["full_name"], "direction": ["asc"],
                    "per_page": ["100"], "page": ["1"],
                })
        self.assertEqual(paths, [
            "/orgs/example/rulesets/rule-suites", "/orgs/example/repos",
            "/repos/example/first/rulesets/rule-suites",
            "/repos/example/second/rulesets/rule-suites",
        ])

    def test_repository_discovery_and_suite_pagination(self, build):
        opener = build.return_value
        opener.open.side_effect = [
            response([]),
            response([{"name": "first"}],
                     '<https://api.github.com/orgs/example/repos?page=2>; rel="next"'),
            response([{"name": "second"}]),
            response([{"id": i, "repository_id": 10} for i in range(100)],
                     '<https://untrusted.example/?page=2>; rel="next"'),
            response([{"id": 100, "repository_id": 10}]),
            response([{"id": 200, "repository_id": 20}]),
        ]
        suites = report.fetch_suites("example", "fake-token")
        self.assertEqual(len(suites), 102)
        urls = [urlsplit(call.args[0].full_url) for call in opener.open.call_args_list]
        self.assertEqual([parse_qs(url.query)["page"][0] for url in urls],
                         ["1", "1", "2", "1", "2", "1"])
        self.assertTrue(all(url.netloc == "api.github.com" for url in urls))
        self.assertEqual(urls[3].path, urls[4].path)

    def test_empty_organization(self, build):
        build.return_value.open.side_effect = [response([]), response([])]
        self.assertEqual(report.fetch_suites("example", "fake-token"), [])
        self.assertEqual(build.return_value.open.call_count, 2)

    @patch.object(report.time, "sleep")
    def test_rate_limits_during_discovery_and_repository_collection(self, sleep, build):
        opener = build.return_value
        opener.open.side_effect = [
            response([]),
            http_error(429, {"Retry-After": "1"}),
            response([{"name": "first"}]),
            response([{"id": 1, "repository_id": 10}],
                     '<https://api.github.com/example?page=2>; rel="next"'),
            http_error(403, message="secondary rate limit"),
            response([{"id": 2, "repository_id": 10}]),
        ]
        with patch("sys.stderr", new=io.StringIO()):
            suites = report.fetch_suites("example", "fake-token")
        self.assertEqual([suite["id"] for suite in suites], [1, 2])
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 60])
        calls = opener.open.call_args_list
        self.assertEqual(calls[1].args[0].full_url, calls[2].args[0].full_url)
        self.assertEqual(calls[4].args[0].full_url, calls[5].args[0].full_url)

    def test_invalid_repository_names_fail_explicitly(self, build):
        for name in (None, "", "..", ".", "../other", "repo?token=x", ["repo"]):
            with self.subTest(name=name):
                build.return_value.open.side_effect = [
                    response([]), response([{"name": name}]),
                ]
                with self.assertRaisesRegex(report.ReportError, "Invalid repository name"):
                    report.fetch_suites("example", "fake-token")

    def test_invalid_suite_identity_fails_explicitly(self, build):
        for suite in ({"id": 1}, {"repository_id": 10}, {"id": [], "repository_id": 10},
                      {"id": True, "repository_id": 10}, {"id": 1, "repository_id": "10"}):
            with self.subTest(suite=suite):
                build.return_value.open.side_effect = [
                    response([]), response([{"name": "first"}]), response([suite]),
                ]
                with self.assertRaisesRegex(report.ReportError, "Invalid rule suite"):
                    report.fetch_suites("example", "fake-token")


@patch.object(report.time, "sleep")
@patch.object(report, "build_opener")
class RateLimitTests(unittest.TestCase):
    def test_retry_after_retries_same_page_without_duplicates(self, build, sleep):
        opener = build.return_value
        opener.open.side_effect = [
            response([{"id": i} for i in range(100)]),
            http_error(429, {"Retry-After": "2"}),
            response([{"id": 100}]),
        ]
        with patch("sys.stderr", new=io.StringIO()) as stderr:
            suites = fetch_org_suites("example", "fake-token")
        self.assertEqual(len(suites), 101)
        sleep.assert_called_once_with(2)
        self.assertEqual(opener.open.call_args_list[1].args[0].full_url,
                         opener.open.call_args_list[2].args[0].full_url)
        self.assertIn("Rate limited on page 2", stderr.getvalue())

    @patch.object(report.time, "time", return_value=1000)
    def test_primary_limit_reset(self, clock, build, sleep):
        build.return_value.open.side_effect = [
            http_error(403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1005"}),
            response([]),
        ]
        with patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(fetch_org_suites("example", "fake-token"), [])
        sleep.assert_called_once_with(6)

    @patch.object(report.time, "time", return_value=0)
    def test_retry_after_http_date(self, clock, build, sleep):
        build.return_value.open.side_effect = [
            http_error(429, {"Retry-After": "Thu, 01 Jan 1970 00:00:03 GMT"}),
            response([]),
        ]
        with patch("sys.stderr", new=io.StringIO()):
            fetch_org_suites("example", "fake-token")
        sleep.assert_called_once_with(3)

    def test_secondary_limit_backoff_and_exhaustion(self, build, sleep):
        build.return_value.open.side_effect = [
            http_error(403, message="You have exceeded a secondary rate limit.")
            for _ in range(4)
        ]
        with patch("sys.stderr", new=io.StringIO()):
            with self.assertRaisesRegex(report.ReportError, "retries exhausted"):
                fetch_org_suites("example", "fake-token")
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [60, 120, 240])

    def test_long_wait_and_invalid_headers_do_not_sleep(self, build, sleep):
        for headers in ({"Retry-After": "301"}, {"Retry-After": "invalid"},
                        {"Retry-After": "nan"},
                        {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "bad"}):
            with self.subTest(headers=headers):
                build.return_value.open.side_effect = http_error(429, headers)
                with self.assertRaisesRegex(report.ReportError, "rate limited|Rate limited"):
                    fetch_org_suites("example", "fake-token")
        sleep.assert_not_called()

    def test_auth_and_permission_errors_do_not_retry(self, build, sleep):
        for code in (401, 403, 404, 500):
            with self.subTest(code=code):
                build.return_value.open.reset_mock()
                build.return_value.open.side_effect = http_error(code)
                with self.assertRaisesRegex(report.ReportError, f"HTTP {code}"):
                    fetch_org_suites("example", "fake-token")
                build.return_value.open.assert_called_once()
        sleep.assert_not_called()


class AuthTests(unittest.TestCase):
    @patch.dict(os.environ, {"GH_TOKEN": "fake-gh", "GITHUB_TOKEN": "fake-github"},
                clear=True)
    @patch.object(report.subprocess, "run")
    def test_environment_precedence(self, run):
        self.assertEqual(report.get_token(), "fake-gh")
        run.assert_not_called()

    @patch.dict(os.environ, {"GITHUB_TOKEN": "fake-github"}, clear=True)
    def test_github_token(self):
        self.assertEqual(report.get_token(), "fake-github")

    @patch.dict(os.environ, {}, clear=True)
    @patch.object(report.subprocess, "run")
    def test_gh_fallback(self, run):
        run.return_value = Mock(returncode=0, stdout="fake-token\n")
        self.assertEqual(report.get_token(), "fake-token")
        self.assertEqual(run.call_args.args[0],
                         ["gh", "auth", "token", "--hostname", "github.com"])

    @patch.dict(os.environ, {}, clear=True)
    @patch.object(report.subprocess, "run")
    def test_auth_failure_does_not_expose_subprocess_output(self, run):
        run.return_value = Mock(returncode=1, stdout="secret", stderr="secret")
        with self.assertRaises(report.ReportError) as caught:
            report.get_token()
        self.assertNotIn("secret", str(caught.exception))
        for error in (FileNotFoundError(), report.subprocess.TimeoutExpired("gh", 10)):
            run.side_effect = error
            with self.assertRaisesRegex(report.ReportError, "unavailable"):
                report.get_token()

    @patch.dict(os.environ, {"GH_TOKEN": "fake\ninjected"}, clear=True)
    def test_invalid_token(self):
        with self.assertRaisesRegex(report.ReportError, "invalid line break"):
            report.get_token()


class CsvAndCliTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name) / "report.csv"

    def test_all_fields_and_csv_escaping(self):
        suite = {column: f"value-{column}" for column in report.COLUMNS}
        suite.update(actor_name='name,"quoted"\nline', before_sha=None,
                     nested={"items": [1, "two"], "enabled": True},
                     array=[{"key": "value"}], flag=False)
        report.write_csv(self.output, [suite, {"id": 2, "later_field": "present"}])
        with self.output.open(encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            rows = list(reader)
            self.assertEqual(reader.fieldnames, list(report.COLUMNS) +
                             ["array", "flag", "later_field", "nested"])
        self.assertEqual(rows[0]["actor_name"], suite["actor_name"])
        self.assertEqual(rows[0]["before_sha"], "")
        self.assertEqual(json.loads(rows[0]["nested"]), suite["nested"])
        self.assertEqual(json.loads(rows[0]["array"]), suite["array"])
        self.assertEqual(rows[0]["flag"], "false")
        self.assertEqual(rows[1]["later_field"], "present")
        self.assertEqual(rows[1]["nested"], "")
        for column in report.COLUMNS:
            if column not in ("before_sha", "actor_name"):
                self.assertEqual(rows[0][column], suite[column])

    def test_empty_report_has_headers(self):
        report.write_csv(self.output, [])
        with self.output.open(encoding="utf-8", newline="") as handle:
            self.assertEqual(list(csv.reader(handle)), [list(report.COLUMNS)])

    def test_output_failure_preserves_existing_file(self):
        self.output.write_text("existing", encoding="utf-8")
        with patch.object(report.os, "replace", side_effect=OSError()):
            with self.assertRaisesRegex(report.ReportError, "Could not write CSV"):
                report.write_csv(self.output, [{"id": 1}])
        self.assertEqual(self.output.read_text(encoding="utf-8"), "existing")
        self.assertEqual(list(self.output.parent.iterdir()), [self.output])
        with self.assertRaises(report.ReportError):
            report.write_csv(self.output.parent / "missing" / "report.csv", [])

    @patch.object(report, "get_token", return_value="fake-token")
    @patch.object(report, "fetch_suites", return_value=[])
    def test_cli_org_options(self, fetch, token):
        for option in ("-o", "--org"):
            with self.subTest(option=option), patch("sys.stdout", new=io.StringIO()):
                self.assertEqual(report.main([
                    option, "example", "--output", str(self.output),
                    "--time-period", "week", "--evaluate-status", "all",
                ]), 0)
                fetch.assert_called_with("example", "fake-token", "week", "all")
                self.assertTrue(self.output.exists())

    @patch.object(report, "get_token", return_value="fake-token")
    @patch.object(report, "fetch_suites", return_value=[])
    @patch.object(report, "write_csv")
    def test_cli_defaults(self, write, fetch, token):
        with patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(report.main(["-o", "example"]), 0)
        fetch.assert_called_once_with("example", "fake-token", "month", "active")
        write.assert_called_once_with(Path("example-ruleset-bypasses.csv"), [])

    @patch.object(report, "get_token", return_value="fake-token")
    @patch.object(report, "fetch_suites")
    def test_fetch_failure_does_not_write_or_replace_output(self, fetch, token):
        self.output.write_text("existing", encoding="utf-8")
        fetch.side_effect = report.ReportError("HTTP 401 on page 1.")
        with patch("sys.stderr", new=io.StringIO()) as stderr, \
                patch("sys.stdout", new=io.StringIO()) as stdout:
            self.assertEqual(report.main(["-o", "example", "--output",
                                          str(self.output)]), 1)
        self.assertIn("HTTP 401", stderr.getvalue())
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(self.output.read_text(encoding="utf-8"), "existing")

    @patch.object(report, "get_token", return_value="fake-token")
    @patch.object(report, "build_opener")
    @patch.object(report.time, "sleep")
    def test_rate_limit_failure_after_a_page_preserves_report(self, sleep, build, token):
        self.output.write_text("existing", encoding="utf-8")
        build.return_value.open.side_effect = [
            response([{"id": i, "repository_id": 1} for i in range(100)]),
            *[http_error(429, {"Retry-After": "1"}) for _ in range(4)],
        ]
        with patch("sys.stderr", new=io.StringIO()) as stderr:
            self.assertEqual(report.main([
                "-o", "example", "--output", str(self.output),
            ]), 1)
        self.assertIn("retries exhausted on page 2", stderr.getvalue())
        self.assertEqual(self.output.read_text(encoding="utf-8"), "existing")
        self.assertEqual(list(self.output.parent.iterdir()), [self.output])
        self.assertEqual(sleep.call_count, 3)

    @patch.object(report, "get_token", return_value="fake-token")
    @patch.object(report, "build_opener")
    def test_repository_or_discovery_failure_preserves_report(self, build, token):
        self.output.write_text("existing", encoding="utf-8")
        suite = {"id": 1, "repository_id": 10}
        for code in (401, 403, 404, 500):
            for discovery in (True, False):
                with self.subTest(code=code, discovery=discovery):
                    results = [response([suite])]
                    if not discovery:
                        results.extend([
                            response([{"name": "first"}, {"name": "second"}]),
                            response([{"id": 2, "repository_id": 10}]),
                        ])
                    build.return_value.open.side_effect = [*results, http_error(code)]
                    with patch("sys.stderr", new=io.StringIO()) as stderr, \
                            patch("sys.stdout", new=io.StringIO()) as stdout:
                        self.assertEqual(report.main([
                            "-o", "example", "--output", str(self.output),
                        ]), 1)
                    path = ("/orgs/example/repos" if discovery else
                            "/repos/example/second/rulesets/rule-suites")
                    self.assertIn(path, stderr.getvalue())
                    self.assertIn(f"HTTP {code}", stderr.getvalue())
                    self.assertEqual(stdout.getvalue(), "")
                    self.assertEqual(self.output.read_text(encoding="utf-8"), "existing")
                    self.assertEqual(list(self.output.parent.iterdir()), [self.output])

    @patch.object(report, "get_token", return_value="fake-token")
    @patch.object(report, "build_opener")
    @patch.object(report.time, "sleep")
    def test_repository_retry_exhaustion_preserves_report(self, sleep, build, token):
        self.output.write_text("existing", encoding="utf-8")
        build.return_value.open.side_effect = [
            response([]), response([{"name": "first"}, {"name": "second"}]),
            response([{"id": 1, "repository_id": 10}]),
            response([{"id": 2, "repository_id": 20}],
                     '<https://api.github.com/example?page=2>; rel="next"'),
            *[http_error(429, {"Retry-After": "1"}) for _ in range(4)],
        ]
        with patch("sys.stderr", new=io.StringIO()) as stderr, \
                patch("sys.stdout", new=io.StringIO()) as stdout:
            self.assertEqual(report.main([
                "-o", "example", "--output", str(self.output),
            ]), 1)
        self.assertIn("/repos/example/second/rulesets/rule-suites", stderr.getvalue())
        self.assertIn("retries exhausted on page 2", stderr.getvalue())
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(self.output.read_text(encoding="utf-8"), "existing")
        self.assertEqual(list(self.output.parent.iterdir()), [self.output])
        self.assertEqual(sleep.call_count, 3)

    @patch.object(report, "get_token", return_value="fake-token")
    @patch.object(report, "build_opener")
    def test_cli_writes_repository_bypasses(self, build, token):
        build.return_value.open.side_effect = [
            response([]), response([{"name": "first"}]),
            response([{"id": 42, "repository_id": 10, "repository_name": "first",
                       "result": "bypass", "extra": {"source": "repository"}}]),
        ]
        with patch("sys.stdout", new=io.StringIO()) as stdout:
            self.assertEqual(report.main([
                "-o", "example", "--output", str(self.output),
            ]), 0)
        with self.output.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], "42")
        self.assertEqual(rows[0]["repository_name"], "first")
        self.assertEqual(json.loads(rows[0]["extra"]), {"source": "repository"})
        self.assertIn("Wrote 1 rule suite(s)", stdout.getvalue())

    def test_invalid_cli_arguments(self):
        for args in ([], ["-o", "../example"], ["-o", "example", "--time-period", "year"],
                     ["-o", "example", "--evaluate-status", "invalid"]):
            with self.subTest(args=args), patch("sys.stderr", new=io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    report.main(args)
                self.assertEqual(caught.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
