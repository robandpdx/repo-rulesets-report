#!/usr/bin/env python3
"""Export completed organization ruleset bypass activity to CSV."""

import argparse
import csv
from email.utils import parsedate_to_datetime
from http.client import HTTPException
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener


API_ROOT = "https://api.github.com"
API_VERSION = "2026-03-10"
MAX_RATE_LIMIT_RETRIES = 3
MAX_RATE_LIMIT_WAIT = 300
COLUMNS = (
    "id",
    "actor_id",
    "actor_name",
    "before_sha",
    "after_sha",
    "ref",
    "repository_id",
    "repository_name",
    "pushed_at",
    "result",
    "evaluation_result",
)


class ReportError(Exception):
    """A report failure that can be displayed without exposing credentials."""


class NoRedirects(HTTPRedirectHandler):
    """Never forward the authorization header to a redirect destination."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def organization(value):
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", value):
        raise argparse.ArgumentTypeError(
            "org must be a GitHub organization login (1-39 letters, digits or hyphens)"
        )
    return value


def get_token():
    for name in ("GH_TOKEN", "GITHUB_TOKEN"):
        token = os.environ.get(name, "").strip()
        if token:
            if "\r" in token or "\n" in token:
                raise ReportError(f"{name} contains an invalid line break.")
            return token
    try:
        result = subprocess.run(
            ["gh", "auth", "token", "--hostname", "github.com"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ReportError(
            "No environment token found and gh authentication is unavailable. "
            "Set GH_TOKEN or GITHUB_TOKEN, or run gh auth login --hostname github.com."
        ) from None
    token = result.stdout.strip()
    if result.returncode != 0 or not token:
        raise ReportError(
            "No GitHub token found. Set GH_TOKEN or GITHUB_TOKEN, "
            "or run gh auth login --hostname github.com."
        )
    if "\r" in token or "\n" in token:
        raise ReportError("gh returned an invalid authentication token.")
    return token


def reject_json_constant(value):
    raise ValueError(f"Nonstandard JSON constant: {value}")


def rate_limit_delay(error, retry):
    headers = error.headers
    retry_after = headers.get("Retry-After")
    remaining = headers.get("X-RateLimit-Remaining")
    is_limited = error.code == 429 or (
        error.code == 403 and (retry_after is not None or remaining == "0")
    )
    if error.code == 403 and not is_limited:
        try:
            body = json.loads(error.read().decode("utf-8"))
        except (ValueError, UnicodeError, OSError, HTTPException):
            body = {}
        message = body.get("message", "") if isinstance(body, dict) else ""
        is_limited = isinstance(message, str) and any(
            phrase in message.lower()
            for phrase in ("secondary rate limit", "abuse detection", "rate limit exceeded")
        )
    if not is_limited:
        return None
    if retry_after is not None:
        try:
            delay = float(retry_after)
        except ValueError:
            try:
                delay = parsedate_to_datetime(retry_after).timestamp() - time.time()
            except (TypeError, ValueError, OverflowError):
                raise ReportError("Rate limited; invalid Retry-After header. Retry later.") from None
        if not math.isfinite(delay):
            raise ReportError("Rate limited; invalid Retry-After header. Retry later.")
        return max(1, math.ceil(delay))
    reset = headers.get("X-RateLimit-Reset")
    if remaining == "0" and reset is not None:
        try:
            return max(1, int(reset) - math.floor(time.time()) + 1)
        except ValueError:
            raise ReportError("Rate limited; invalid rate-limit reset header. Retry later.") from None
    return 60 * (2 ** retry)


def fetch_page(opener, request, page):
    for retry in range(MAX_RATE_LIMIT_RETRIES + 1):
        try:
            with opener.open(request, timeout=30) as response:
                if response.status != 200:
                    raise ReportError(
                        f"Unexpected HTTP {response.status} on page {page}."
                    )
                payload = json.loads(
                    response.read().decode("utf-8"),
                    parse_constant=reject_json_constant,
                )
                return payload, response.headers.get("Link", "")
        except HTTPError as exc:
            try:
                delay = rate_limit_delay(exc, retry)
            finally:
                exc.close()
            if delay is not None:
                if retry == MAX_RATE_LIMIT_RETRIES:
                    raise ReportError(
                        f"HTTP {exc.code}: rate-limit retries exhausted on page {page}. "
                        "Retry later; no report was written."
                    ) from None
                if delay > MAX_RATE_LIMIT_WAIT:
                    raise ReportError(
                        f"HTTP {exc.code}: rate limited on page {page}; retry in "
                        f"{delay} seconds (automatic wait limit is "
                        f"{MAX_RATE_LIMIT_WAIT} seconds). No report was written."
                    ) from None
                print(
                    f"Rate limited on page {page}; retrying in {delay} seconds "
                    f"(retry {retry + 1}/{MAX_RATE_LIMIT_RETRIES}).",
                    file=sys.stderr,
                )
                time.sleep(delay)
                continue
            hints = {
                401: "Check that your token is valid.",
                403: "Check organization access, token permissions and SSO authorization.",
                404: "Check the requested resource and your access to it.",
            }
            hint = hints.get(exc.code, "Check GitHub API availability and retry.")
            raise ReportError(f"HTTP {exc.code} on page {page}. {hint}") from None
        except (URLError, OSError, HTTPException):
            raise ReportError(
                f"Network request failed on page {page}; check connectivity and retry."
            ) from None
        except (UnicodeError, ValueError):
            raise ReportError(f"Invalid JSON response on page {page}.") from None


class GitHubClient:
    """Shared authenticated JSON requests, pagination and rate-limit handling."""

    def __init__(self, token):
        self.token = token
        self.opener = build_opener(NoRedirects())

    def request(self, path, params=None, page=1):
        query = urlencode(params or {})
        request = Request(
            f"{API_ROOT}{path}" + (f"?{query}" if query else ""),
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "ruleset-bypass-report",
            },
        )
        try:
            return fetch_page(self.opener, request, page)
        except ReportError as exc:
            raise ReportError(f"{path}: {exc}") from None

    def get(self, path, params=None):
        payload, _ = self.request(path, params)
        if not isinstance(payload, dict):
            raise ReportError(f"{path}: invalid response; expected an object.")
        return payload

    def paginate(self, path, params=None):
        page = 1
        while True:
            query = dict(params or {}, per_page=100, page=page)
            payload, link = self.request(path, query, page)
            if not isinstance(payload, list) or any(
                not isinstance(item, dict) for item in payload
            ):
                raise ReportError(
                    f"{path}: invalid response on page {page}: "
                    "expected an array of objects."
                )
            if len(payload) > 100:
                raise ReportError(f"{path}: Invalid response on page {page}: exceeds page size.")
            has_next = any(
                re.search(r';\s*rel=["\']next["\']', part)
                for part in link.split(",")
            )
            if not payload and has_next:
                raise ReportError(f"{path}: Invalid pagination on page {page}: empty next page.")
            yield from payload
            if len(payload) < 100 and not has_next:
                return
            page += 1


def fetch_suites(org, token, time_period="month", evaluate_status="active"):
    client = GitHubClient(token)
    return list(client.paginate(
        f"/orgs/{org}/rulesets/rule-suites",
        {
            "rule_suite_result": "bypass",
            "time_period": time_period,
            "evaluate_status": evaluate_status,
        },
    ))


def csv_value(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list, bool)):
        return json.dumps(value, ensure_ascii=False, allow_nan=False)
    return value


def write_csv(output, suites, columns=COLUMNS):
    extra_columns = sorted({key for suite in suites for key in suite} - set(columns))
    columns = list(columns) + extra_columns
    output = Path(output)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            for suite in suites:
                writer.writerow({key: csv_value(value) for key, value in suite.items()})
        os.replace(temporary, output)
        temporary = None
    except (OSError, ValueError, csv.Error):
        raise ReportError(
            "Could not write CSV; check the output path, permissions and disk space."
        ) from None
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                raise ReportError(
                    "CSV writing failed and its temporary file could not be removed."
                ) from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-o", "--org", required=True, type=organization)
    parser.add_argument(
        "--time-period", choices=("hour", "day", "week", "month"), default="month",
        help="GitHub API lookback window (default: month)",
    )
    parser.add_argument(
        "--evaluate-status", choices=("all", "active", "evaluate"), default="active",
        help="Ruleset enforcement filter (default: active)",
    )
    parser.add_argument(
        "--output", type=Path,
        help="CSV path (default: ORG-ruleset-bypasses.csv in the current directory)",
    )
    args = parser.parse_args(argv)
    output = args.output or Path(f"{args.org}-ruleset-bypasses.csv")
    try:
        suites = fetch_suites(
            args.org, get_token(), args.time_period, args.evaluate_status
        )
        write_csv(output, suites)
    except ReportError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Wrote {len(suites)} rule suite(s) to {output.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
