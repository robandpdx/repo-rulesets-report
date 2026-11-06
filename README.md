# Ruleset bypass CSV report

A dependency-free Python CLI that exports **completed organization ruleset
bypass activity**, one CSV row per rule suite. It calls
[`GET /orgs/{org}/rulesets/rule-suites`](https://docs.github.com/en/rest/orgs/rule-suites#list-organization-rule-suites)
with `rule_suite_result=bypass`, retrieves all pages, and includes every field
returned by the list endpoint.

This is **not** a push-protection bypass-request report, a list of people eligible
to bypass rules, or a count of distinct users.

## Setup and authentication

Use Python 3.9 or newer. No pip packages are required.

```sh
git clone https://github.com/robandpdx/ruleset-bypass-report.git
cd ruleset-bypass-report
```

Authenticate with either an environment token or the existing GitHub CLI:

```sh
gh auth login --hostname github.com
python3 ruleset_bypass_report.py --org example-org
```

Alternatively, securely supply a token as `GH_TOKEN` or `GITHUB_TOKEN` in your
environment, for example through a secret manager. Lookup order is `GH_TOKEN`,
`GITHUB_TOKEN`, then `gh auth token --hostname github.com`. Tokens are never
passed as CLI options, written to the CSV, or printed by the tool. Do not commit
tokens or reports. The tool targets GitHub.com, not GitHub Enterprise Server.

The [current endpoint documentation](https://docs.github.com/en/rest/orgs/rule-suites#list-organization-rule-suites--fine-grained-access-tokens)
supports fine-grained personal access tokens, GitHub App user access tokens,
and GitHub App installation access tokens. It requires **"Administration"
organization permissions (write)** for fine-grained tokens, despite the endpoint
being read-only. Configure access for the target organization; organization
approval may also be required. Do not substitute repository Administration or
assume read-only organization permission is sufficient.

Existing `gh` credentials must also be authorized to access this endpoint;
successful login alone does not guarantee access. For classic/OAuth credentials,
check your organization's policy and SAML SSO authorization rather than assuming
the default CLI scopes are sufficient. The endpoint reference does not specify a
classic-token scope, so this tool does not claim a minimum classic scope.
Never broaden token permissions unnecessarily. A `403` can indicate insufficient
access or rate limiting; a `404` can indicate an incorrect login or inaccessible
organization. Requests use API version `2026-03-10`.

## Usage

```sh
# Default: last month, active enforcement, bypass results only.
python3 ruleset_bypass_report.py -o example-org

# Choose an existing output directory and a shorter window.
python3 ruleset_bypass_report.py --org example-org \
  --time-period week --output ./example-report.csv

# Include suites for active and evaluate-mode rulesets.
python3 ruleset_bypass_report.py -o example-org --evaluate-status all

python3 ruleset_bypass_report.py --help
```

| Option | Meaning |
| --- | --- |
| `-o`, `--org` | Required organization **login**, not display name or URL. |
| `--time-period` | `hour`, `day`, `week`, or `month`; default `month`. |
| `--evaluate-status` | `active`, `evaluate`, or `all`; default `active`. |
| `--output` | CSV filename/path; default `ORG-ruleset-bypasses.csv` in the current working directory. |

The endpoint's own default time period is `day`; this tool explicitly requests
`month`. GitHub defines these rolling lookback windows (`day` is the past 24 hours;
`week` is the past 168 hours). This tool does not accept arbitrary historical
start/end dates or promise access beyond the API's available history.
The list endpoint also supports `actor_name`, `ref`, and `repository_name` filters,
but this CLI intentionally does not apply them.

The tool requests 100 rows per page and paginates until completion. Only after
every page succeeds does it write a UTF-8 CSV, replacing the chosen output file
atomically. Existing output is overwritten on success; parent directories must
already exist. Zero results produce a header-only file, not an error.
HTTP, authentication, network, malformed-response, and output errors print to
stderr and exit with status `1`; invalid CLI arguments exit with status `2`.
Retrieval failures do not create or overwrite a report.

### Pagination and rate limits

The exporter follows pagination by requesting successive page numbers, using
GitHub's `Link: ...; rel="next"` signal and continuing after full 100-row pages.
Rate-limited requests retry **the same page**, without appending duplicate rows.
It honors `Retry-After` (seconds or an HTTP date) first, then
`X-RateLimit-Reset` when the remaining quota is zero. Secondary limits without
those headers use exponential waits of 60, 120, then 240 seconds.

There are at most three retries per page and each automatic wait is capped at
300 seconds. A longer required wait fails immediately with the wait duration,
rather than retrying before GitHub permits it. Retry progress goes to stderr;
exhausted retries fail explicitly and leave any existing report untouched.
Authentication/permission errors are not retried as rate limits unless GitHub
identifies rate limiting through its headers or error message. Other HTTP and
network failures are not retried automatically.

## Report columns

These are the list endpoint's documented fields. They appear even in empty reports.

| Column | Meaning |
| --- | --- |
| `id` | Rule suite identifier, not a user or bypass-request identifier. |
| `actor_id` | GitHub identifier for the actor responsible for the suite. |
| `actor_name` | Actor login/name returned by GitHub. |
| `before_sha` | Git commit SHA before the activity. |
| `after_sha` | Git commit SHA after the activity. |
| `ref` | Git reference involved, such as `refs/heads/main`. |
| `repository_id` | GitHub repository identifier. |
| `repository_name` | Repository name returned by the API. |
| `pushed_at` | Timestamp for the push/activity returned by GitHub. |
| `result` | Rule suite result; this tool requests `bypass`. |
| `evaluation_result` | Rules evaluation outcome returned by GitHub, distinct from the suite result. |

Any additional returned fields are included as extra columns, sorted by name,
including fields first encountered on later pages. Nested objects and arrays
are serialized as JSON within correctly quoted CSV cells; booleans are `true`
or `false`. Null and missing values become empty cells. Other scalar values
are preserved as CSV text.

The separate
[`GET /orgs/{org}/rulesets/rule-suites/{rule_suite_id}`](https://docs.github.com/en/rest/orgs/rule-suites#get-an-organization-rule-suite)
detail endpoint exposes `rule_evaluations`. This tool does **not** request
details or infer which individual rule was bypassed, the bypass reason, or
actor eligibility from the list data.

### Interpretation and limitations

Multiple suites can belong to the same actor. Counting rows counts suites,
not distinct users, repositories, or individual rules bypassed. Interpret
`result` and `evaluation_result` separately and retain the enforcement filter
and lookback window alongside your report. An empty report means no matching
activity was returned in that scope, not that no one can bypass rules.

Pagination is not an atomic snapshot: concurrent activity may change the results
while pages are retrieved. Coverage is limited to what the authenticated caller
and the API expose. CSV cells contain unmodified API values; treat reports as
untrusted data and import cells as text in spreadsheet software to avoid formula
execution. Reports can contain sensitive organization activity: store and share
them appropriately. CSV reports are excluded by `.gitignore`.

## Tests

```sh
python3 -m unittest -v
```

Tests use fabricated values and mock authentication/network calls. They cover
pagination, rate-limit retries and exhaustion, filters, all-field CSV output,
empty results, failures, authentication, and the required organization CLI
options. No real organization queries are needed.
