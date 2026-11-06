# Ruleset CSV reports

Two dependency-free Python CLIs for GitHub.com:

| Script | Report |
| --- | --- |
| `ruleset_bypass_report.py` | Completed ruleset bypass **activity** within a lookback window. |
| [`repo_rulesets_report.py`](#repository-rulesets-and-bypass-actors) | Current repository ruleset **configuration** and configured bypass actors. |

Both use `-o`/`--org`, environment or `gh` authentication, complete pagination,
bounded rate-limit retries, and atomic CSV output. Keep both scripts together:
the configuration exporter imports the shared API/CSV helpers from the activity
exporter.

## Ruleset bypass activity report

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

For the **activity report**, the [current endpoint documentation](https://docs.github.com/en/rest/orgs/rule-suites#list-organization-rule-suites--fine-grained-access-tokens)
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

## Repository rulesets and bypass actors

`repo_rulesets_report.py` inventories the rulesets returned for **every repository
visible to the token** in an organization, including repository-level rulesets.
By default it also includes inherited organization/enterprise rulesets that the
repository API returns. Source type and source name distinguish local and
inherited configuration. All returned enforcement states and targets are
included, including disabled/evaluate-mode rulesets, tags, and push rulesets.
No target or enforcement filter is applied.

```sh
# Local rulesets plus any inherited rulesets returned by GitHub.
python3 repo_rulesets_report.py -o example-org

# Only rulesets configured at the repository level.
python3 repo_rulesets_report.py --org example-org --repository-only \
  --output ./example-repository-rulesets.csv

python3 repo_rulesets_report.py --help
```

Default output: `ORG-repo-rulesets.csv` in the current working directory.
There is no time-period option: this is current configuration, not activity.
Archived repositories and forks are included when visible to the caller.

### Access and completeness

Authentication lookup is the same as the activity report. The current REST
documentation lists **Metadata repository permission (read)** for
[listing organization repositories](https://docs.github.com/en/rest/repos/repos#list-organization-repositories),
[listing repository rulesets](https://docs.github.com/en/rest/repos/rules#get-all-repository-rulesets),
and [reading a repository ruleset](https://docs.github.com/en/rest/repos/rules#get-a-repository-ruleset).
However, GitHub explicitly **omits `bypass_actors` unless the caller has write
access to that ruleset**. Read access alone is not enough for this report.
Use credentials with write access to each ruleset being inventoried, including
the appropriate organization/enterprise access for inherited rulesets. Repository
Administration (write) is relevant to repository-owned rulesets, not a substitute
for access to organization-owned rulesets. A token must also have access to every
repository you intend to cover; a selected-repository token cannot inventory
repositories outside its selection.

If GitHub hides a bypass list, the script fails explicitly rather than treating
it as an empty list. API errors, malformed responses, hidden actor lists, or
failed writes exit `1` without creating/replacing the final report. Invalid CLI
arguments exit `2`. An empty organization result produces headers only.
Repositories without rulesets still get a coverage row.

Visibility limitations apply even when requests succeed: the API may silently
omit repositories the caller cannot see. This report is not proof of
organization-wide completeness unless the caller has organization-wide access.
Like the activity report, multiple requests are not an atomic snapshot.

### CSV layout and interpretation

There is **one row per repository/ruleset/bypass-actor combination**. A ruleset
with no bypass actors gets one row with empty actor columns. A repository with
no rulesets gets one row with empty ruleset/actor columns. An inherited ruleset
appears under each repository for which GitHub returns it.

| Columns | Meaning |
| --- | --- |
| `organization` | Requested organization login. |
| `repository_id`, `repository_name`, `repository_full_name` | Repository identity. |
| `repository_visibility`, `repository_private`, `repository_archived`, `repository_fork`, `repository_html_url` | Repository scope and context, when returned. |
| `record_type` | `ruleset` or `repository_without_rulesets`. |
| `bypass_actors_status` | `configured`, `none` (explicit empty array), or `not_applicable` (no rulesets). Hidden actor lists are errors, never `none`. |
| `bypass_actor_type`, `bypass_actor_id` | Configured actor kind and GitHub ID. IDs are scoped by actor type, not necessarily user IDs. |
| `bypass_mode` | `always`, `pull_request`, or `exempt`, as returned by GitHub. |
| `bypass_actor_json` | Complete actor object, including any additional fields. |
| `ruleset_id`, `ruleset_name`, `ruleset_node_id` | Ruleset identity. |
| `ruleset_source_type`, `ruleset_source` | Defining level (`Repository`, `Organization`, `Enterprise`) and source. |
| `ruleset_target`, `ruleset_enforcement` | Target and enforcement state. Configured bypass entries in disabled/evaluate rulesets are not proof of currently enforced bypass privileges. |
| `ruleset_conditions` | Complete JSON conditions determining where the ruleset applies. |
| `ruleset_rules` | Complete JSON rule definitions and parameters. Bypass actors apply to the ruleset, not individually enumerated rules. |
| `ruleset_bypass_actors` | Full JSON bypass list, repeated across that ruleset's actor rows. |
| `ruleset_current_user_can_bypass` | Repository-specific bypass status of the authenticated caller, when returned; not the status of the actor in the row. |
| `ruleset_created_at`, `ruleset_updated_at`, `ruleset__links` | Timestamps and API/HTML links, when returned. |
| Other `ruleset_*` columns | Every additional field returned by the summary or detail endpoint, preserving nested values as JSON. Detail values take precedence. |

Actor types currently include `User`, `Team`, `Integration`, `RepositoryRole`,
`OrganizationAdmin`, and `DeployKey`. Organization administrators and deploy-key
categories may have a null actor ID. Actors are exported **as configured**, by
type and ID: the script does not expand teams, roles, administrators, apps, or
deploy keys into users, or resolve their display names. An `Integration` actor
ID identifies the app, not an individual user.

`pull_request` restricts bypass to pull requests; `exempt` means rules are not
run for that actor and a bypass audit entry is not created. Preserve these modes
when interpreting eligibility. This is not a report of actual bypass activity
or an exhaustive effective-permissions calculation: conditions, enforcement,
other applicable rulesets and non-ruleset protections still matter.

### API efficiency and rate limits

The script uses the shared authenticated client and rate-limit policy documented
above. Repository and ruleset lists request 100 entries per page, with stable
repository name ordering. It fetches one detail per distinct repository/ruleset
pair because summaries do not provide the full configuration and bypass list.
Duplicate repositories and rulesets encountered during pagination are skipped.
It does not perform actor-name lookups or member-expansion requests, and does
not make a separate organization-ruleset inventory pass.

An inherited ruleset's detail is deliberately retrieved in each repository's
context, rather than blindly reusing another repository's response:
`current_user_can_bypass` and bypass-list visibility are contextual. Requests
are sequential to avoid concurrent bursts and secondary rate-limit pressure.
Retries resume the same request; output is written only after all requests and
permission checks succeed.

## Tests

```sh
python3 -m unittest -v
```

Tests use fabricated values and mock authentication/network calls. They cover
both scripts, repository/ruleset pagination, rate-limit retries and exhaustion,
all-field CSV output, bypass actor types and modes, hidden actor permissions,
empty results, failures, authentication, and CLI options. No real organization
queries are needed.
