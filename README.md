# IP Checker dashboard

Check public IPv4 addresses against IPinfo, IP2Location, proxycheck.io and
Spamhaus DQS, and optionally IPQualityScore (IPQS), with registered allocation CIDRs from RDAP. Prints a terminal
summary and writes a 40-column CSV with provider detections, diagnostics and review flags.
The browser dashboard adds live progress, summary cards, text-file import,
search, filters, sortable results, per-address detail views and CSV export.

## Start the dashboard with Docker

Install Docker Engine with Compose, then:

```bash
git clone https://github.com/Deano86/ip-checker.git
cd ip-checker
umask 077
cp .secrets.example .secrets
chmod 600 .secrets
nano .secrets
LOCAL_UID="$(id -u)" LOCAL_GID="$(id -g)" docker compose up -d --build
```

Open **http://localhost:8080** on the server. If it runs on a remote server,
use an SSH tunnel from your own computer:

```bash
ssh -L 8080:127.0.0.1:8080 your-user@your-server
```

Then open http://localhost:8080 on your computer. The Compose port is bound
to loopback. The container reads `.secrets` through a read-only mount;
credentials are excluded from the image. `LOCAL_UID` and `LOCAL_GID` let
the container read a Linux secrets file owned by your account with mode 600.
On Docker Desktop, `docker compose up -d --build` uses the default IDs.

If the checkout already exists, run `git pull` first. If `.secrets` already
contains your keys, keep it; do not copy the empty template over it.

## Start without Docker (Linux / WSL)

After installing the dependencies below and setting up `.secrets`, run:

```bash
python3 dashboard.py
```

Open http://localhost:8080. The Python server itself has no third-party
package dependencies. Bash, curl, jq, dig and Python 3 run the existing
lookup engine behind the dashboard.

## Dashboard behaviour

- Paste or import up to 500 public IPv4 addresses, one per line.
- Run one scan at a time and watch completed results arrive.
- Search, sort, filter and open an address for all 40 report fields.
- Export all completed rows, even while a scan is running.
- Check key presence and missing dependencies in the Providers screen.
- Explore clearly labelled sample results without credentials.

History stays in server memory for the latest 20 scans and clears on
restart. Export reports you want to keep. Refreshing the page reconnects
to the current scan or restores the last scan from this browser.
No credentials are accepted, stored or displayed in the browser. Provider
configuration indicates key presence, not successful authentication.
Live scans still require valid keys and access to the provider APIs.

The dashboard is intended for local use or access through an SSH tunnel.
It has no built-in login. For a shared deployment, place it behind an
authenticated HTTPS reverse proxy and set `IP_CHECKER_ALLOWED_HOSTS` to
the exact dashboard hostname (comma-separated for multiple names).
For Docker, add that variable to the service's `environment` in Compose.
Do not expose the unauthenticated service directly to the Internet.
The dashboard is self-hosted; it is not deployed to Sites hosting, which
does not run this Bash/DNS lookup engine or mount a local `.secrets` file.

## Update or stop Docker

```bash
git pull
LOCAL_UID="$(id -u)" LOCAL_GID="$(id -g)" docker compose up -d --build
docker compose down
```

## CLI install (Ubuntu / Debian)

Requires Bash 4.3+, curl, jq, dig and Python 3. Run it on Linux or in WSL.

```bash
sudo apt-get update
sudo apt-get install -y git curl jq dnsutils python3
git clone https://github.com/Deano86/ip-checker.git
cd ip-checker
umask 077
cp .secrets.example .secrets
chmod 600 .secrets
nano .secrets
cp ip-addresses.example.txt ip-addresses.txt
nano ip-addresses.txt
bash ip-checker.sh
```

The repository is private, so cloning requires GitHub access to it.
Use your own keys from your provider accounts, with access to the queried
endpoints. No keys are included in this repository.

## Secrets

All four keys go in the **local `.secrets` file**, next to the script:

```bash
IPINFO_KEY='your-ipinfo-token'
IP2_KEY='your-ip2location-key'
PROXY_KEY='your-proxycheck-key'
SPAMHAUS_KEY='your-spamhaus-dqs-key'
IPQS_KEY='your-ipqualityscore-key' # optional
```

`.secrets` is ignored by Git. Only the empty `.secrets.example` template is
committed. Input lists, CSV reports and the original separate token filenames
are also ignored. Do not force-add these files. If a key has already been
committed elsewhere, revoke it with its provider; ignoring a file does not
remove it from history.

The configuration is sourced as Bash code: use only a file you control.
Keep it readable only by the account running the script (`chmod 600`).
To keep it outside the checkout:

```bash
IP_CHECKER_SECRETS=/secure/path/.secrets bash ip-checker.sh
```

## Usage

```bash
bash ip-checker.sh [input-file [output-csv]]
bash ip-checker.sh /root/ip-addresses.txt /root/ip-results.csv
```

Defaults are `ip-addresses.txt` and `ip-results.csv` beside the script,
regardless of the current working directory. An existing output is replaced
on each run. The output cannot be the input or secrets file. Files created
by the script use a restrictive umask.

Input accepts one public IPv4 address per line, optional `#` comments, blank
lines and duplicates. IPv6 and invalid/non-public addresses are skipped.

`YES` means a positive detection; `NO` means an explicit negative;
`UNKNOWN` means unavailable, missing or unrecognised data. Anonymisation
is `YES` if any source is positive, `UNKNOWN` if no source is positive and
any detection is unknown, and `NO` only when all checked signals are negative.
`INCOMPLETE` marks otherwise unflagged rows with unknown classification data.
Rows with positive flags can also contain unknown fields; inspect the columns.
The incomplete summary counts rows labelled `INCOMPLETE`.

Spamhaus PBL alone is not treated as a threat listing. SBL, CSS, XBL and
DROP are threat flags. RDAP CIDRs describe registered allocations, not
necessarily currently announced routing prefixes. Results support manual
review and are not a guarantee that an address is safe or malicious.

Requests send each address to the listed services and applicable RDAP
registries. API failures and rate limits produce unknown results. Paid
subscriptions, provider quotas and Spamhaus DQS resolver access may be
required. Lookups run sequentially with bounded per-request timeouts.

## Checks

GitHub Actions runs Bash and JavaScript syntax checking and offline regression tests with
mock responses. It does not require API keys or perform live provider lookups.

```bash
bash -n ip-checker.sh
node --check web/app.js
python3 -m unittest discover -s tests -v
```

## IPQualityScore (IPQS)

Add `IPQS_KEY='your-key'` to your existing `.secrets` file to enable IPQS.
Keep the four original provider keys. An empty or missing IPQS key disables
only IPQS and does not prevent scans. Rebuild after pulling this update:

```bash
git pull
nano .secrets
LOCAL_UID="$(id -u)" LOCAL_GID="$(id -g)" docker compose up -d --build
```

The dashboard shows IPQS configuration status and a fraud score column.
Per-address details and CSV contain lookup status, fraud score (0–100),
proxy, VPN, Tor, recent abuse and bot flags. The first 19 CSV columns stay
in the same order; seven IPQS columns are appended. Older saved CSVs are
unchanged. New scans are needed to populate IPQS results.

IPQS positives contribute to anonymisation and VPN/Tor/proxy review flags.
Recent abuse and bot detections add `IPQS_RECENT_ABUSE` and `IPQS_BOT` review
flags; the Spamhaus threat column stays specific to Spamhaus. The fraud
score is shown as returned and does not impose an automatic blocking rule.
Invalid keys, provider failures, quota errors and missing fields stay unknown;
an otherwise unflagged scan row is incomplete when enabled IPQS data is missing.
`NOT_CONFIGURED` means IPQS was skipped; `OK` means a successful API response;
`ERROR` means it did not return a successful response.

Authentication uses the server-side `ipqs-key` request header, following
[IPQS authentication documentation](https://www.ipqualityscore.com/documentation/about-ipqs-apis/submitting-data-to-ipqs-apis).
Field meanings follow the [IPQS response reference](https://www.ipqualityscore.com/documentation/proxy-detection-api/response-parameters).
Live lookups consume your IPQS account's quota.

## Provider diagnostics and fallback data

New scans include provider statuses, ASN/provider sources and a separate
`Lookup Health` column. `PARTIAL` is shown even on rows with positive review
flags, and the Incomplete filter includes these rows. Missing or blank fields
display as `UNKNOWN`. Successful detections remain visible when another
provider fails.

Network identity uses IPinfo's legacy response, then its Lite API when the
legacy organisation field is absent. If unavailable, it uses valid fields
from IP2Location, proxycheck.io and IPQS in that order. ASN and provider each
show their source. Fallback data does not hide failed-provider diagnostics.
The Lite fallback adds one request only when the legacy field is missing.

| Status | Action |
| --- | --- |
| `AUTH_ERROR` | Check that provider's key in `.secrets`. |
| `ACCESS_DENIED` | Check the key, endpoint access, account plan and provider restrictions. |
| `RATE_LIMIT_OR_QUOTA` | Check the provider's usage/credits and retry after the applicable limit resets. |
| `AUTH_OR_QUOTA_ERROR` | IP2Location code 10000 combines invalid-key and exhausted-query conditions; check both in your account. |
| `TIMEOUT` / `NETWORK_ERROR` | Check server DNS, connectivity and outbound HTTPS access. |
| `MISSING_NETWORK_FIELDS` / `MISSING_PROXY_FIELD` | The response lacks required data; check endpoint/plan access. |
| `INVALID_JSON` / `INVALID_RESPONSE` | The provider returned unusable data. |

Statuses are classified from HTTP codes and provider responses. Raw error
messages, response bodies, URLs and credentials are not exposed in reports.
An IPinfo diagnostic lists both legacy and Lite outcomes when fallback runs.
The original 26 columns retain their order; seven diagnostic columns are appended.
Old scan reports are not re-enriched: run a new scan after rebuilding.

## Risk gauges and provider comparison

The Risk & Reputation panel shows speedometer-style gauges for the selected
address's IPQS fraud score and proxycheck risk score. Both use their original
0–100 scale, where higher means higher risk. They are separate provider
models, not interchangeable scores or probabilities. Missing scores show
an empty grey gauge labelled Unknown, never a misleading zero. Spamhaus
reputation is shown as a listing status rather than an invented numeric score.

Choose an address in the panel, or open a result to select its gauges.
The detail view compares VPN, proxy/anonymity, Tor and hosting by provider.
Explicit YES/NO differences are highlighted and can be filtered using
Providers disagree. Unknown and unsupported fields do not count as negative
votes. Anonymity comparison includes proxycheck's anonymous/VPN/proxy/Tor
signals because IPQS and IP2 proxy flags cover anonymity more broadly.
Hosting comparison uses proxycheck hosting against IPQS connection type.
Provider definitions differ; a disagreement does not establish which is correct.

Seven more IPQS fields are appended to the original 33 report columns:
active VPN, active Tor, connection type, abuse frequency, verified crawler,
hostname and country code. These are taken from the existing IPQS response;
no additional endpoint or lookup call is added. Plan-restricted or absent
context fields remain UNKNOWN and do not by themselves make lookup health
partial. Active VPN/Tor positives contribute to the corresponding review flags.
Suspected VPN/Tor and active VPN/Tor are kept separate in the report.
Crawler identification provides context and never suppresses other detections.

After pulling and rebuilding, run a new scan to populate the new fields.
Saved history and lookup caching are not included in this update.

## Email lookup and dark mode

Use **Email lookup** in the sidebar to check one email address with IPQS.
It uses the same `IPQS_KEY` from `.secrets`, independently of the four
required IP scan providers. Your IPQS account must have email API access
and available email lookup credits. Submitted addresses are sent to IPQS
using a server-side HTTPS POST; the API key is sent in a request header.
No email is sent by the dashboard itself.

The report includes validity, disposable status, fraud risk, deliverability,
recent abuse, DNS/catch-all signals and other selected reputation fields.
Absent or plan-restricted fields remain UNKNOWN. A timed-out mailbox check
does not become a confirmed invalid address. The report can be exported to
CSV; email input/results are not persisted to disk or browser storage.
The optional Sample report button uses illustrative local data without an API call.

Dark mode is the default. The top bar has a Light mode / Dark mode toggle;
the browser remembers your selection. The theme is applied before the page
styles load to minimise a white flash. Existing IP scan behaviour is preserved.

Reference: [IPQS email verification](https://www.ipqualityscore.com/documentation/email-validation-api/overview).

References: [IPinfo Lite response fields](https://ipinfo.io/developers/lite-api),
[IP2Location response fields and error codes](https://www.ip2location.io/ip2location-documentation).
