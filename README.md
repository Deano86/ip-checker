# IP Checker dashboard

Check public IPv4 addresses against IPinfo, IP2Location, proxycheck.io and
Spamhaus DQS, with registered allocation CIDRs from RDAP. Prints a terminal
summary and writes a 19-column CSV with provider detections and review flags.
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
- Search, sort, filter and open an address for all 19 report fields.
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
