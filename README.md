# IP checker

Check public IPv4 addresses against IPinfo, IP2Location, proxycheck.io and
Spamhaus DQS, with registered allocation CIDRs from RDAP. Prints a terminal
summary and writes a 19-column CSV with provider detections and review flags.

## Install (Ubuntu / Debian)

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

GitHub Actions runs Bash syntax checking and offline regression tests with
mock responses. It does not require API keys or perform live provider lookups.

```bash
bash -n ip-checker.sh
python3 -m unittest discover -s tests -v
```
