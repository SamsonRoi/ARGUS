# ARGUS

**Network Attack Surface Mapper**

_See everything. Miss nothing._

ARGUS is a Python-based command-line tool for network reconnaissance and attack surface assessment.

It helps security professionals discover network hosts, identify open ports, detect running services, estimate operating systems, and understand potential exposure points.

> **Authorized use only.** ARGUS is intended for defensive security assessments on networks you own or have explicit permission to test. Scan results indicate potential exposure; they do not prove that a system is vulnerable or exploitable.

---

## Current Status

ARGUS is under active development.

### Implemented Features

- Interactive, menu-driven command-line interface.
- Target input supporting:
  - Single IPv4 addresses.
  - Multiple IPv4 addresses.
  - CIDR network ranges.
- Target validation and duplicate removal.
- Session management and target replacement confirmation.
- Host discovery using multiple discovery methods:
  - ARP discovery.
  - ICMP Echo discovery.
  - TCP SYN discovery.
  - TCP ACK discovery.
  - UDP discovery.
- TCP port scanning:
  - Quick scan – top 100 common TCP ports.
  - Standard scan – top 1,000 common TCP ports.
  - Full scan – all 65,535 TCP ports.
  - Custom port selection.
- Optional UDP port scanning.
- Service and version detection.
- Operating system estimation.
- Structured scan results and warnings.
- Nmap execution and XML result parsing.
- Scan history in a local SQLite database:
  - Every scan is saved automatically, with Nmap's raw XML as evidence.
  - Records exactly which ports each scan checked.
  - Coverage-aware comparison of any two scans.
  - Baselines, to answer "what changed since then?".
  - Engagements, to record who authorized the work and what is in scope.
- Asset classification:
  - Every host gets its likely roles (router, printer, database server and so on).
  - Each role has a confidence level and the evidence behind it.
  - Each host gets a criticality level.
- Network map:
  - Hosts grouped by subnet under their gateway.
  - Optional traceroute, so links can be marked observed or inferred.

- Risk analysis:
  - Findings with evidence, an explanation and a fix for each.
  - Context-aware 0-10 scores, with every factor shown.
  - A letter grade for the network, and a fix-first plan.
  - Possible attack paths from weak devices to critical assets.
  - History for each finding: first seen, streak, new since baseline.
  - "Resolved" only when a newer scan really checked again.
  - Accepted risks, with a reason and an expiry date.

### Planned Features

- Improved service enumeration.
- Report generation in JSON, CSV, HTML, and PDF.

---

## Requirements

- Python 3.10 or newer.
- Nmap.
- Git.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/SamsonRoi/ARGUS.git
cd ARGUS
```

### 2. Create a virtual environment

**Windows:**

```powershell
python -m venv venv
venv\Scripts\activate
```

**Linux / Kali:**

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install ARGUS

```bash
pip install -e .
```

For development and testing:

```bash
pip install -e ".[dev]"
```

---

## Usage

Start ARGUS:

```bash
argus
```

ARGUS opens an interactive command-line interface.

### Basic Workflow

1. Start ARGUS.
2. Select target configuration.
3. Enter an IP address, multiple IP addresses, or a CIDR range.
4. Review the target information.
5. Choose a scanning operation.
6. Configure additional scan options when available.
7. Review the scan results.

---

## Scanning Options

ARGUS currently provides the following scanning operations:

| Scan              | Description                                               |
| ----------------- | --------------------------------------------------------- |
| Host Discovery    | Identifies active hosts using selected discovery methods. |
| Quick TCP Scan    | Scans the top 100 common TCP ports.                       |
| Standard TCP Scan | Scans the top 1,000 common TCP ports.                     |
| Full TCP Scan     | Scans all 65,535 TCP ports.                               |
| Custom TCP Scan   | Scans user-defined ports or port ranges.                  |

Additional scan options include:

- UDP scanning.
- Service and version detection.
- Operating system estimation.
- Traceroute, for observed links in the network map.
- Discovery method selection.

Some discovery methods and scan types may require elevated privileges.

---

## Scan History

Every scan is saved automatically. Open **Scan History** from the main menu to:

- View any saved scan.
- Compare two scans.
- Compare the newest scan with its baseline.
- Mark a scan as the baseline.
- Delete a scan.
- Record engagements, and choose which one new scans are filed under.

### How comparison works

ARGUS records exactly which ports each scan checked, and only reports what it can actually tell:

| Result                   | Meaning                                                                 |
| ------------------------ | ----------------------------------------------------------------------- |
| Port opened              | Both scans checked the port; it is open now and was not before.         |
| Port no longer open      | Both scans checked the port; it was open before and is not now.         |
| Open, not checked before | The port is open now, but the older scan never checked it.              |
| Not re-checked           | The port was open before, but the newer scan did not check it.          |
| New host / Host not seen | Only reported for addresses inside both scans' targets.                 |
| Address changed          | Same MAC address, new IP: the same device moved.                        |
| Service changed          | The service or version on an open port changed.                         |
| OS estimate changed      | The operating system estimate changed.                                  |
| Role changed             | The host's likely role changed (medium or high confidence only).        |

Comparisons also show **risk changes**: findings that are new, resolved, or not re-checked.

Hosts are matched by MAC address when both scans saw one, and by IP address otherwise.

### Where the history is stored

- Default: `~/.argus/argus.db`.
- Under `sudo` on Linux/macOS, ARGUS uses the real user's home folder, so the history is not split between root and your account.
- Set the `ARGUS_DB` environment variable to use another file.

### Engagements

An engagement records who authorized the work, the authorized scope, and the dates. Scans are filed under the current engagement. ARGUS stores this information but does not enforce the scope yet.

---

## Assets and Network Map

After a scan, open **Current Session**, then **View Assets** or **Network Map**. Saved scans have both under **Scan History**.

### Asset classification

ARGUS labels each host with the roles its evidence points to, for example:

| Host         | Likely role              | Evidence                                     | Criticality |
| ------------ | ------------------------ | -------------------------------------------- | ----------- |
| 192.168.1.20 | Printer (high)           | ports 9100/tcp and 631/tcp open              | Medium      |
| 192.168.1.5  | Domain controller (high) | ports 88/tcp and 389/tcp open, 3268/tcp open | High        |

- Clues come from open ports, software and versions, MAC vendor, OS estimate, hostname, and traceroute.
- Each clue has a weight. The total gives the confidence:
  - **high**: 70 or more.
  - **medium**: 40 to 69.
  - **low**: 20 to 39.
- Some clues count against a role. For example, a Windows Server OS counts against "Workstation".
- Matching is whole-word, so "iOS" does not match "BIOS".
- A host with too little evidence is shown as **Unknown**. ARGUS does not guess.
- **Criticality** comes from the most critical medium- or high-confidence role. Unknown hosts are treated as medium. Step 7's risk scoring uses this level.
- The rules are in [`argus/data/asset_rules.toml`](argus/data/asset_rules.toml). You can add or tune roles without changing code. ARGUS checks the file when it loads, and reports mistakes clearly.

### Network map

- Hosts are grouped into the subnets that were scanned. A host scanned on its own is placed in an assumed /24, and the map says so.
- Each subnet's gateway is found in one of two ways:
  - **observed**: the first hop of a traceroute.
  - **inferred**: a host classified as a router.
- Every link is marked as one of:
  - **observed**: traceroute saw traffic pass that way.
  - **inferred**: worked out from addresses only.
- Traceroute needs Administrator/root and sends extra probes. It is off unless you choose it.

---

## Risk Analysis

Open **Current Session → Risk Analysis**, or **Scan History → Risk analysis of a saved scan**.

ARGUS turns what the scan saw into findings. **It never attacks anything.** It only reasons about open ports, software banners, OS estimates, device roles and how the network is laid out.

### What a finding contains

- **Evidence**: exactly what was seen, for example "port 23/tcp open".
- **Why it matters**, in plain words.
- **How to fix it.**
- **Confidence**:
  - **high**: the exposure itself is the problem.
  - **medium**: it is usually a problem.
  - **low**: a hint, such as an old version banner.
- **Raised because**: when the situation makes it worse, for example Telnet on a router or camera, or RDP on a public address.
- **References**, such as CWE, MITRE ATT&CK or CVE, where they apply.

### How findings are scored

Every score is worked out in the open, and every factor is printed next to it:

```text
score = severity points x asset criticality x exposure x confidence (+ persistence), capped at 10

severity:     critical 9.5 | high 7.5 | medium 5 | low 2.5 | info 0.5
criticality:  high x1.25   | medium x1.0 | low x0.8      (from asset classification)
exposure:     public address x1.3
confidence:   high x1.0    | medium x0.85 | low x0.7
persistence:  +0.5 if still open after 3 or more scans in a row
```

Example: "8.0 = high severity: 7.5 x 1.25 asset criticality high x 0.85 medium confidence".

Each score falls in a priority band:

| Band     | Score       |
| -------- | ----------- |
| critical | 9.0 or more |
| high     | 7.0 to 8.9  |
| medium   | 4.0 to 6.9  |
| low      | 1.0 to 3.9  |
| info     | below 1.0   |

The network gets a letter grade, from **A** (nothing above low) to **F** (two or more critical findings). The reason for the grade is shown.

### Beyond single hosts

- **Network segmentation**: ARGUS flags critical assets that share a subnet with weakly protected devices, and management interfaces on the general network.
- **Possible attack paths**: weak starting points (for example a camera with Telnet) next to critical targets (for example a domain controller). These are possible, not proven, because ARGUS cannot see firewalls between hosts on the same subnet.
- **Fix these first**: findings grouped by fix and ranked by how much risk each fix removes.

### Risk over time

When scan history is available:

- **First seen**: the scan in which each finding first appeared.
- **Streak**: how many scans in a row a finding has stayed open.
- **NEW since baseline**: shown only when the baseline scan could have seen the finding. Otherwise it is unknown.
- **Resolved**: the newer scan checked again, and the problem was gone.
- **Not re-checked**: the newer scan did not look. For example the port was outside its coverage, the host did not answer, or no versions were collected. ARGUS does not count these as fixed.

All scans are re-analysed with the current rules, so old and new results are always compared like with like.

### Accepted risks

Some risks are known and acceptable, for example an isolated lab device.

- To accept one, open **Risk Analysis → Accept a finding** and give a reason and, optionally, an expiry date.
- Accepted risks are left out of the grade but are always listed.
- When the expiry date passes, the risk counts again.
- **Scan History → Accepted risks** lists them all, and lets you revoke one.

### Editing the rules

The rules are in [`argus/data/risk_rules.toml`](argus/data/risk_rules.toml). The file covers:

- cleartext protocols
- remote access
- exposed databases
- services that usually have no login
- management interfaces
- end-of-life software

You can add or tune rules without changing code. ARGUS checks the file when it loads and reports mistakes clearly.

---

## Project Structure

```text
ARGUS/
│
├── argus/
│   ├── __init__.py
│   ├── main.py
│   ├── banner.py
│   ├── menus.py
│   ├── scan_menu.py
│   ├── history_menu.py
│   ├── risk_menu.py
│   ├── results_display.py
│   │
│   ├── data/
│   │   ├── __init__.py
│   │   ├── asset_rules.toml
│   │   └── risk_rules.toml
│   │
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── classify.py
│   │   ├── compare.py
│   │   ├── discovery.py
│   │   ├── evidence.py
│   │   ├── models.py
│   │   ├── nmap_parser.py
│   │   ├── nmap_runner.py
│   │   ├── port_scan.py
│   │   ├── scan_manager.py
│   │   ├── service_detect.py
│   │   ├── os_detect.py
│   │   ├── risk.py
│   │   ├── risk_history.py
│   │   ├── topology.py
│   │   ├── traceroute.py
│   │   └── versions.py
│   │
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── database.py
│   │   └── repository.py
│   │
│   └── utils/
│       ├── __init__.py
│       ├── helpers.py
│       ├── prompts.py
│       ├── session.py
│       ├── target_parser.py
│       └── validators.py
│
├── tests/
├── README.md
├── requirements.txt
├── pyproject.toml
└── LICENSE
```

---

## Running Tests

ARGUS uses `pytest` for testing.

Run the complete test suite:

```bash
python -m pytest -v
```

---

## Limitations

- Host discovery may miss systems that block or ignore discovery probes.
- CIDR-based port scanning depends on discovered hosts. Hosts that do not respond to discovery may be missed.
- UDP scan results can be inconclusive because filtered and open UDP ports may be difficult to distinguish.
- Service and operating system detection are estimates and may not always be accurate.
- Some scanning methods require elevated privileges.
- Scan results do not establish that a vulnerability exists. Risk findings describe exposure, not confirmed vulnerabilities.
- Version-based findings come from service banners. Distributions often patch software without changing the version number.
- Attack paths are possible, not proven. ARGUS cannot see firewalls between hosts on the same subnet.
- Vulnerability exploitation and NSE-based vulnerability scanning are not currently part of ARGUS.
- Comparisons can only report changes in ports that both scans checked.
- Engagement scope is recorded but not yet enforced.
- Asset roles are estimates from the evidence a scan collected, not confirmed facts.
- Without traceroute, the network map's links are inferred from addresses and may not match the real wiring. Nmap cannot trace the local machine itself.
- Report generation is a planned feature.

---

## Development Roadmap

ARGUS is being developed in stages:

1. Project foundation and interactive CLI. **Done**
2. Session management. **Done**
3. Target parsing, validation, and scope checks. **Done**
4. Nmap engine: host discovery, port scanning, service and OS detection. **Done**
5. SQLite database, scan history, and comparing scans. **Done**
6. Asset classification and a network graph. **Done**
7. The risk analysis engine. **Done**
8. Reports: JSON and CSV first, then HTML and PDF.

Next version: enforcing the authorized scope recorded in engagements.

---

## License

ARGUS is released under the MIT License. See [LICENSE](LICENSE) for details.
