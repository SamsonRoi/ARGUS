# ARGUS

**Network Attack Surface Mapper**

_See everything. Miss nothing._

ARGUS is a Python command-line tool for network reconnaissance and attack surface assessment. It aims to discover network assets, identify open ports and services, analyze potential security exposures, and generate structured reports.

> **Authorized use only.** ARGUS is intended for defensive security assessments on networks you own or have explicit written permission to test. Scan results indicate potential exposure. They do not prove exploitability.

## Current Status

ARGUS is in early development.

### Implemented

- Randomized startup banner
- Interactive, menu-driven CLI
- Safe menu input handling
- CIDR range, single IP, and multiple IP entry
- Current session management
- Session start-time tracking
- Target replacement confirmation
- Session clearing

### Not Yet Implemented

- Authorization confirmation
- IP address and CIDR validation
- Host discovery
- TCP/UDP port scanning
- Service and version detection
- Asset classification and network mapping
- Evidence-based risk analysis
- Report generation
- Scan history and comparison using SQLite

**Note:** ARGUS currently collects and stores target text only. It does not perform network scans.

## Planned Features

- Host discovery and network reconnaissance
- TCP/UDP port scanning
- Service and version detection
- Asset classification and network mapping
- Evidence-based risk analysis and prioritization
- Reports in HTML, JSON, CSV, and PDF
- Scan history and comparison using SQLite

## Requirements

- Python 3.10 or newer
- Git
- Nmap (required when scanning functionality is implemented)

## Installation

Clone the repository:

```bash
git clone https://github.com/SamsonRoi/ARGUS.git
cd ARGUS
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it:

**Windows PowerShell**

```powershell
.\venv\Scripts\Activate.ps1
```

**Windows Command Prompt**

```cmd
venv\Scripts\activate.bat
```

**Linux / macOS**

```bash
source venv/bin/activate
```

Install ARGUS and its dependencies:

```bash
pip install -e .
```

## Usage

Start ARGUS:

```bash
argus
```

Follow the interactive menu to explore the available options.

## Project Structure

```text
ARGUS/
├── argus/
│   ├── __init__.py
│   ├── main.py
│   ├── banner.py
│   ├── menus.py
│   └── utils/
│       ├── __init__.py
│       ├── prompts.py
│       ├── session.py
│       ├── target_parser.py
│       ├── validators.py
│       └── helpers.py
├── requirements.txt
├── pyproject.toml
├── README.md
└── LICENSE
```

Some utility modules are planned for future development and may not contain implementation yet.

## License

ARGUS is released under the MIT License. See the [LICENSE](LICENSE) file.
