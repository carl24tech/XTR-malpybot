# XTR Malware Scanner

<div align="center">
  
**Professional Malware Detection Tool for Terminal**

[![Version](https://img.shields.io/badge/version-1.0.0-red.svg)](https://github.com/xtrsoftwares/xtr-malware-scanner)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

</div>

---

## ⚠️ API Status

> **🚧 UNDER DEVELOPMENT:** We are currently building the REST API. The CLI tool is fully functional and production-ready. API endpoints and documentation will be released in Q2 2024.

---

## Features

- 🔍 Multi-engine scanning (Signature, Heuristic, YARA, Behavioral)
- ⚡ High-performance parallel scanning
- 📊 Multiple report formats (Text, JSON, HTML)
- 🎯 Real-time directory monitoring
- 🔄 Automatic signature updates
- 🎨 Colorful terminal interface

---

## Installation

```bash
# Install from GitHub
pip install git+https://github.com/xtrsoftwares/xtr-malware-scanner.git

# Or clone and install
git clone https://github.com/xtrsoftwares/xtr-malware-scanner.git
cd xtr-malware-scanner
pip install -e .
```

---

## Quick Usage

```bash
# Scan a file
xtr-scan scan suspicious.exe

# Scan directory recursively
xtr-scan scan /downloads -r

# Scan with heuristic analysis
xtr-scan scan /path --heuristic

# Generate HTML report
xtr-scan scan /path -r -o report.html -f html

# Real-time monitoring
xtr-scan monitor /watch-directory

# Update signatures
xtr-scan update
```

---

## Commands

| Command | Description |
|---------|-------------|
| `scan` | Scan files or directories |
| `monitor` | Real-time file monitoring |
| `update` | Update malware signatures |
| `database` | Database operations |

### Scan Options

- `-r, --recursive` - Scan subdirectories
- `-o, --output FILE` - Save report
- `-f, --format FORMAT` - text, json, html
- `--heuristic` - Enable heuristic analysis
- `--yara FILE` - Custom YARA rules
- `--quarantine` - Auto-quarantine threats

---

## Examples

```bash
# Basic scan
xtr-scan scan ~/Downloads

# Full system scan with report
xtr-scan scan / -r -o system_scan.html -f html --heuristic

# Monitor downloads folder
xtr-scan monitor ~/Downloads

# Quick scan with JSON output
xtr-scan scan file.exe -o result.json -f json
```

---

## Requirements

- Python 3.8+
- pip packages (auto-installed): yara-python, colorama, tqdm, prettytable, psutil

---

## Project Structure

```
xtr-malware-scanner/
├── xtr_scanner/          # Main package
│   ├── scanner/          # Scanning engines
│   ├── models/           # Data models
│   ├── utils/            # Utilities
│   └── cli.py           # Command line interface
├── signatures/           # Malware signatures
├── logs/                # Scan logs
├── reports/             # Generated reports
├── setup.py             # Installation script
└── requirements.txt     # Dependencies
```

---

## Coming Soon (API)

- 🌐 REST API endpoints
- 🖥️ Web dashboard
- 📱 Mobile SDK
- 🔗 SIEM integration

**API Beta Access**: api-beta@xtrsoftwares.com

---



## License

MIT License - see [LICENSE](LICENSE) file

---

<div align="center">
  
**Made with ❤️ by XTR Softwares**

*CLI: Stable | API: Building*

</div>
