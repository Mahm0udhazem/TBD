# TBD (Active Defense System)

An active intrusion prevention system (IPS) designed to detect zero-day threats locally by constructing a behavioral world model and executing automated mitigation protocols.

## Features

- **Behavioral World Model:** Builds a real-time performance baseline using latency variance instead of signature databases.
- **Jitter & Traffic Profiling:** Uses request timing standard deviation (`statistics.stdev`) to differentiate between automated bot attacks and human traffic.
- **Automated Mitigation:** Executes system-level network isolation upon detecting malicious automated floods.
- **Local-First Architecture:** Operates completely offline with zero reliance on cloud services or external signatures.

## Repository Contents

- `tbd.py` — Source code for the system and CustomTkinter interface.
- `dist/` — Compiled standalone executables for Windows and Linux.

## Quick Start (Pre-built Binaries)

Executable files are provided in the repository for immediate deployment without configuring Python environments.

### Windows
Run `dist/tbd.exe` (run as Administrator to allow firewall/adapter management).

### Linux
Grant execution permissions and run:
```bash
chmod +x dist/tbd
./dist/tbd
```

## Running from Source

### Prerequisites
- Python 3.8+
- `customtkinter`

### Installation
```bash
pip install customtkinter
```

### Execution
```bash
python tbd.py
```

## Build Instructions

To build the executable from source using PyInstaller:

**Windows:**
```cmd
python -m PyInstaller --noconsole --onefile --collect-all customtkinter tbd.py
```

**Linux:**
```bash
python3 -m PyInstaller --onefile --collect-all customtkinter tbd.py
```