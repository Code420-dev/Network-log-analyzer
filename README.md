# Secure Network Log Analyzer
# project by Code420-dev

A lightweight Python tool that parses firewall and server logs to detect basic suspicious network behavior, such as potential brute-force logins and port scanning. 

I built this project to practice applying data manipulation (using Pandas) to IT security concepts, keeping the architecture fast and entirely file-based without relying on a database backend.

## Features
- **Brute-Force Detection:** Flags IP addresses with multiple failed login attempts within the log timeframe.

- **Port Scan Detection:** Identifies IPs attempting to connect to an abnormal number of distinct ports.

- **Summary Generation:** Outputs a clean statistical breakdown of network traffic.

## How to run
1. Install dependencies: `pip install -r requirements.txt`
2. Run the analyzer against the sample data: `python src/main.py`