Local Listening Ports Enumerator (Defensive – Local Machine Only)

NAU-CYB 221 – Cybersecurity Technology

Scans listening TCP ports and bound UDP sockets on the local host using psutil. Shows protocol, port, bind address, PID/process (sudo required), service name, exposure risk, and high-interest flags. Outputs terminal table, txt log, JSON export, and top security attention summary.
Scope: Local machine inspection only. No remote scanning, no network probing.
Requirements
Python 3
pip install psutil prettytable
Tested on ChromeOS Crostini (Debian container)
Installation
python3 -m venv venv
source venv/bin/activate
pip install psutil prettytable
Usage
Recommended (for full PID/process visibility):
sudo venv/bin/python3 scanner.py

Filters:
sudo venv/bin/python3 scanner.py --tcp-only
sudo venv/bin/python3 scanner.py --udp-only
sudo venv/bin/python3 scanner.py --above 1000
sudo venv/bin/python3 scanner.py --below 100

Outputs
Terminal: PrettyTable + Top 5 attention summary


ports_report.txt


ports_report.json


Sample Output (ChromeOS Crostini, sudo)

Local Listening Ports Report – 2026-02-28 14:47:23
+----------+------+---------------+------+--------------+---------+------------+-----------+
| Protocol | Port | Local Address | PID  | Process Name | Service | Risk       | Attention |
+----------+------+---------------+------+--------------+---------+------------+-----------+
| TCP      | 3217 | 127.0.0.1     | 1285 | code         | Unknown | Local-only | Normal    |
| UDP      | 68   | 0.0.0.0       | 109  | dhclient     | bootpc  | Exposed    | Normal    |
+----------+------+---------------+------+--------------+---------+------------+-----------+

Top 5 ports by security attention:
  UDP 68 (bootpc) – Exposed / Normal – dhclient (PID 109)
  TCP 3217 (Unknown) – Local-only / Normal – code (PID 1285)

Limitations
UDP detection is bound-socket approximation (no real LISTEN state)


Process names/PIDs hidden without sudo


Crostini shows very few ports due to container + host isolation


Service mapping fails on non-standard ports
