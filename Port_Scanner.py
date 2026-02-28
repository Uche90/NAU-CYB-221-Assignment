'''
Name: Obi Promise Uche
Registration Number: 2024924028
Course Code: NAU-CYB 221
Level: 200l
Department: Cyber Security
Faculty: Physical Science
'''

# NAU-CYB 221 – Local Port Discovery Tool (Defensive, Local Machine Only)
import psutil
import socket
import argparse
import json
from datetime import datetime
from prettytable import PrettyTable

HIGH_INTEREST_PORTS = {21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389}


def get_connections():
    """Fetch all relevant inet connections for listening/bound ports.
    Note: UDP 'listening' is approximated by bound sockets (laddr present, no raddr, status NONE).
    This aligns with 'where available' in assignment; true UDP listen doesn't exist in sockets."""
    try:
        conns = psutil.net_connections(kind='inet')
    except PermissionError:
        print("Permission denied. Run as administrator/sudo for full process/PID info.")
        conns = []
    
    listening = []
    for conn in conns:
        if conn.type == socket.SOCK_STREAM and conn.status == psutil.CONN_LISTEN:
            listening.append(conn)
        elif conn.type == socket.SOCK_DGRAM and conn.laddr and not conn.raddr:
            listening.append(conn)
    return listening


def extract_info(conn):
    """Extract and classify port info from a connection."""
    laddr = conn.laddr
    port = laddr.port
    ip = laddr.ip
    protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
    
    pid = conn.pid
    process = "Unknown"
    if pid:
        try:
            process = psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            process = "Access Denied / Zombie"
    
    service = "Unknown"
    try:
        service = socket.getservbyport(port, protocol.lower())
    except OSError:
        try:
            # Fallback without proto if fails
            service = socket.getservbyport(port)
        except OSError:
            pass
    
    risk = "Local-only" if ip in {"127.0.0.1", "::1"} else "Exposed"
    is_high_interest = port in HIGH_INTEREST_PORTS
    flag = "CRITICAL" if risk == "Exposed" and is_high_interest else \
           "High-Interest" if is_high_interest else "Normal"
    
    # Attention score for Top 5 sorting: higher = more attention
    attention_score = 3 if flag == "CRITICAL" else 2 if flag == "High-Interest" else 1 if risk == "Exposed" else 0
    
    return {
        "protocol": protocol,
        "port": port,
        "local_address": ip,
        "pid": pid if pid else "N/A",
        "process": process,
        "service": service,
        "risk": risk,
        "flag": flag,
        "attention_score": attention_score
    }


def build_report(args):
    """Build and filter the port report."""
    results = [extract_info(conn) for conn in get_connections()]
    
    # Apply filters
    if args.tcp_only:
        results = [r for r in results if r["protocol"] == "TCP"]
    if args.udp_only:
        results = [r for r in results if r["protocol"] == "UDP"]
    if args.above is not None:
        results = [r for r in results if r["port"] > args.above]
    if args.below is not None:
        results = [r for r in results if r["port"] < args.below]
    
    # Sort by protocol (TCP first), then port
    results.sort(key=lambda x: (x["protocol"] != "TCP", x["port"]))
    return results


def print_table(results):
    """Print pretty table to terminal."""
    if not results:
        print("No listening ports found (or none after filtering).")
        return
    
    table = PrettyTable([
        "Protocol", "Port", "Local Address", "PID", "Process Name", "Service", "Risk", "Attention"
    ])
    table.align = "l"
    for r in results:
        table.add_row([
            r["protocol"], r["port"], r["local_address"],
            r["pid"], r["process"], r["service"],
            r["risk"], r["flag"]
        ])
    print(f"\nLocal Listening Ports Report – {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(table)


def save_reports(results, txt_file="ports_report.txt", json_file="ports_report.json"):
    """Save to TXT and JSON files."""
    # TXT
    with open(txt_file, "w", encoding="utf-8") as f:
        f.write(f"Local Port Report – {datetime.now()}\n\n")
        for r in results:
            f.write(f"{r['protocol']} {r['port']} | {r['local_address']} | "
                    f"{r['process']} (PID {r['pid']}) | {r['service']} | "
                    f"Risk: {r['risk']} | Attention: {r['flag']}\n")
    
    # JSON (exclude internal score)
    json_results = [{k: v for k, v in r.items() if k != "attention_score"} for r in results]
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(json_results, f, indent=2, sort_keys=True)


def print_summary(results):
    """Print Top 5 ports by security attention (sorted by score descending)."""
    if not results:
        return
    
    sorted_by_attention = sorted(results, key=lambda x: x["attention_score"], reverse=True)[:5]
    if sorted_by_attention:
        print("\nTop 5 ports by security attention:")
        for r in sorted_by_attention:
            print(f"  {r['protocol']} {r['port']} ({r['service']}) – {r['risk']} / {r['flag']} – {r['process']} (PID {r['pid']})")


def main():
    parser = argparse.ArgumentParser(description="Local listening ports enumerator (defensive only)")
    parser.add_argument("--tcp-only", action="store_true", help="Show only TCP")
    parser.add_argument("--udp-only", action="store_true", help="Show only UDP")
    parser.add_argument("--above", type=int, help="Show only ports above this threshold")
    parser.add_argument("--below", type=int, help="Show only ports below this threshold")
    args = parser.parse_args()
    
    # Validate mutually exclusive filters if needed, but assignment allows combos
    if args.tcp_only and args.udp_only:
        print("Error: Cannot filter both TCP-only and UDP-only simultaneously.")
        return
    
    results = build_report(args)
    print_table(results)
    save_reports(results)
    print_summary(results)


if __name__ == "__main__":
    main()
