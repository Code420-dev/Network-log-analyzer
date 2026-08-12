import os
from log_parser import LogAnalyzer

def get_threshold(prompt_text, default_value=3):
    user_input = input(f"{prompt_text} [Default: {default_value}]: ").strip()
    if not user_input:
        return default_value
    try:
        return int(user_input)
    except ValueError:
        print(f"[!] Invalid input. Using default ({default_value}).")
        return default_value

def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_dir = os.path.join(base_dir, 'data')

    print("========================================")
    print("      SECURE NETWORK LOG ANALYZER       ")
    print("========================================\n")

    try:
        files = [f for f in os.listdir(data_dir) if os.path.isfile(os.path.join(data_dir, f))]
    except FileNotFoundError:
        print(f"[ERROR] Data folder not found at: {data_dir}")
        return

    if not files:
        print("[ERROR] No log files found in the 'data' folder.")
        return

    print("Available Datasets:")
    for i, filename in enumerate(files, start=1):
        filepath = os.path.join(data_dir, filename)
        size_mb = os.path.getsize(filepath) / (1024 * 1024)
        print(f"  [{i}] {filename} ({size_mb:.1f} MB)")

    while True:
        choice = input(f"\nSelect a dataset (1-{len(files)}): ").strip()
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(files):
                log_path = os.path.join(data_dir, files[idx])
                break
            else:
                print("[!] Invalid number. Please pick a number from the list.")
        except ValueError:
            print("[!] Please enter a valid number.")

    print(f"\n[+] Loading {os.path.basename(log_path)}...")

    try:
        analyzer = LogAnalyzer(log_path)
        df = analyzer.load_logs()
    except FileNotFoundError as e:
        print(f"[ERROR] {e}")
        return

    # Print Statistical Traffic Summary
    summary = analyzer.get_traffic_summary(df)
    print("\n--- TRAFFIC STATISTICAL OVERVIEW ---")
    print(f"Total Log Records: {summary['total_records']}")
    print(f"Unique Source IPs: {summary['unique_ips']}")
    print(f"Unique Destination Ports: {summary['unique_ports']}")
    print("Status Breakdown:")
    for status, count in summary['status_counts'].items():
        print(f"  - {status}: {count}")

    # Configure Detection Rules
    print("\n--- CONFIGURE DETECTION RULES ---")
    brute_force_thresh = get_threshold("Enter failed login threshold for Brute-Force", 3)
    port_scan_thresh = get_threshold("Enter distinct port threshold for Port Scan", 3)

    # Brute Force Analysis
    print("\n--- BRUTE FORCE ALERTS ---")
    failed_logins = analyzer.get_failed_logins(df, threshold=brute_force_thresh)
    if not failed_logins.empty:
        for _, row in failed_logins.iterrows():
            print(f"[!] IP {row['source_ip']} had {row['failed_count']} failed logins.")
    else:
        print("No brute force detected.")

    # Port Scan Analysis
    print("\n--- PORT SCAN ALERTS ---")
    port_scans = analyzer.get_port_scans(df, threshold=port_scan_thresh)
    if not port_scans.empty:
        for _, row in port_scans.iterrows():
            print(f"[!] IP {row['source_ip']} scanned {row['ports_scanned']} different ports.")
    else:
        print("No port scans detected.")

if __name__ == "__main__":
    main()