import os
import pandas as pd

class LogAnalyzer:
    def __init__(self, log_filepath):
        self.log_filepath = log_filepath

    def load_logs(self):
        if not self.log_filepath or not os.path.exists(self.log_filepath):
            raise FileNotFoundError(f"Log file not found at: '{self.log_filepath}'")

        df = pd.read_csv(self.log_filepath)

        # Auto-clean column headers
        df.columns = [str(col).strip().lower().replace(" ", "_") for col in df.columns]

        required = {"timestamp", "source_ip", "dest_port", "status", "event"}
        missing = required - set(df.columns)

        if missing:
            print("\n[!] Schema mismatch. Let's map your columns.")
            print(f"Available in your file: {list(df.columns)}\n")
            
            mapping = {}
            for req in missing:
                while True:
                    user_col = input(f"Which column is '{req}'?: ").strip().lower().replace(" ", "_")
                    if user_col in df.columns:
                        mapping[user_col] = req
                        break
                    else:
                        print(f"  -> '{user_col}' not found. Try again.")
            
            df = df.rename(columns=mapping)

        return df

    def get_traffic_summary(self, df):
        # Calculate key metrics across the dataset
        total_records = len(df)
        unique_ips = df["source_ip"].nunique()
        unique_ports = df["dest_port"].nunique()
        status_counts = df["status"].value_counts().to_dict()

        return {
            "total_records": total_records,
            "unique_ips": unique_ips,
            "unique_ports": unique_ports,
            "status_counts": status_counts
        }

    def get_failed_logins(self, df, threshold=3):
        failed = df[df["status"] == "FAILED"]
        counts = failed.groupby("source_ip").size().reset_index(name="failed_count")
        return counts[counts["failed_count"] >= threshold]

    def get_port_scans(self, df, threshold=3):
        scans = df.groupby("source_ip")["dest_port"].nunique().reset_index(name="ports_scanned")
        return scans[scans["ports_scanned"] >= threshold]