# main.py - ログパースと全体実行
from datetime import datetime
import re
import pandas as pd
from tree_engine import evaluate_ip


def run_analysis(log_text=None):
    sample_logs = [
        "192.168.1.10 - - [04/Sep/2026:10:00:00 +0900] 'GET /index.html HTTP/1.1' 200 1200",
        "192.168.1.10 - - [04/Sep/2026:10:00:15 +0900] 'GET /about.html HTTP/1.1' 200 3400",
        "172.16.0.99 - - [04/Sep/2026:10:00:00 +0900] 'GET /api/v1 HTTP/1.1' 200 500",
        "172.16.0.99 - - [04/Sep/2026:10:00:01 +0900] 'GET /api/v1 HTTP/1.1' 200 500",
        "172.16.0.99 - - [04/Sep/2026:10:00:02 +0900] 'GET /api/v1 HTTP/1.1' 200 500",
        "10.0.0.50 - - [04/Sep/2026:10:00:00 +0900] 'POST /login HTTP/1.1' 401 250",
        "10.0.0.50 - - [04/Sep/2026:10:00:01 +0900] 'POST /login HTTP/1.1' 401 250",
    ]

    lines = log_text.strip().split("\n") if log_text else sample_logs
    pattern = r"(?P<ip>\d+\.\d+\.\d+\.\d+).*?\[(?P<time>.*?)\] [\"'](?P<method>\w+)\s+(?P<url>\S+).*?[\"'] (?P<status>\d+) (?P<bytes>\d+|-)"

    ip_logs = {}
    for line in lines:
        match = re.search(pattern, line)
        if match:
            ip = match.group("ip")
            time_raw = match.group("time").split(" ")[0]
            dt = None
            for fmt in (
                "%d/%b/%Y:%H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
            ):
                try:
                    dt = datetime.strptime(time_raw, fmt)
                    break
                except ValueError:
                    continue

            if dt:
                raw_bytes = match.group("bytes")
                ip_logs.setdefault(
                    ip,
                    {"timestamps": [], "statuses": [], "urls": [], "bytes": []},
                )
                ip_logs[ip]["timestamps"].append(dt)
                ip_logs[ip]["statuses"].append(int(match.group("status")))
                ip_logs[ip]["urls"].append(match.group("url"))
                ip_logs[ip]["bytes"].append(
                    int(raw_bytes) if raw_bytes.isdigit() else 0
                )

    results = [evaluate_ip(ip, data) for ip, data in ip_logs.items()]
    return pd.DataFrame(results)


if __name__ == "__main__":
    df_result = run_analysis()
    print(df_result.to_string())
