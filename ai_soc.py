import pandas as pd
from datetime import datetime

# =========================
# CONFIG
# =========================
CONN_LOG = "conn.log"
DNS_LOG = "dns.log"
HTTP_LOG = "http.log"

CONN_THRESHOLD = 5          # for demo
EXFIL_THRESHOLD = 1000000   # 1 MB

# =========================
# LOAD CONN LOG
# =========================
def load_conn_log(file_path):
    rows = []
    with open(file_path, "r") as f:
        for line in f:
            if line.startswith("#"):
                continue
            parts = line.strip().split("\t")
            try:
                ts = float(parts[0])
                src_ip = parts[2]
                dst_ip = parts[4]
                orig_bytes = parts[9]

                rows.append({
                    "ts": ts,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "orig_bytes": int(orig_bytes) if orig_bytes != "-" else 0
                })
            except:
                continue

    df = pd.DataFrame(rows)
    df["time"] = df["ts"].apply(lambda x: datetime.fromtimestamp(x))
    return df

# =========================
# LOAD DNS LOG
# =========================
def load_dns_log(file_path):
    rows = []
    with open(file_path, "r") as f:
        for line in f:
            if line.startswith("#"):
                continue
            parts = line.strip().split("\t")
            try:
                ts = float(parts[0])
                src_ip = parts[2]
                query = parts[4]

                rows.append({
                    "ts": ts,
                    "src_ip": src_ip,
                    "query": query
                })
            except:
                continue

    df = pd.DataFrame(rows)
    df["time"] = df["ts"].apply(lambda x: datetime.fromtimestamp(x))
    return df

# =========================
# LOAD HTTP LOG
# =========================
def load_http_log(file_path):
    rows = []
    with open(file_path, "r") as f:
        for line in f:
            if line.startswith("#"):
                continue
            parts = line.strip().split("\t")
            try:
                ts = float(parts[0])
                src_ip = parts[2]
                host = parts[4]
                uri = parts[5]

                rows.append({
                    "ts": ts,
                    "src_ip": src_ip,
                    "host": host,
                    "uri": uri
                })
            except:
                continue

    df = pd.DataFrame(rows)
    df["time"] = df["ts"].apply(lambda x: datetime.fromtimestamp(x))
    return df

# =========================
# DETECTION: PORT SCAN
# =========================
def detect_port_scan(conn_df):
    alerts = []
    conn_df["time_bucket"] = conn_df["time"].dt.floor("1min")

    grouped = conn_df.groupby(["src_ip", "time_bucket"]).size().reset_index(name="conn_count")

    for _, row in grouped.iterrows():
        if row["conn_count"] > CONN_THRESHOLD:
            alerts.append({
                "type": "Possible Port Scan",
                "src_ip": row["src_ip"],
                "time_window": row["time_bucket"],
                "connections": row["conn_count"],
                "severity": "High",
                "recommendation": "Investigate host for scanning activity"
            })

    return alerts

# =========================
# DETECTION: DATA EXFIL
# =========================
def detect_data_exfil(conn_df):
    alerts = []
    conn_df["time_bucket"] = conn_df["time"].dt.floor("1min")

    grouped = conn_df.groupby(["src_ip", "time_bucket"])["orig_bytes"].sum().reset_index()

    for _, row in grouped.iterrows():
        if row["orig_bytes"] > EXFIL_THRESHOLD:
            alerts.append({
                "type": "Possible Data Exfiltration",
                "src_ip": row["src_ip"],
                "time_window": row["time_bucket"],
                "bytes_sent": row["orig_bytes"],
                "severity": "Critical",
                "recommendation": "Check for large outbound transfers"
            })

    return alerts

# =========================
# PLAYBOOK GENERATOR
# =========================
def generate_playbook(alert):
    if alert["type"] == "Possible Port Scan":
        return [
            "Verify if the source IP is internal or external",
            "Check firewall/IDS logs for blocked or allowed traffic",
            "Identify targeted ports and critical assets",
            "Check if the scanning host is authorized",
            "Block the source IP if malicious",
            "Escalate if repeated scanning is observed"
        ]

    elif alert["type"] == "Possible Data Exfiltration":
        return [
            "Identify the host generating large outbound traffic",
            "Check destination IP reputation",
            "Review user activity on the source host",
            "Inspect transferred data for sensitive content",
            "Isolate the host if data theft is suspected",
            "Escalate to incident response team"
        ]

    else:
        return ["No playbook available"]

# =========================
# BUILD UNIFIED DATASET
# =========================
def build_unified_dataset(conn_df, dns_df, http_df):
    unified_rows = []

    for _, row in conn_df.iterrows():
        unified_rows.append({
            "ts": row["time"],
            "src_ip": row["src_ip"],
            "dst": row["dst_ip"],
            "log_type": "conn",
            "feature": "bytes_sent",
            "value": row["orig_bytes"]
        })

    for _, row in dns_df.iterrows():
        unified_rows.append({
            "ts": row["time"],
            "src_ip": row["src_ip"],
            "dst": row["query"],
            "log_type": "dns",
            "feature": "query",
            "value": row["query"]
        })

    for _, row in http_df.iterrows():
        unified_rows.append({
            "ts": row["time"],
            "src_ip": row["src_ip"],
            "dst": row["host"],
            "log_type": "http",
            "feature": "uri",
            "value": row["uri"]
        })

    return pd.DataFrame(unified_rows)

# =========================
# SOC OUTPUT
# =========================
def soc_output(alerts):
    if not alerts:
        print("✅ No threats detected\n")
        return

    print("\n🚨 SOC ALERTS 🚨\n")

    for alert in alerts:
        print(f"[ALERT] {alert['type']}")
        print(f"Time Window : {alert['time_window']}")
        print(f"Source IP   : {alert['src_ip']}")

        if "connections" in alert:
            print(f"Connections : {alert['connections']}")
        if "bytes_sent" in alert:
            print(f"Bytes Sent  : {alert['bytes_sent']}")

        print(f"Severity    : {alert['severity']}")
        print(f"Action      : {alert['recommendation']}")

        print("Playbook:")
        steps = generate_playbook(alert)
        for i, step in enumerate(steps, 1):
            print(f"  {i}. {step}")

        print("-" * 50)

# =========================
# MAIN
# =========================
def main():
    print("🔍 Loading logs...")

    conn_df = load_conn_log(CONN_LOG)
    dns_df = load_dns_log(DNS_LOG)
    http_df = load_http_log(HTTP_LOG)

    print(f"Conn rows: {len(conn_df)} | DNS rows: {len(dns_df)} | HTTP rows: {len(http_df)}")

    print("🧠 Running detections...")
    alerts = []
    alerts += detect_port_scan(conn_df)
    alerts += detect_data_exfil(conn_df)

    print("📢 Generating SOC alerts...")
    soc_output(alerts)

    print("🔗 Building unified dataset for AI/ML...")
    unified_df = build_unified_dataset(conn_df, dns_df, http_df)

    print("\n📊 Unified Dataset Preview:")
    print(unified_df.head())

# =========================
# RUN
# =========================
if __name__ == "__main__":
    main()
