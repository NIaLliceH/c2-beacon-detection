import os
from datetime import datetime, timedelta, timezone
from elasticsearch_dsl import Search
from elasticsearch_dsl.connections import connections
import pandas as pd
import numpy as np

# --- CẤU HÌNH ---
ELASTIC_HOST = os.environ.get("ELASTIC_HOST", "elasticsearch")
ELASTIC_PORT = int(os.environ.get("ELASTIC_PORT", 9200))

SOURCE_INDEX = "filebeat*"
TARGET_INDEX = "suspicion_scores"

# Internal network prefix
INTERNAL_PREFIX = os.environ.get("INTERNAL_PREFIX", "192.168.28.")
# C2 IP Blacklist
BLACKLIST = {}

# --- LẤY CREDENTIALS ---
ANALYZER_USER = os.environ.get("ANALYZER_USER")
ANALYZER_PASSWORD = os.environ.get("ANALYZER_PASSWORD")

# --- KẾT NỐI ---
print(f"Connecting to Elasticsearch at {ELASTIC_HOST}:{ELASTIC_PORT}...")
try:
    if ANALYZER_USER and ANALYZER_PASSWORD:
        connections.create_connection(
            hosts=[{'host': ELASTIC_HOST, 'port': ELASTIC_PORT}],
            http_auth=(ANALYZER_USER, ANALYZER_PASSWORD)
        )
    else:
        connections.create_connection(
            hosts=[{'host': ELASTIC_HOST, 'port': ELASTIC_PORT}]
        )
    print("Successfully connected to Elasticsearch.")
except Exception as e:
    print(f"Could not connect to Elasticsearch: {e}")
    exit(1)

def classify_ip(ip: str) -> str:
    return "internal" if ip.startswith(INTERNAL_PREFIX) else "external"

def analyze_periodicity():
    client = connections.get_connection()

    # 1. Query dữ liệu 5 phút gần nhất
    end_time = datetime.now(timezone(timedelta(hours=7)))
    start_time = end_time - timedelta(minutes=5)

    s = Search(index=SOURCE_INDEX)\
        .filter("range", **{'@timestamp': {"gte": start_time, "lt": end_time}})\
        .source(['@timestamp', 'source.ip', 'destination.ip'])

    print(f"Querying data from {start_time} to {end_time}...")
    results = s.scan()

    # 2. Load vào DataFrame
    data = []
    for r in results:
        source = r.to_dict()
        src_ip = (source.get("source", {}).get("ip") or
                  source.get("source", {}).get("address"))
        dst_ip = (source.get("destination", {}).get("ip") or
                  source.get("destination", {}).get("address"))
        timestamp = source.get("@timestamp")

        if src_ip and dst_ip and timestamp:
            data.append({
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip
            })

    if not data:
        print("No relevant connection data found in the last 5 minutes.")
        return

    df = pd.DataFrame(data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values(by='timestamp')
    print(f"Analyzing {len(df)} connection logs...")

    # 3. Gom nhóm theo cặp (unordered)
    df['pair'] = df.apply(lambda row: tuple(sorted([row['src_ip'], row['dst_ip']])), axis=1)
    grouped = df.groupby('pair')

    connection_stats = []

    for pair, group in grouped:
        if len(group) < 3:
            continue

        time_diffs = group['timestamp'].diff().dt.total_seconds().dropna()
        if time_diffs.empty:
            continue

        avg_interval = time_diffs.mean()
        jitter = time_diffs.std()

        # đếm số packet mỗi chiều
        src_a, src_b = pair
        sent_a = len(group[group['src_ip'] == src_a])
        sent_b = len(group[group['src_ip'] == src_b])
        total_packets = sent_a + sent_b

        # phân loại internal/external
        ip_role = {ip: classify_ip(ip) for ip in pair}
        internal_ip = next((ip for ip, role in ip_role.items() if role == "internal"), None)
        external_ip = next((ip for ip, role in ip_role.items() if role == "external"), None)

        connection_stats.append({
            "pair": pair,
            "internal_ip": internal_ip,
            "external_ip": external_ip,
            "sent_a": sent_a,
            "sent_b": sent_b,
            "total": total_packets,
            "avg_interval": avg_interval,
            "jitter": jitter
        })

    if not connection_stats:
        print("No valid connections found for scoring.")
        return

    # 4. Xác định top 3 kết nối nhiều packets nhất
    sorted_by_total = sorted(connection_stats, key=lambda x: x['total'], reverse=True)
    top3_pairs = {tuple(item['pair']) for item in sorted_by_total[:3]}

    suspicious_events = []

    for stat in connection_stats:
        score = 0
        reasons = []

        if stat['external_ip'] in BLACKLIST:
            score += 30
            reasons.append(f"External IP {stat['external_ip']} in blacklist")

        if stat['sent_a'] == stat['sent_b']:
            score += 15
            reasons.append("Packets sent == received")

        if tuple(stat['pair']) in top3_pairs:
            score += 20
            reasons.append("Top 3 by total packets")

        if stat['avg_interval'] < 3:
            score += 15
            reasons.append(f"Avg interval {stat['avg_interval']:.2f}s < 3s")

        if stat['jitter'] < 2:
            score += 20
            reasons.append(f"Jitter {stat['jitter']:.2f}s < 2s")

        if score > 0:
            event = {
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "source": {"ip": stat['internal_ip']},
                "destination": {"ip": stat['external_ip']},
                "suspicion_score": score,
                "reason": "; ".join(reasons),
                "stats": {
                    "total_packets": stat['total'],
                    "avg_interval": round(stat['avg_interval'], 3),
                    "jitter": round(stat['jitter'], 3),
                }
            }
            suspicious_events.append(event)
            print(f"[+] Suspicious connection: {event}")

    # 5. Ghi kết quả vào Elasticsearch
    if suspicious_events:
        print(f"Writing {len(suspicious_events)} suspicious events to index '{TARGET_INDEX}'...")
        for event in suspicious_events:
            client.index(index=TARGET_INDEX, document=event)
    else:
        print("No suspicious traffic found.")

if __name__ == "__main__":
    analyze_periodicity()
