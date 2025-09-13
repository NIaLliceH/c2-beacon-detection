import os
from datetime import datetime, timedelta, timezone
from elasticsearch_dsl import Search
from elasticsearch_dsl.connections import connections
import pandas as pd
import numpy as np

# --- CẤU HÌNH ---
ELASTIC_HOST = os.environ.get("ELASTIC_HOST", "elasticsearch")
ELASTIC_PORT = int(os.environ.get("ELASTIC_PORT", 9200))

# Index để đọc dữ liệu Zeek conn log
# SOURCE_INDEX = "filebeat-*-zeek-conn-*"
SOURCE_INDEX = "filebeat*"
# Index để ghi kết quả điểm nghi ngờ
TARGET_INDEX = "suspicion_scores"

# Ngưỡng để coi là "đều đặn". Càng nhỏ càng đều.
PERIODICITY_THRESHOLD_SECONDS = 5.0

# --- LẤY CREDENTIALS TỪ BIẾN MÔI TRƯỜNG ---
ANALYZER_USER = os.environ.get("ANALYZER_USER")
ANALYZER_PASSWORD = os.environ.get("ANALYZER_PASSWORD")

# --- KẾT NỐI ELASTICSEARCH ---
print(f"Connecting to Elasticsearch at {ELASTIC_HOST}:{ELASTIC_PORT}...")
try:
    # Kiểm tra xem credentials có được cung cấp hay không
    if ANALYZER_USER and ANALYZER_PASSWORD:
        print(f"Authenticating with user '{ANALYZER_USER}'...")
        connections.create_connection(
            hosts=[{'host': ELASTIC_HOST, 'port': ELASTIC_PORT}],
            # Thêm tham số http_auth để xác thực
            http_auth=(ANALYZER_USER, ANALYZER_PASSWORD)
        )
    else:
        # Kết nối không cần xác thực (dùng cho môi trường dev/test)
        print("Connecting without authentication.")
        connections.create_connection(hosts=[{'host': ELASTIC_HOST, 'port': ELASTIC_PORT}])
        
    print("Successfully connected to Elasticsearch.")
except Exception as e:
    print(f"Could not connect to Elasticsearch: {e}")
    exit(1)

def analyze_periodicity():
    """
    Phân tích conn.log để tìm các kết nối có tính chu kỳ và ghi điểm.
    """
    client = connections.get_connection()
    
    # 1. TRUY VẤN DỮ LIỆU TRONG 5 PHÚT GẦN NHẤT
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=5)

    s = Search(index=SOURCE_INDEX)\
        .filter("range", **{'@timestamp': {"gte": start_time, "lt": end_time}})\
        .source(['@timestamp', 'source.ip', 'destination.ip'])
    

    print('debuggg', s)

    print(f"Querying data from {start_time} to {end_time}...")
    
    results = s.scan()

    # print('results:')
    # for r in results:
    #     ts = r['@timestamp']  # should work if it's inside _source
    #     print(ts, r.source.ip, r.destination.ip)
    
    # 2. CHUYỂN DỮ LIỆU SANG PANDAS DATAFRAME
    data = []
    for r in results:
        source = r.to_dict()  # Convert Hit to dict

        # Safe extraction with fallback
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

    # 3. NHÓM THEO CẶP (SRC, DST) VÀ TÍNH TOÁN ĐỘ LỆCH CHUẨN CỦA THỜI GIAN
    suspicious_events = []
    
    grouped = df.groupby(['src_ip', 'dst_ip'])

    for name, group in grouped:
        if len(group) < 3:
            continue
        
        time_diffs = group['timestamp'].diff().dt.total_seconds().dropna()
        
        if time_diffs.empty:
            continue

        std_dev = time_diffs.std()

        # 4. TÍNH ĐIỂM NẾU ĐỘ LỆCH CHUẨN THẤP
        if not np.isnan(std_dev) and std_dev < PERIODICITY_THRESHOLD_SECONDS:
            score = 25
            reason = (f"High Periodicity Detected (std_dev: {std_dev:.2f}s, "
                      f"count: {len(group)})")
            
            event = {
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "source": {"ip": name[0]},
                "destination": {"ip": name[1]},
                "suspicion_score": score,
                "reason": reason
            }
            suspicious_events.append(event)
            print(f"Found suspicious activity: {event}")

    # 5. GHI KẾT QUẢ VÀO INDEX MỚI
    if suspicious_events:
        print(f"Writing {len(suspicious_events)} suspicious events to index '{TARGET_INDEX}'...")
        for event in suspicious_events:
            client.index(index=TARGET_INDEX, document=event)
    else:
        print("No suspicious periodic traffic found.")

if __name__ == "__main__":
    analyze_periodicity()