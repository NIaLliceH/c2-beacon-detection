import pyshark
from collections import defaultdict
import statistics

# === CONFIG ===
pcap_file = "traffic.pcap"
internal_network_prefix = "192.168."  # hoặc 10. / 172.16. để lọc mạng nội bộ

# Load capture
capture = pyshark.FileCapture(pcap_file, display_filter="tcp")

# Dictionary: { (src_ip, dst_ip): [timestamps, payload_sizes] }
conn_data = defaultdict(lambda: {'timestamps': [], 'payload_sizes': []})

print("[+] Đang phân tích PCAP...")

for pkt in capture:
    try:
        src_ip = pkt.ip.src
        dst_ip = pkt.ip.dst
        timestamp = float(pkt.sniff_timestamp)

        # Lọc chỉ lấy kết nối từ mạng nội bộ ra ngoài
        if src_ip.startswith(internal_network_prefix):
            # Payload size (nếu có tcp.len)
            payload_size = int(pkt.length)

            key = (src_ip, dst_ip)
            conn_data[key]['timestamps'].append(timestamp)
            conn_data[key]['payload_sizes'].append(payload_size)

    except AttributeError:
        # Bỏ qua gói tin không có IP hoặc TCP
        continue

capture.close()

print("\n[+] Thống kê beaconing:\n")
for key, data in conn_data.items():
    src, dst = key
    timestamps = sorted(data['timestamps'])
    payloads = data['payload_sizes']

    if len(timestamps) < 2:
        continue  # Không đủ dữ liệu để tính interval

    # Tính khoảng thời gian giữa các kết nối
    intervals = [round(timestamps[i+1] - timestamps[i], 3) for i in range(len(timestamps)-1)]
    
    # Jitter = độ lệch chuẩn của intervals
    jitter = round(statistics.pstdev(intervals), 3)
    avg_interval = round(statistics.mean(intervals), 3)

    # Thống kê payload
    avg_payload = round(statistics.mean(payloads), 2)
    min_payload = min(payloads)
    max_payload = max(payloads)

    print(f"[SRC: {src} -> DST: {dst}]")
    print(f"  - Số kết nối: {len(timestamps)}")
    print(f"  - Avg interval: {avg_interval}s | Jitter: {jitter}s")
    print(f"  - Payload size (bytes): Avg={avg_payload}, Min={min_payload}, Max={max_payload}")
    print(f"  - Intervals: {intervals[:10]}{'...' if len(intervals)>10 else ''}\n")