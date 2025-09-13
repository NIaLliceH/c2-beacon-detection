import pyshark
from collections import defaultdict
import statistics
import os
import argparse

# === ARGUMENTS ===
parser = argparse.ArgumentParser(description="PCAP analysis (first/last N minutes)")
parser.add_argument("pcap_file", help="Path to PCAP file")
parser.add_argument("--prefix", default="192.168.28.", help="Internal network prefix")
parser.add_argument("--minutes", type=int, default=5, help="Time window (minutes)")
parser.add_argument("--mode", choices=["first", "last"], default="first",
                    help="Analyse first N minutes or last N minutes")
args = parser.parse_args()

time_limit = args.minutes * 60  # seconds

print(f"[+] Analyzing {args.pcap_file} ({args.mode} {args.minutes} minutes)")

# === Step 1: Find cutoff if last mode
cutoff = None
if args.mode == "last":
    capture = pyshark.FileCapture(args.pcap_file, display_filter="tcp")
    last_ts = None
    for pkt in capture:
        try:
            ts = float(pkt.sniff_timestamp)
            last_ts = ts
        except AttributeError:
            continue
    capture.close()

    if last_ts is None:
        raise RuntimeError("No packets found in pcap")
    cutoff = last_ts - time_limit
    print(f"[+] Last timestamp: {last_ts}, cutoff: {cutoff}")

# === Step 2: Collect data
conn_data = defaultdict(lambda: {
    'timestamps': [],
    'src_payloads': [],
    'dst_payloads': [],
    'src_sent': 0,
    'src_recv': 0
})

capture = pyshark.FileCapture(args.pcap_file, display_filter="tcp")

start_time = None
for pkt in capture:
    try:
        ts = float(pkt.sniff_timestamp)

        if args.mode == "first":
            if start_time is None:
                start_time = ts
            if ts - start_time > time_limit:
                break
        else:  # last
            if ts < cutoff:
                continue

        src_ip = pkt.ip.src
        dst_ip = pkt.ip.dst
        payload_size = int(pkt.length)

        if src_ip.startswith(args.prefix):
            key = (src_ip, dst_ip)
            conn_data[key]['timestamps'].append(ts)
            conn_data[key]['src_payloads'].append(payload_size)
            conn_data[key]['src_sent'] += 1
        elif dst_ip.startswith(args.prefix):
            key = (dst_ip, src_ip)
            conn_data[key]['timestamps'].append(ts)
            conn_data[key]['dst_payloads'].append(payload_size)
            conn_data[key]['src_recv'] += 1

    except AttributeError:
        continue
capture.close()

# === Step 3: Analysis output
os.makedirs("analyse", exist_ok=True)
result = os.path.splitext(os.path.basename(args.pcap_file))[0]
outfile = f"analyse/{result}-{args.mode}-{args.minutes}min.txt"

with open(outfile, "w") as f:
    for key, data in conn_data.items():
        src, dst = key
        timestamps = sorted(data['timestamps'])
        if len(timestamps) < 2:
            continue

        intervals = [round(timestamps[i+1] - timestamps[i], 3) for i in range(len(timestamps)-1)]
        jitter = round(statistics.pstdev(intervals), 3) if len(intervals) > 1 else 0.0
        avg_interval = round(statistics.mean(intervals), 3)

        if data['src_payloads']:
            avg_src = round(statistics.mean(data['src_payloads']), 2)
            stddev_src = round(statistics.pstdev(data['src_payloads']), 2) if len(data['src_payloads']) > 1 else 0.0
        else:
            avg_src, stddev_src = 0, 0

        if data['dst_payloads']:
            avg_dst = round(statistics.mean(data['dst_payloads']), 2)
            stddev_dst = round(statistics.pstdev(data['dst_payloads']), 2) if len(data['dst_payloads']) > 1 else 0.0
        else:
            avg_dst, stddev_dst = 0, 0

        f.write(f"[SRC: {src} -> DST: {dst}]\n")
        f.write(f"  - Total packets: {len(timestamps)} | SRC: {data['src_sent']} | DST: {data['src_recv']}\n")
        f.write(f"  - Avg interval: {avg_interval}s | Jitter: {jitter}s\n")
        f.write(f"  - Source sent bytes: Avg={avg_src}, StdDev={stddev_src}\n")
        f.write(f"  - Destination sent bytes: Avg={avg_dst}, StdDev={stddev_dst}\n\n")

print(f"[+] Finished. Results saved to {outfile}")


# capinfos -c havoc-http-windows-mix.pcapng
# editcap -c 7500 havoc-http-windows-mix.pcapng havoc-http-split.pcapng