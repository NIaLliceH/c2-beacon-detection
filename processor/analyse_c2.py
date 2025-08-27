import pyshark
import json
from collections import defaultdict
import sys
import os
from datetime import datetime

def calculate_jitter(timestamps):
    """Calculates the average jitter from a list of packet timestamps."""
    if len(timestamps) < 2:
        return 0.0

    interarrival_times = [
        (timestamps[i] - timestamps[i-1]).total_seconds() 
        for i in range(1, len(timestamps))
    ]
    
    if len(interarrival_times) < 2:
        return 0.0

    jitters = [
        abs(interarrival_times[i] - interarrival_times[i-1]) 
        for i in range(1, len(interarrival_times))
    ]
    
    return sum(jitters) / len(jitters) if jitters else 0.0

def analyze_pcap(pcap_file, output_file):
    """
    Analyzes a pcap file to extract conversation metrics for C2 beaconing detection.
    """
    print(f"[*] Starting analysis of {pcap_file}...")
    
    # Use a dictionary to store conversations, keyed by a sorted tuple of IP addresses
    conversations = defaultdict(lambda: {
        # 'packets': 0, 
        'timestamps': [], 
        'total_payload_size': 0,
        'packet_count': 0
    })

    try:
        # Use keep_packets=False for memory efficiency with large files
        cap = pyshark.FileCapture(pcap_file, keep_packets=False)
        
        for packet in cap:
            try:
                # We are interested in IP conversations
                if 'IP' in packet:
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    
                    # Create a canonical key for the conversation
                    conv_key = tuple(sorted((src_ip, dst_ip)))
                    
                    conversations[conv_key]['packet_count'] += 1
                    conversations[conv_key]['total_payload_size'] += int(packet.length)
                    
                    # Use sniff_time which is a datetime object
                    packet_timestamp = packet.sniff_time
                    conversations[conv_key]['timestamps'].append(packet_timestamp)

            except AttributeError:
                # Packet might not have the expected attributes (e.g., non-IP packets)
                continue
    
    except Exception as e:
        print(f"[!] An error occurred while reading the pcap file: {e}")
        return

    print(f"[*] Found {len(conversations)} unique IP conversations.")
    
    # Process conversations to calculate final metrics
    processed_conversations = []
    last_seen_times = {}

    # Sort conversations by the first packet's timestamp to calculate intervals correctly
    sorted_conv_keys = sorted(conversations.keys(), key=lambda k: conversations[k]['timestamps'][0])

    for conv_key in sorted_conv_keys:
        conv_data = conversations[conv_key]
        
        if not conv_data['timestamps']:
            continue
            
        conv_data['timestamps'].sort()
        
        start_time = conv_data['timestamps'][0]
        end_time = conv_data['timestamps'][-1]
        
        duration = (end_time - start_time).total_seconds()
        
        # Calculate interval from the last conversation involving this pair
        interval = 0.0
        if conv_key in last_seen_times:
            interval = (start_time - last_seen_times[conv_key]).total_seconds()
        last_seen_times[conv_key] = end_time

        jitter = calculate_jitter(conv_data['timestamps'])
        
        processed_conversations.append({
            'timestamp': start_time.isoformat(),
            'src_ip': conv_key[0],
            'dst_ip': conv_key[1],
            'packet_count': conv_data['packet_count'],
            'total_payload_size': conv_data['total_payload_size'],
            'connection_duration': duration,
            'connection_interval': interval,
            'average_jitter': jitter
        })

    # Write results to a newline-delimited JSON file
    try:
        with open(output_file, 'w') as f:
            for conv in processed_conversations:
                f.write(json.dumps(conv) + '\n')
        print(f"[*] Analysis complete. Results written to {output_file}")
    except IOError as e:
        print(f"[!] Error writing to output file: {e}")

if __name__ == "__main__":
    if len(sys.argv)!= 3:
        print("Usage: python3 analyze_c2.py <path_to_pcapng_file> <path_to_output_json_file>")
        sys.exit(1)
        
    pcap_path = sys.argv[1]
    output_path = sys.argv[2]
    
    if not os.path.exists(pcap_path):
        print(f"[!] Error: PCAP file not found at {pcap_path}")
        sys.exit(1)
        
    analyze_pcap(pcap_path, output_path)