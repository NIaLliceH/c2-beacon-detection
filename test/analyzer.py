"""
C2 Beaconing and Anomaly Detection Analyzer v2.0

This script analyzes Zeek logs stored in Elasticsearch to detect Command & Control (C2)
traffic using a hybrid approach:
1.  **Enriched Heuristic Scoring:** Moves beyond simple statistical measures (like jitter
    and interval) to focus on more robust, high-fidelity indicators such as:
    - JA3/JA3S Fingerprint Rarity Analysis
    - DNS Query Entropy and Structure Analysis (for DGA/tunneling detection)
    - HTTP URI Entropy and User-Agent Rarity
    - TLS Certificate Analysis (Self-Signed, Issuer/Subject mismatch)
2.  **Unsupervised Machine Learning:** Utilizes an Isolation Forest model to detect
    anomalous connections that deviate from a learned baseline of normal network
    behavior. This helps in identifying novel and unknown C2 patterns.

The script is designed to be run periodically (e.g., via cron) to analyze recent
network traffic.
"""

import time
import yaml
import logging
from collections import Counter
from datetime import datetime, timedelta, timezone

import pandas as pd
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from scipy.stats import entropy as shannon_entropy
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

# --- Configuration ---
CONFIG_FILE = 'config.yaml'

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Helper Functions ---

def load_config(config_path):
    """Loads configuration from a YAML file."""
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            # Set default values for optional ML parameters
            config.setdefault('ml_model', {})
            config['ml_model'].setdefault('enabled', False)
            config['ml_model'].setdefault('model_path', 'isolation_forest_model.joblib')
            config['ml_model'].setdefault('scaler_path', 'scaler.joblib')
            config['ml_model'].setdefault('contamination', 0.01)
            return config
    except FileNotFoundError:
        logging.error(f"Configuration file not found at '{config_path}'. Please create it.")
        exit(1)
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML configuration file: {e}")
        exit(1)

def calculate_shannon_entropy(s):
    """Calculates the Shannon entropy of a string."""
    if not s or len(s) < 2:
        return 0.0
    # Create a frequency distribution of the characters in the string
    counts = Counter(s)
    # Calculate the probability of each character
    probabilities = [count / len(s) for count in counts.values()]
    # Calculate the Shannon entropy
    return shannon_entropy(probabilities, base=2)

# --- Main Analyzer Class ---

class C2Analyzer:
    def __init__(self, config):
        self.config = config
        self.es_client = self._connect_es()
        self.iocs = self._load_iocs()
        self.whitelists = self._load_whitelists()
        self.ml_model = None
        self.scaler = None
        if self.config['ml_model']['enabled']:
            self._load_ml_model()

    def _connect_es(self):
        """Establishes connection to Elasticsearch."""
        es_conf = self.config['elasticsearch']
        try:
            client = Elasticsearch(
                f"http://{es_conf['host']}:{es_conf['port']}",
                basic_auth=(es_conf['user'], es_conf['password']),
                verify_certs=es_conf.get('verify_certs', False)
            )
            if not client.ping():
                raise ConnectionError("Elasticsearch ping failed.")
            logging.info(f"Successfully connected to Elasticsearch at {es_conf['host']}:{es_conf['port']}")
            return client
        except Exception as e:
            logging.error(f"Failed to connect to Elasticsearch: {e}")
            exit(1)

    def _load_iocs(self):
        """Loads IoCs from specified files."""
        iocs = {}
        for ioc_type, path in self.config.get('ioc_files', {}).items():
            try:
                with open(path, 'r') as f:
                    iocs[ioc_type] = set(line.strip() for line in f if line.strip())
                logging.info(f"Loaded {len(iocs[ioc_type])} IoCs for '{ioc_type}' from {path}")
            except FileNotFoundError:
                logging.warning(f"IoC file not found for '{ioc_type}' at {path}. Skipping.")
                iocs[ioc_type] = set()
        return iocs

    def _load_whitelists(self):
        """Loads whitelists from specified files."""
        whitelists = {}
        for wl_type, path in self.config.get('whitelist_files', {}).items():
            try:
                with open(path, 'r') as f:
                    whitelists[wl_type] = set(line.strip() for line in f if line.strip())
                logging.info(f"Loaded {len(whitelists[wl_type])} whitelist entries for '{wl_type}' from {path}")
            except FileNotFoundError:
                logging.warning(f"Whitelist file not found for '{wl_type}' at {path}. Skipping.")
                whitelists[wl_type] = set()
        return whitelists

    def _load_ml_model(self):
        """Loads the pre-trained Isolation Forest model and scaler."""
        model_path = self.config['ml_model']['model_path']
        scaler_path = self.config['ml_model']['scaler_path']
        try:
            self.ml_model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            logging.info(f"Successfully loaded ML model from {model_path} and scaler from {scaler_path}")
        except FileNotFoundError:
            logging.warning(f"ML model or scaler file not found. Anomaly detection will be disabled. Please train the model first.")
            self.config['ml_model']['enabled'] = False
        except Exception as e:
            logging.error(f"Error loading ML model: {e}")
            self.config['ml_model']['enabled'] = False

    def fetch_data(self, start_time, end_time):
        """Fetches logs from multiple Zeek indices within a time range."""
        indices = {
            'conn': 'zeek-conn-log-*',
            'dns': 'zeek-dns-log-*',
            'http': 'zeek-http-log-*',
            'ssl': 'zeek-ssl-log-*',
            'x509': 'zeek-x509-log-*'
        }
        data = {key: {} for key in indices}

        for log_type, index_pattern in indices.items():
            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": start_time.isoformat(),
                            "lt": end_time.isoformat()
                        }
                    }
                },
                "size": 10000 # Adjust size as needed
            }
            try:
                res = self.es_client.search(index=index_pattern, body=query)
                hits = res['hits']['hits']
                logging.info(f"Fetched {len(hits)} documents from {index_pattern}")
                for hit in hits:
                    source = hit['_source']
                    uid = source.get('uid')
                    if uid:
                        # For conn log, store the whole record. For others, append to a list.
                        if log_type == 'conn':
                            data[log_type][uid] = source
                        else:
                            if uid not in data[log_type]:
                                data[log_type][uid] = []
                            data[log_type][uid].append(source)
            except Exception as e:
                logging.error(f"Error querying index {index_pattern}: {e}")
        return data

    def analyze(self):
        """Main analysis loop."""
        analysis_interval_min = self.config['analysis_interval_minutes']
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=analysis_interval_min)

        logging.info(f"Querying data from {start_time} to {end_time}")
        raw_data = self.fetch_data(start_time, end_time)

        if not raw_data['conn']:
            logging.info("No connection logs found in the time window.")
            return

        # --- Data Enrichment and Feature Engineering ---
        enriched_connections = self._enrich_connections(raw_data)
        
        # --- Rarity Analysis (Frequency Counting) ---
        # This should be done on a larger dataset for accuracy, but we'll do it on the current batch for demonstration
        ja3_counts = Counter(conn['ja3'] for conn in enriched_connections if conn.get('ja3'))
        ja3s_counts = Counter(conn['ja3s'] for conn in enriched_connections if conn.get('ja3s'))
        user_agent_counts = Counter(conn['user_agent'] for conn in enriched_connections if conn.get('user_agent'))
        server_name_counts = Counter(conn['server_name'] for conn in enriched_connections if conn.get('server_name'))

        # --- Scoring ---
        alerts = []
        for conn in enriched_connections:
            # Add rarity info to each connection
            conn['ja3_rarity'] = ja3_counts.get(conn.get('ja3'), 0)
            conn['ja3s_rarity'] = ja3s_counts.get(conn.get('ja3s'), 0)
            conn['user_agent_rarity'] = user_agent_counts.get(conn.get('user_agent'), 0)
            conn['server_name_rarity'] = server_name_counts.get(conn.get('server_name'), 0)

            # Heuristic scoring
            heuristic_score, reasons = self._score_heuristic(conn)
            
            # ML scoring
            ml_score, ml_prediction = -1, 0 # Default values
            if self.config['ml_model']['enabled'] and self.ml_model:
                ml_score, ml_prediction = self._score_ml(conn)

            # Generate alert if thresholds are met
            if (heuristic_score >= self.config['alert_thresholds']['heuristic'] or 
               (ml_prediction == -1 and self.config['ml_model']['enabled'])):
                
                alert = self._format_alert(conn, heuristic_score, reasons, ml_score, ml_prediction)
                alerts.append(alert)

        if alerts:
            logging.info(f"Generated {len(alerts)} alerts.")
            self._write_alerts(alerts)
        else:
            logging.info("No suspicious connections found.")

    def _enrich_connections(self, raw_data):
        """Correlate logs by UID and calculate features."""
        enriched = []
        internal_nets = self.config.get('internal_networks',)

        for uid, conn_log in raw_data['conn'].items():
            # Basic connection info
            rec = {
                'uid': uid,
                '@timestamp': conn_log.get('@timestamp'),
                'src_ip': conn_log.get('id.orig_h'),
                'src_port': conn_log.get('id.orig_p'),
                'dst_ip': conn_log.get('id.resp_h'),
                'dst_port': conn_log.get('id.resp_p'),
                'proto': conn_log.get('proto'),
                'duration': conn_log.get('duration', 0) or 0,
                'orig_bytes': conn_log.get('orig_bytes', 0) or 0,
                'resp_bytes': conn_log.get('resp_bytes', 0) or 0,
                'service': conn_log.get('service'),
                'conn_state': conn_log.get('conn_state'),
            }
            
            # Determine internal/external IPs
            rec['internal_ip'], rec['external_ip'] = self._classify_ips(rec['src_ip'], rec['dst_ip'], internal_nets)
            if not rec['internal_ip']:
                continue # Skip connections not originating from or destined for internal network

            # Enrich with DNS data
            if uid in raw_data['dns']:
                dns_rec = raw_data['dns'][uid] # Taking the first DNS query for simplicity
                rec['dns_query'] = dns_rec.get('query')
                rec['dns_query_entropy'] = calculate_shannon_entropy(rec['dns_query']) if rec['dns_query'] else 0.0
                rec['dns_qtype_name'] = dns_rec.get('qtype_name')
                rec['dns_rcode_name'] = dns_rec.get('rcode_name')
                rec['dns_answers'] = dns_rec.get('answers')

            # Enrich with HTTP data
            if uid in raw_data['http']:
                http_rec = raw_data['http'][uid]
                rec['http_uri'] = http_rec.get('uri')
                rec['http_uri_entropy'] = calculate_shannon_entropy(rec['http_uri']) if rec['http_uri'] else 0.0
                rec['http_host'] = http_rec.get('host')
                rec['user_agent'] = http_rec.get('user_agent')
                rec['http_method'] = http_rec.get('method')
                rec['http_status_code'] = http_rec.get('status_code')

            # Enrich with SSL/TLS data
            if uid in raw_data['ssl']:
                ssl_rec = raw_data['ssl'][uid]
                rec['ja3'] = ssl_rec.get('ja3')
                rec['ja3s'] = ssl_rec.get('ja3s')
                rec['server_name'] = ssl_rec.get('server_name') # SNI
                rec['tls_version'] = ssl_rec.get('version')
                
                # Enrich with x509 certificate data
                if uid in raw_data['x509']:
                    # Check the first certificate in the chain
                    cert_rec = raw_data['x509'][uid]
                    rec['cert_issuer'] = cert_rec.get('certificate.issuer')
                    rec['cert_subject'] = cert_rec.get('certificate.subject')
                    rec['cert_self_signed'] = (rec['cert_issuer'] == rec['cert_subject'])

            enriched.append(rec)
        return enriched

    def _classify_ips(self, ip1, ip2, internal_nets):
        """Classify which IP is internal and which is external."""
        ip1_is_internal = any(ip1.startswith(prefix) for prefix in internal_nets)
        ip2_is_internal = any(ip2.startswith(prefix) for prefix in internal_nets)
        
        if ip1_is_internal and not ip2_is_internal:
            return ip1, ip2
        if not ip1_is_internal and ip2_is_internal:
            return ip2, ip1
        # Either both are internal or both are external, skip for now
        return None, None

    def _score_heuristic(self, conn):
        """Calculates a suspicion score based on a set of heuristic rules."""
        score = 0
        reasons = []
        weights = self.config['heuristic_weights']

        # --- Whitelist Check ---
        if (conn.get('external_ip') in self.whitelists.get('ip', set()) or
            conn.get('http_host') in self.whitelists.get('domain', set()) or
            conn.get('server_name') in self.whitelists.get('domain', set()) or
            conn.get('ja3') in self.whitelists.get('ja3', set())):
            return 0,

        # --- IoC Matching (High Confidence) ---
        if conn.get('external_ip') in self.iocs.get('ip', set()):
            score += weights['ioc_ip']
            reasons.append("External IP in IoC list")
        if conn.get('http_host') in self.iocs.get('domain', set()) or conn.get('server_name') in self.iocs.get('domain', set()):
            score += weights['ioc_domain']
            reasons.append("Domain in IoC list")
        if conn.get('ja3') in self.iocs.get('ja3', set()):
            score += weights['ioc_ja3']
            reasons.append("JA3 fingerprint in IoC list")
        if conn.get('user_agent') in self.iocs.get('user_agent', set()):
            score += weights['ioc_user_agent']
            reasons.append("User-Agent in IoC list")

        # --- DNS Analysis ---
        if conn.get('dns_query_entropy', 0) > 3.5:
            score += weights['dns_entropy']
            reasons.append(f"High DNS query entropy ({conn['dns_query_entropy']:.2f})")
        if conn.get('dns_qtype_name') in ['NULL', 'TXT', 'ANY']:
            score += weights['dns_tunnel_qtype']
            reasons.append(f"Potential DNS tunneling (Query Type: {conn['dns_qtype_name']})")

        # --- HTTP Analysis ---
        if conn.get('http_uri_entropy', 0) > 4.0:
            score += weights['http_uri_entropy']
            reasons.append(f"High HTTP URI entropy ({conn['http_uri_entropy']:.2f})")
        if conn.get('user_agent_rarity', 100) <= 2: # Very rare UA
            score += weights['http_rare_user_agent']
            reasons.append(f"Rare User-Agent (seen {conn['user_agent_rarity']} times)")

        # --- TLS/SSL Analysis ---
        if conn.get('cert_self_signed', False):
            score += weights['tls_self_signed_cert']
            reasons.append("Self-signed TLS certificate")
        if conn.get('ja3_rarity', 100) <= 2: # Very rare JA3
            score += weights['tls_rare_ja3']
            reasons.append(f"Rare JA3 fingerprint (seen {conn['ja3_rarity']} times)")
        if conn.get('server_name') and conn.get('cert_subject') and conn.get('server_name') not in conn.get('cert_subject'):
            score += weights['tls_sni_cert_mismatch']
            reasons.append("SNI and Certificate Subject mismatch")

        # --- Connection Stats (Weak signals, lower weights) ---
        if conn.get('duration', 0) > 3600: # Connection longer than 1 hour
            score += weights['conn_long_duration']
            reasons.append(f"Long connection duration ({conn['duration']:.0f}s)")
        if conn.get('orig_bytes', 0) > 0 and conn.get('resp_bytes', 0) == 0:
            score += weights['conn_data_exfil_pattern']
            reasons.append("Possible data exfil (data out, no data in)")

        return score, reasons

    def _score_ml(self, conn):
        """Scores a connection using the loaded Isolation Forest model."""
        # Define the feature vector - MUST match the training script
        feature_names = [
            'duration', 'orig_bytes', 'resp_bytes',
            'dns_query_entropy', 'http_uri_entropy',
            'ja3_rarity', 'user_agent_rarity'
        ]
        
        # Create a dictionary with default values (0) for all features
        feature_dict = {name: 0 for name in feature_names}
        
        # Populate with actual values from the connection
        for name in feature_names:
            if name in conn and conn[name] is not None:
                feature_dict[name] = conn[name]

        # Convert to DataFrame for consistent ordering
        df_features = pd.DataFrame([feature_dict])
        
        # Scale the features
        scaled_features = self.scaler.transform(df_features)
        
        # Get anomaly score and prediction
        score = self.ml_model.decision_function(scaled_features)
        prediction = self.ml_model.predict(scaled_features) # -1 for anomaly, 1 for normal
        
        return score, prediction

    def _format_alert(self, conn, heuristic_score, reasons, ml_score, ml_prediction):
        """Formats a dictionary for an alert."""
        return {
            '@timestamp': datetime.now(timezone.utc).isoformat(),
            'event.kind': 'alert',
            'event.category': 'network',
            'event.type': 'connection',
            'event.action': 'c2-activity-detected',
            'source.ip': conn.get('internal_ip'),
            'destination.ip': conn.get('external_ip'),
            'destination.port': conn.get('dst_port'),
            'network.transport': conn.get('proto'),
            'network.protocol': conn.get('service'),
            'url.domain': conn.get('http_host') or conn.get('server_name') or conn.get('dns_query'),
            'user_agent.original': conn.get('user_agent'),
            'tls.client.ja3': conn.get('ja3'),
            'tls.server.ja3s': conn.get('ja3s'),
            'threat.tactic.name': 'Command and Control',
            'rule.name': 'Hybrid C2 Detection',
            'rule.description': 'Suspicious network connection detected by hybrid heuristic and ML analysis.',
            'rule.severity': 'high' if heuristic_score > 75 or ml_prediction == -1 else 'medium',
            'c2_detection': {
                'heuristic_score': heuristic_score,
                'heuristic_reasons': reasons,
                'ml_anomaly_score': ml_score,
                'ml_prediction': 'anomaly' if ml_prediction == -1 else 'normal',
                'connection_details': {k: v for k, v in conn.items() if v is not None}
            }
        }

    def _write_alerts(self, alerts):
        """Writes alerts to a specified Elasticsearch index."""
        index_name = self.config['elasticsearch']['alerts_index']
        actions = [
            {
                "_index": index_name,
                "_source": alert
            }
            for alert in alerts
        ]
        try:
            success, failed = bulk(self.es_client, actions)
            logging.info(f"Successfully wrote {success} alerts to index '{index_name}'.")
            if failed:
                logging.error(f"Failed to write {len(failed)} alerts.")
        except Exception as e:
            logging.error(f"Error writing alerts to Elasticsearch: {e}")

def main():
    """Main execution function."""
    config = load_config(CONFIG_FILE)
    analyzer = C2Analyzer(config)
    
    while True:
        logging.info("Starting C2 analysis run...")
        try:
            analyzer.analyze()
        except Exception as e:
            logging.error(f"An unexpected error occurred during analysis: {e}", exc_info=True)
        
        sleep_duration = config['analysis_interval_minutes'] * 60
        logging.info(f"Analysis finished. Sleeping for {config['analysis_interval_minutes']} minutes.")
        time.sleep(sleep_duration)

if __name__ == '__main__':
    # This script is intended to be run as a service.
    # For training the ML model, a separate script should be used.
    # See `train_model.py` for an example.
    main()

