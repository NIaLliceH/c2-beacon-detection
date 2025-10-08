# %%
from elasticsearch import Elasticsearch, helpers
from elasticsearch.dsl import Search
from elasticsearch.helpers import bulk
import pandas as pd
import numpy as np
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from pprint import pprint
import json
from statsmodels.tsa.stattools import acf
import matplotlib.pyplot as plt
from pandas.util import hash_pandas_object as pdhash
from datetime import datetime, timedelta
import pytz # Thư viện để xử lý múi giờ

pd.set_option('display.max_columns', None)

# %%
# Establish connection to Elasticsearch
conn = Elasticsearch(
    # ['https://192.168.145.101:9200'], 
    ['http://localhost:9200'],
    # ca_certs=False, 
    # verify_certs=False,
    # basic_auth=('jupyter', 'jupyter@seconi.com'),
    # basic_auth=('nialliceh@gmail.com', 'nialliceh3108'),
    basic_auth=('analyzer_internal', 'analyzer'),
)

print(conn.info())
# print(conn.indices.get_data_stream(name="logs-zeek*"))

# %%
# --- Search across all filebeat Zeek indices ---
zlog = Search(using=conn, index="filebeat-*")

# --- Define Zeek datasets ---
datasets = {
    "conn": "zeek.connection",
    "http": "zeek.http",
    "dns": "zeek.dns",
    "ssl": "zeek.ssl"
}

# 1. Định nghĩa múi giờ của bạn (Việt Nam, UTC+7)
local_tz = pytz.timezone("Asia/Ho_Chi_Minh")

# 2. Định nghĩa thời gian bắt đầu và kết thúc một cách tường minh
# Timestamp A: 23h ngày 6/10/2025 (UTC+7)
start_time_local = local_tz.localize(datetime(2025, 10, 6, 23, 0, 0))

# Timestamp B: 8h ngày 7/10/2025 (UTC+7)
end_time_local = local_tz.localize(datetime(2025, 10, 7, 8, 0, 0))

print(f"Querying data from {start_time_local.isoformat()} to {end_time_local.isoformat()}")


dfs = {}  # store DataFrames for each type

for name, dataset in datasets.items():
    print(f"Fetching {dataset} logs...")

    query = (
        zlog.query("term", **{"event.dataset": dataset})
            .filter("range", **{
                "@timestamp": {
                    "gte": start_time_local.isoformat(),
                    "lt": end_time_local.isoformat()
                }
            })
    )

    # Collect results
    rows = []
    for hit in query.scan():
        doc = hit.to_dict()
        rows.append(doc)   # keep full parsed document (all ECS + Zeek fields)

    # Convert to DataFrame
    if rows:
        df = pd.json_normalize(rows, sep='.')
        dfs[name] = df
        print(f"✅ {dataset}: {len(df)} rows, {len(df.columns)} columns")
    else:
        print(f"⚠️ {dataset}: no data found")

for name, df in dfs.items():
    df['@timestamp'] = pd.to_datetime(df['@timestamp']).dt.tz_convert('Asia/Bangkok')
    df['ts'] = df['@timestamp'].astype('int64') / 1e9

# %%
# convert to zeek log format

conn_df = dfs['conn'][['ts', 'source.ip', 'destination.ip', 'destination.port', 'event.duration', 'source.bytes']]
# rename columns for clarity
conn_df.columns = ['ts', 'id.orig_h', 'id.resp_h', 'id.resp_p', 'duration', 'orig_ip_bytes']
conn_df.head()


ssl_df = dfs['ssl'][['ts', 'source.ip', 'destination.ip', 'zeek.ssl.sni_matches_cert', 'zeek.ssl.server.name', 'tls.client.ja3']]
ssl_df.columns = ['ts', 'id.orig_h', 'id.resp_h', 'sni_matches_cert', 'server_name', 'ja3']
ssl_df.head()

http_df = dfs['http'][['ts', 'source.ip', 'destination.ip', 'url.domain', 'http.response.body.bytes', 'user_agent.original']]
http_df.columns = ['ts', 'id.orig_h', 'id.resp_h', 'host', 'response_body_len', 'user_agent']
http_df.head()

dns_df = dfs['dns'][['ts', 'source.ip', 'destination.ip', 'zeek.dns.query', 'zeek.dns.qtype_name', 'zeek.dns.rcode_name']]
dns_df.columns = ['ts', 'id.orig_h', 'id.resp_h', 'query', 'qtype_name', 'rcode_name']
dns_df.head()

# %%
# 1. remove logs where dstIP in whitelist
WHITELIST_IP = ['8.8.8.8', '1.1.1.1']
conn_df = conn_df.loc[~conn_df['id.resp_h'].isin(WHITELIST_IP)]

# %%
# 2. check common port
common_ports = {80, 443, 53, 22, 25, 21, 5353}

conn_df['rare_port'] = conn_df['id.resp_p'].apply(lambda x: 0 if x in common_ports else 1)

# %%
# group by srcIP, dstIP

rows = []

conn_df = conn_df.sort_values(by=['ts'])
conn_grouped = conn_df.groupby(['id.orig_h', 'id.resp_h', 'id.resp_p'])
for name, group in conn_grouped:
    rows.append({
        'srcIP': name[0],
        'dstIP': name[1],
        'dstPort': name[2],
        'timeList': group["ts"].tolist(),
        'dataList': group['orig_ip_bytes'].tolist(),
        'durList': [v for v in group['duration'].tolist() if pd.notna(v)],
        'rare_port': max(group['rare_port'].tolist()),
    })
grcon_df = pd.DataFrame(rows)

# %%
# 3. check IoC list for dstIP
with open('ioc_ip.txt', 'r') as f:
    ioc_list = {line.strip() for line in f if line.strip()}

grcon_df.loc[:, 'ip_ioc'] = np.where(grcon_df['dstIP'].isin(ioc_list), 1, 0)

# %%
# Calc Bowkey skewness and Median Absolute Deviation

# --- Lọc outlier bằng IQR ---
def remove_outliers_iqr(data, factor=1.5):
    if len(data) < 5:
        return np.array(data)
    q1, q3 = np.percentile(data, [25, 75])
    iqr = q3 - q1
    lower = q1 - factor * iqr
    upper = q3 + factor * iqr
    return data[(data >= lower) & (data <= upper)]

# --- Tính độ lệch Bowley (mức độ đối xứng của phân phối) ---
def calc_bowley_skewness(data):
    if len(data) < 5:
        return 0.0
    data = remove_outliers_iqr(np.array(data))
    q1, q2, q3 = np.percentile(data, [25, 50, 75])
    if (q3 - q1) == 0:
        return 1.0
    bowley_skewness = (q3 + q1 - 2 * q2) / (q3 - q1)
    score = 1 - abs(bowley_skewness)  # 1 là đối xứng hoàn hảo
    return score

# --- Tính MAD (độ phân tán quanh trung vị) ---
def calc_median_absolute_deviation(data):
    if len(data) < 5:
        return 0.0
    data = remove_outliers_iqr(np.array(data))
    median = np.median(data)
    mad = np.median(np.abs(data - median))
    cv_mad = mad / median if median != 0 else 0
    score = 1.0 / (1.0 + cv_mad)  # 1 là ổn định tuyệt đối
    return score

# --- Hàm tổng hợp theo cửa sổ (window-based) ---
def rolling_score(data, func, window_size=20, agg="median"):
    if len(data) < window_size:
        return func(np.array(data))
    
    scores = []
    for i in range(0, len(data) - window_size + 1, window_size):
        window = np.array(data[i:i+window_size])
        score = func(window)
        scores.append(score)
    
    if len(scores) == 0:
        return 0.0

    if agg == "median":
        return np.median(scores)
    elif agg == "mean":
        return np.mean(scores)
    elif agg == "max":
        return np.max(scores)
    else:
        raise ValueError("agg must be 'median', 'mean', or 'max'")

# Calc autocorrelation v2 using statsmodels
def calc_autocorrelation_v2(data: list) -> float:
    if len(data) < 5:
        return 0.0
    
    data = remove_outliers_iqr(np.array(data))

    if len(data) < 2 or np.var(data) == 0:
        return 1 # beacon deu

    nlags = len(data) // 2

    try:
        autocorr_values = acf(data, nlags=nlags, fft=True)
        autocorr_values = np.nan_to_num(autocorr_values, nan=0.0, posinf=0.0, neginf=0.0)
    except Exception:
        return 0.0

    if len(autocorr_values) < 2:
        return 0.0

    score = np.max(np.clip(autocorr_values[1:], 0, 1))  # chỉ quan tâm lag > 0
    return score

# %%
# save row with timeList length < 5 for the next analysis

# %%
# Calc features

def ts_to_interval(ts):
    return np.diff(ts)

# # time features
# grcon_df['time_bskew'] = grcon_df['timeList'].apply(lambda x: calc_bowley_skewness(ts_to_interval(x)))
# grcon_df['time_mad'] = grcon_df['timeList'].apply(lambda x: calc_median_absolute_deviation(ts_to_interval(x)))
# grcon_df['time_acf'] = grcon_df['timeList'].apply(lambda x: calc_autocorrelation_v2(ts_to_interval(x)))

# # data features
# grcon_df['data_bskew'] = grcon_df['dataList'].apply(lambda x: calc_bowley_skewness(x))
# grcon_df['data_mad'] = grcon_df['dataList'].apply(lambda x: calc_median_absolute_deviation(x))

# # duration features
# grcon_df['dur_bskew'] = grcon_df['durList'].apply(lambda x: calc_bowley_skewness(x))
# grcon_df['dur_mad'] = grcon_df['durList'].apply(lambda x: calc_median_absolute_deviation(x))

grcon_df['time_bskew'] = grcon_df['timeList'].apply(lambda x: rolling_score(ts_to_interval(x), calc_bowley_skewness))
grcon_df['time_mad'] = grcon_df['timeList'].apply(lambda x: rolling_score(ts_to_interval(x), calc_median_absolute_deviation))
grcon_df['time_acf'] = grcon_df['timeList'].apply(lambda x: rolling_score(ts_to_interval(x), calc_autocorrelation_v2))

grcon_df['data_bskew'] = grcon_df['dataList'].apply(lambda x: rolling_score(x, calc_bowley_skewness))
grcon_df['data_mad'] = grcon_df['dataList'].apply(lambda x: rolling_score(x, calc_median_absolute_deviation))

grcon_df['dur_bskew'] = grcon_df['durList'].apply(lambda x: rolling_score(x, calc_bowley_skewness))
grcon_df['dur_mad'] = grcon_df['durList'].apply(lambda x: rolling_score(x, calc_median_absolute_deviation))
grcon_df['dur_acf'] = grcon_df['durList'].apply(lambda x: rolling_score(x, calc_autocorrelation_v2))

grcon_df

# %%
# merge grcon_df to final_df
final_con = grcon_df.groupby(['srcIP', 'dstIP']).agg({
    'time_bskew': 'max',
    'time_mad': 'max',
    'time_acf': 'max',
    'data_bskew': 'max',
    'data_mad': 'max',
    'dur_bskew': 'max',
    'dur_mad': 'max',
    'dur_acf': 'max',
    'rare_port': 'max',
    'ip_ioc': 'max',
}).reset_index()
# final_con.set_index(['srcIP', 'dstIP'], inplace=True)
final_con['time_score'] = final_con[['time_bskew', 'time_mad']].mean(axis=1)
final_con['time_score'] = final_con[['time_score', 'time_acf']].max(axis=1)

final_con['data_score'] = final_con[['data_bskew', 'data_mad']].mean(axis=1)
final_con['dur_score'] = final_con[['dur_bskew', 'dur_mad']].mean(axis=1)
final_con['dur_score'] = final_con[['dur_score', 'dur_acf']].max(axis=1)
final_con['conn_score'] = final_con[['time_score', 'data_score']].mean(axis=1)
# if dur_score > 0.6, increase final_score by 10% as a bonus, but not exceed 1.0
final_con['conn_score'] = np.where(final_con['dur_score'] > 0.6, final_con['conn_score'] * 1.2, final_con['conn_score'])
final_con['conn_score'] = np.where(final_con['rare_port'] == 1, final_con['conn_score'] * 1.1, final_con['conn_score'])
final_con['conn_score'] = np.where(final_con['ip_ioc'] == 1, final_con['conn_score'] * 1.2, final_con['conn_score'])
final_con['conn_score'] = final_con['conn_score'].clip(upper=1.0)
# only keep important columns
final_con = final_con[['srcIP', 'dstIP', 'conn_score', 'rare_port', 'ip_ioc']]
# final_con
# final_con[(final_con['srcIP'] == '192.168.28.129') & (final_con['dstIP'] == '192.168.20.100')]



# %%
# 3. check JA3
with open('ioc_ja3.txt', 'r') as f:
    ioc_list = {line.strip() for line in f if line.strip()}

ssl_df.loc[:, 'ja3_ioc'] = np.where(ssl_df['ja3'].isin(ioc_list), 1, 0)

# %%
# group by srcIP, dstIP
rows = []
ssl_df = ssl_df.sort_values(by=['ts'])
ssl_grouped = ssl_df.groupby(['id.orig_h', 'id.resp_h'])
for name, group in ssl_grouped:
    rows.append({
        'srcIP': name[0],
        'dstIP': name[1],
        'sni_matches_cert': max(group['sni_matches_cert'].tolist()),
    })
grssl_df = pd.DataFrame(rows)
grssl_df.set_index(['srcIP', 'dstIP'], inplace=True)

for index, row in ssl_df.iterrows():
    if pd.isna(row['sni_matches_cert']):
        ssl_df.at[index, 'sni_matches_cert'] = grssl_df.loc[(row['id.orig_h'], row['id.resp_h']), 'sni_matches_cert']


# %%
# 4. check SNI
# ssl_df.loc[:, 'sni_not_matched_cert'] = np.where(ssl_df['sni_matches_cert'] == False, 1, 0)

def extract_domain(fqdn):
    if pd.isna(fqdn): return ''
    parts = fqdn.lower().split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else fqdn

SAFE_DOMAINS = [
    'google.com','gstatic.com','youtube.com','ggpht.com',
    'microsoft.com','windowsupdate.com','office.com','msftconnecttest.com',
    'apple.com','icloud.com','mzstatic.com',
    'facebook.com','fbcdn.net','instagram.com','whatsapp.net',
    'cloudflare.com','cdn.cloudflare.net',
    'dns.google','quad9.net','a.root-servers.net','b.root-servers.net','c.root-servers.net',
    'd.root-servers.net','e.root-servers.net','f.root-servers.net','g.root-servers.net',
    'h.root-servers.net','i.root-servers.net','j.root-servers.net','k.root-servers.net',
    'l.root-servers.net','m.root-servers.net'
] # service that not likely to be used for domain fronting

ssl_df = ssl_df[~(
    (ssl_df['sni_matches_cert'] == True) &
    (ssl_df['server_name'].apply(lambda x: extract_domain(x)).isin(SAFE_DOMAINS))
)]

# group by srcIP, server_name, sni_not_matched_cert
rows = []
ssl_df['sni_not_matches_cert'] = np.where(ssl_df['sni_matches_cert'] == False, 1, 0)

ssl_df = ssl_df.sort_values(by=['ts'])
ssl_df['server_name'] = ssl_df['server_name'].fillna(ssl_df['id.resp_h'])
ssl_grouped = ssl_df.groupby(['id.orig_h', 'server_name', 'sni_not_matches_cert'])
for name, group in ssl_grouped:
    rows.append({
        'srcIP': name[0],
        'server_name': name[1],
        'dstIPList': list(set(group['id.resp_h'].tolist())),
        'timeList': group["ts"].tolist(),
        'ja3_ioc': max(group['ja3_ioc'].tolist()),
        'sni_not_matched_cert': name[2],
    })
grssl_df = pd.DataFrame(rows)

# %%
# Calc features
grssl_df['time_bskew'] = grssl_df['timeList'].apply(lambda x: rolling_score(ts_to_interval(x), calc_bowley_skewness))
grssl_df['time_mad'] = grssl_df['timeList'].apply(lambda x: rolling_score(ts_to_interval(x), calc_median_absolute_deviation))
grssl_df['time_acf'] = grssl_df['timeList'].apply(lambda x: rolling_score(ts_to_interval(x), calc_autocorrelation_v2))

# %%
# merge grssl_df to final_ssl
# get max of mean(time_bskew, time_mad) and time_acf
grssl_df['ssl_score'] = grssl_df[['time_bskew', 'time_mad']].mean(axis=1)
grssl_df['ssl_score'] = grssl_df[['ssl_score', 'time_acf']].max(axis=1)
# if ja3_ioc == 1, increase ssl_score by 20% as a bonus, but not exceed 1.0
grssl_df['ssl_score'] = np.where(grssl_df['ja3_ioc'] == 1, grssl_df['ssl_score'] * 1.2, grssl_df['ssl_score'])
grssl_df['ssl_score'] = np.where(grssl_df['sni_not_matched_cert'] == 1, grssl_df['ssl_score'] * 1.2, grssl_df['ssl_score'])
grssl_df['ssl_score'] = grssl_df['ssl_score'].clip(upper=1.0)

final_ssl = grssl_df.explode('dstIPList', ignore_index=True)
final_ssl = final_ssl.rename(columns={'dstIPList': 'dstIP'})
# final_ssl.set_index(['srcIP', 'dstIP'], inplace=True)
final_ssl = final_ssl[['srcIP', 'dstIP', 'ssl_score', 'ja3_ioc', 'sni_not_matched_cert']]

# %% [markdown]
# # http.log

# %%
# check User-Agent
http_df['null_user_agent'] = http_df['user_agent'].apply(lambda x: 1 if pd.isna(x) else 0)

# %%
# group by srcIP, Host
rows = []
http_df = http_df.sort_values(by=['ts'])
http_df['host'] = http_df['host'].fillna(http_df['id.resp_h'])
http_grouped = http_df.groupby(['id.orig_h', 'host'])
for name, group in http_grouped:
    rows.append({
        'srcIP': name[0],
        'host': name[1],
        'dstIPList': list(set(group['id.resp_h'].tolist())),
        'timeList': group["ts"].tolist(),
        'dataList': group['response_body_len'].tolist(),
        'null_user_agent': 1 if pd.isna(group['user_agent']).any() else 0
    })
grhttp_df = pd.DataFrame(rows)

# %%
# Calc features

grhttp_df['time_bskew'] = grhttp_df['timeList'].apply(lambda x: rolling_score(ts_to_interval(x), calc_bowley_skewness))
grhttp_df['time_mad'] = grhttp_df['timeList'].apply(lambda x: rolling_score(ts_to_interval(x), calc_median_absolute_deviation))
grhttp_df['time_acf'] = grhttp_df['timeList'].apply(lambda x: rolling_score(ts_to_interval(x), calc_autocorrelation_v2))
grhttp_df['data_bskew'] = grhttp_df['dataList'].apply(lambda x: rolling_score(x, calc_bowley_skewness))
grhttp_df['data_mad'] = grhttp_df['dataList'].apply(lambda x: rolling_score(x, calc_median_absolute_deviation))
# grhttp_df['data_acf'] = grhttp_df['dataList'].apply(lambda x: rolling_score(x, calc_autocorrelation_v2))

# %%
# merge grhttp_df to final_http

# get max of mean(time_bskew, time_mad) and time_acf
grhttp_df['time_score'] = grhttp_df[['time_bskew', 'time_mad']].mean(axis=1)
grhttp_df['time_score'] = grhttp_df[['time_score', 'time_acf']].max(axis=1)
# get mean of data_bskew and data_mad
grhttp_df['data_score'] = grhttp_df[['data_bskew', 'data_mad']].mean(axis=1)
# final score is mean of time_score and data_score
grhttp_df['http_score'] = (grhttp_df['time_score'] + grhttp_df['data_score']) / 2
# if null_user_agent == 1, increase http_score by 20% as a bonus, but not exceed 1.0
grhttp_df['http_score'] = np.where(grhttp_df['null_user_agent'] == 1, grhttp_df['http_score'] * 1.2, grhttp_df['http_score'])
grhttp_df['http_score'] = grhttp_df['http_score'].clip(upper=1.0)

final_http = grhttp_df.explode('dstIPList', ignore_index=True)
final_http = final_http.rename(columns={'dstIPList': 'dstIP'})
# final_http.set_index(['srcIP', 'dstIP'], inplace=True)
final_http = final_http[['srcIP', 'dstIP', 'http_score', 'null_user_agent']]

# %% [markdown]
# # dns.log

# %%
# remove logs with nan query
dns_df = dns_df[~pd.isna(dns_df['query'])]

# %%
dns_df.loc[:, 'domain'] = dns_df['query'].apply(lambda x: extract_domain(x))

def extract_subdomain(fqdn):
    if pd.isna(fqdn): return ''
    parts = fqdn.lower().split('.')
    return '.'.join(parts[:-2]) if len(parts) > 2 else ''

# group by srcIP, domain
rows = []
dns_df = dns_df.sort_values(by=['ts'])
dns_grouped = dns_df.groupby(['id.orig_h', 'domain'])
for name, group in dns_grouped:
    rows.append({
        'srcIP': name[0],
        'domain': name[1],
        'timeList': group["ts"].tolist(),
        'subdmList': group['query'].apply(lambda x: extract_subdomain(x)).tolist(),
        '%TXT/CNAME': sum(group['qtype_name'].isin(['TXT', 'CNAME'])),
        '%NXDOMAIN': sum(group['rcode_name'] == 'NXDOMAIN'),
    })

grdns_df = pd.DataFrame(rows)
grdns_df['%TXT/CNAME'] = grdns_df['%TXT/CNAME'] / grdns_df['timeList'].apply(len)
grdns_df['%NXDOMAIN'] = grdns_df['%NXDOMAIN'] / grdns_df['timeList'].apply(len)
grdns_df['%unique_subdm'] = grdns_df['subdmList'].apply(lambda x: len(set(x))) / grdns_df['timeList'].apply(len)
grdns_df['dm_avg_len'] = grdns_df['subdmList'].apply(lambda x: np.mean([len(s) for s in x]) if len(x) > 0 else 0) + grdns_df['domain'].apply(lambda x: len(x))

# %%
# Calc features
grdns_df['time_bskew'] = grdns_df['timeList'].apply(lambda x: rolling_score(ts_to_interval(x), calc_bowley_skewness))
grdns_df['time_mad'] = grdns_df['timeList'].apply(lambda x: rolling_score(ts_to_interval(x), calc_median_absolute_deviation))
grdns_df['time_acf'] = grdns_df['timeList'].apply(lambda x: rolling_score(ts_to_interval(x), calc_autocorrelation_v2))

# %%
grdns_df['high_TXT/CNAME_ratio'] = np.where(grdns_df['%TXT/CNAME'] > 0.5, 1, 0)
grdns_df['high_NXDOMAIN_ratio'] = np.where(grdns_df['%NXDOMAIN'] > 0.5, 1, 0)
grdns_df['high_unique_subdm_ratio'] = np.where(grdns_df['%unique_subdm'] > 0.5, 1, 0)
grdns_df['long_dm_avg_len'] = np.where(grdns_df['dm_avg_len'] > 40, 1, 0)

grdns_df['dns_score'] = grdns_df[['time_bskew', 'time_mad']].mean(axis=1)
grdns_df['dns_score'] = grdns_df[['dns_score', 'time_acf']].max(axis=1)
# if %TXT/CNAME > 0.5 and number of query > 10, increase dns_score by 10% as a bonus, but not exceed 1.0
grdns_df['dns_score'] = np.where(grdns_df['high_TXT/CNAME_ratio'] == 1, grdns_df['dns_score'] * 1.1, grdns_df['dns_score'])
grdns_df['dns_score'] = np.where(grdns_df['high_NXDOMAIN_ratio'] == 1, grdns_df['dns_score'] * 1.1, grdns_df['dns_score'])
grdns_df['dns_score'] = np.where(grdns_df['high_unique_subdm_ratio'] == 1, grdns_df['dns_score'] * 1.1, grdns_df['dns_score'])
grdns_df['dns_score'] = np.where(grdns_df['long_dm_avg_len'] == 1, grdns_df['dns_score'] * 1.1, grdns_df['dns_score'])
grdns_df['dns_score'] = grdns_df['dns_score'].clip(upper=1.0)

final_dns = grdns_df.explode('domain', ignore_index=True)
final_dns = final_dns.rename(columns={'domain': 'dstIP'})
# final_dns.set_index(['srcIP', 'dstIP'], inplace=True)
final_dns = final_dns[['srcIP', 'dstIP', 'dns_score', 'high_TXT/CNAME_ratio', 'high_NXDOMAIN_ratio', 'high_unique_subdm_ratio', 'long_dm_avg_len']]

# %%
def merge_with_reason(base_df, new_df, score_col, reason_map):
    """
    Hợp nhất DataFrame phát hiện beacon theo IP pair.
    - Giữ lại duy nhất một score_col.
    - Gộp reason nếu nhiều điều kiện match.
    """
    # Nếu base_df đã có score_col thì xóa (tránh sinh _x/_y)
    if score_col in base_df.columns:
        base_df = base_df.drop(columns=[score_col])

    # Merge theo IP pair
    merged = base_df.merge(
        new_df[['srcIP', 'dstIP', score_col] + list(reason_map.keys())],
        on=['srcIP', 'dstIP'],
        how='outer'
    )

    # Bổ sung cột reason nếu thiếu
    merged['reason'] = merged['reason'].fillna('')

    # Thêm mô tả vào reason nếu flag = 1
    for col, msg in reason_map.items():
        merged.loc[merged[col] == 1, 'reason'] = (
            merged['reason'].astype(str).str.strip() +
            np.where(merged['reason'].astype(bool), '; ', '') +
            msg
        )

    # Xóa cột flag sau khi xử lý
    merged = merged.drop(columns=reason_map.keys())

    return merged

final_df = pd.DataFrame(columns=['srcIP', 'dstIP', 'conn_score', 'ssl_score', 'http_score', 'dns_score', 'reason'])

# 1️⃣ Connection
final_df = merge_with_reason(
    final_df, final_con,
    score_col='conn_score',
    reason_map={
        'rare_port': 'Rare port used',
        'ip_ioc': 'IP in IOC list'
    }
)

# 2️⃣ SSL
final_df = merge_with_reason(
    final_df, final_ssl,
    score_col='ssl_score',
    reason_map={
        'ja3_ioc': 'JA3 in IOC list',
        'sni_not_matched_cert': 'SNI not matched with certificate'
    }
)

# 3️⃣ HTTP
final_df = merge_with_reason(
    final_df, final_http,
    score_col='http_score',
    reason_map={
        'null_user_agent': 'Null User-Agent'
    }
)

# 4️⃣ DNS
final_df = merge_with_reason(
    final_df, final_dns,
    score_col='dns_score',
    reason_map={
        'high_TXT/CNAME_ratio': 'High TXT/CNAME ratio',
        'high_NXDOMAIN_ratio': 'High NXDOMAIN ratio',
        'high_unique_subdm_ratio': 'High unique subdomain ratio',
        'long_dm_avg_len': 'Long domain average length'
    }
)

final_df.set_index(['srcIP', 'dstIP'], inplace=True)

# final_df.loc[('192.168.28.129', '192.168.20.100')]

# %%
# final_con[final_con['dstIP'] == '192.168.20.100']

print(final_df)