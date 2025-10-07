# %%
from elasticsearch import Elasticsearch
from elasticsearch.dsl import Search
import pandas as pd
import numpy as np
import urllib3
from datetime import datetime, timedelta
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from pprint import pprint
import json

# %%
# Thiết lập kết nối đến Elasticsearch
conn = Elasticsearch(
    ['https://192.168.145.101:9200'], 
    ca_certs=False, 
    verify_certs=False,
    basic_auth=('jupyter', 'jupyter@seconi.com'),
)

print(conn.info())

# %%
# print(conn.indices.get_data_stream(name="logs-zeek*"))

# %%
zlog = Search(using=conn, index='logs-zeek-so')

conn_log = zlog.query("term", **{"event.dataset": "zeek.conn"})
http_log = zlog.query("term", **{"event.dataset": "zeek.http"})
dns_log = zlog.query("term", **{"event.dataset": "zeek.dns"})
ssl_log = zlog.query("term", **{"event.dataset": "zeek.ssl"})

conn_12h = conn_log.filter('range', **{'@timestamp': {'gte': 'now-12h', 'lt': 'now'}})
http_12h = http_log.filter('range', **{'@timestamp': {'gte': 'now-12h', 'lt': 'now'}})
dns_12h = dns_log.filter('range', **{'@timestamp': {'gte': 'now-12h', 'lt': 'now'}})
ssl_12h = ssl_log.filter('range', **{'@timestamp': {'gte': 'now-12h', 'lt': 'now'}})

conn_df = pd.DataFrame()
for hit in conn_12h.scan():
    data = hit.to_dict()['message']
    data = json.loads(data)
    row = pd.DataFrame([data])
    conn_df = pd.concat([conn_df, row], ignore_index=True)

http_df = pd.DataFrame()
for hit in http_12h.scan():
    data = hit.to_dict()['message']
    data = json.loads(data)
    row = pd.DataFrame([data])
    http_df = pd.concat([http_df, row], ignore_index=True)

dns_df = pd.DataFrame()
for hit in dns_12h.scan():
    data = hit.to_dict()['message']
    data = json.loads(data)
    row = pd.DataFrame([data])
    dns_df = pd.concat([dns_df, row], ignore_index=True)

ssl_df = pd.DataFrame()
for hit in ssl_12h.scan():
    data = hit.to_dict()['message']
    data = json.loads(data)
    row = pd.DataFrame([data])
    ssl_df = pd.concat([ssl_df, row], ignore_index=True)

# %%
# write dataframe to csv file
conn_df.to_csv('zeek_conn_12h.csv', index=False)
http_df.to_csv('zeek_http_12h.csv', index=False)
dns_df.to_csv('zeek_dns_12h.csv', index=False)
ssl_df.to_csv('zeek_ssl_12h.csv', index=False)

# %% [markdown]
# ### Start from here if not running SecOni

# %%
# read csv file to dataframe
conn_df = pd.read_csv('zeek_conn_12h.csv')
http_df = pd.read_csv('zeek_http_12h.csv')
dns_df = pd.read_csv('zeek_dns_12h.csv')
ssl_df = pd.read_csv('zeek_ssl_12h.csv')

# %%
conn_df.head(2)

# %%
http_df.head(2)

# %%
dns_df.head(2)

# %%
ssl_df.head(2)

# %%
conn_df

# %%
# convert ts to datetime
conn_df['ts'] = pd.to_datetime(conn_df['ts'], unit='s')

# %%
conn_df

# %%
uid_to_bytes_map = conn_df[['uid', 'orig_ip_bytes']].drop_duplicates('uid').set_index('uid')['orig_ip_bytes']
final_df = pd.DataFrame()
rows = []

# --- SSL LOG ---
ssl_df['hash'] = ssl_df.apply(lambda row: hash((row['id.orig_h'], row['server_name'])), axis=1)
ssl_grouped = ssl_df.groupby('hash')
for name, group in ssl_grouped:
    rows.append({
        'hash': name,
        'log': 'ssl',
        'tsList': group["ts"].tolist(),
        'dsList': group['uid'].map(uid_to_bytes_map).tolist()
    })

# --- HTTP LOG ---
http_df['hash'] = http_df.apply(lambda row: hash((row['id.orig_h'], row['host'], row['uri'])), axis=1)
http_grouped = http_df.groupby('hash')
for name, group in http_grouped:
    rows.append({
        'hash': name,
        'log': 'http',
        'tsList': group["ts"].tolist(),
        'dsList': group['uid'].map(uid_to_bytes_map).tolist()
    })
    
# --- DNS LOG ---
dns_df['hash'] = dns_df.apply(lambda row: hash((row['id.orig_h'], row['id.resp_h'], row['query'])), axis=1)
dns_grouped = dns_df.groupby('hash')
for name, group in dns_grouped:
    rows.append({
        'hash': name,
        'log': 'dns',
        'tsList': group["ts"].tolist(),
        'dsList': group['uid'].map(uid_to_bytes_map).tolist()
    })

final_df = pd.DataFrame(rows).set_index('hash')


# %%
final_df

# %%
# # muc do tuong quan giua cac chu ki
# def calc_auto_correlation(data, lag=1):
#     if len(data) < lag + 1:
#         return 0.0

#     n = len(data)
#     mean = np.mean(data)
#     c_lag = np.sum((data[:n - lag] - mean) * (data[lag:] - mean))
#     c0 = np.sum((data - mean) ** 2)

#     if c0 == 0:
#         return 0.0

#     autocorr = c_lag / c0
#     score = abs(autocorr)
#     return score

# %%
# Mức độ lặp lại của chu kỳ tín hiệu

def calc_autocorrelation(data, resolution=1.0):
    """
    Phân tích một danh sách timestamp bằng phương pháp tự tương quan (autocorrelation)
    để xác định mức độ lặp lại của tín hiệu (khả năng là beaconing).

    Args:
        data (list or np.array): Danh sách các timestamp (dưới dạng Unix timestamp hoặc tương tự).
        resolution (float): Độ phân giải thời gian (tính bằng giây) để tạo chuỗi tín hiệu. 
                             Mặc định là 1 giây.

    Returns:
        float: Một điểm số từ 0.0 đến 1.0 đại diện cho mức độ tương đồng. 
               Giá trị càng gần 1, tín hiệu càng có tính chu kỳ mạnh.
    """
    # 1. Kiểm tra đầu vào
    if len(data) < 10:  # Cần đủ dữ liệu để phân tích có ý nghĩa
        return 0.0

    data = np.array(sorted(data))
    duration = data[-1] - data[0]
    
    if duration <= 0:
        return 0.0

    # 2. Chuyển đổi data thành một chuỗi tín hiệu nhị phân (0 và 1)
    # Kích thước của chuỗi tín hiệu sẽ là tổng thời gian chia cho độ phân giải
    num_bins = int(np.ceil(duration / resolution))
    signal = np.zeros(num_bins)
    
    # "bin" các timestamp vào đúng vị trí trong chuỗi tín hiệu
    indices = ((data - data[0]) / resolution).astype(int)
    # Đảm bảo index không vượt quá giới hạn
    indices = np.minimum(indices, num_bins - 1)
    signal[indices] = 1

    # 3. Tính toán tự tương quan (Autocorrelation)
    # mode='full' sẽ trả về kết quả tương quan ở mọi điểm chồng chéo
    autocorr = np.correlate(signal, signal, mode='full')
    
    # Chúng ta chỉ quan tâm đến nửa sau của kết quả (các độ trễ dương)
    autocorr = autocorr[len(autocorr) // 2:]

    # 4. Tính toán điểm số
    # Đỉnh đầu tiên (tại lag=0) luôn là lớn nhất, tương ứng với năng lượng của tín hiệu.
    # Chúng ta tìm đỉnh cao thứ hai, đại diện cho chu kỳ lặp lại mạnh nhất.
    
    # Bỏ qua đỉnh ở lag=0
    if len(autocorr) < 2:
        return 0.0
        
    peak_at_zero = autocorr[0]
    
    if peak_at_zero == 0:
        return 0.0

    # Tìm đỉnh cao nhất trong phần còn lại của chuỗi
    second_highest_peak = np.max(autocorr[1:]) if len(autocorr) > 1 else 0

    # Điểm số là tỷ lệ giữa đỉnh chu kỳ và đỉnh năng lượng.
    # Tỷ lệ này cho biết mức độ mạnh mẽ của thành phần lặp lại so với toàn bộ tín hiệu.
    score = second_highest_peak / peak_at_zero
    
    return score

# %%
def ts_to_interval(ts_list):
    if len(ts_list) < 2:
        return []

    ts_list_sorted = sorted(ts_list)
    intervals = [(ts_list_sorted[i] - ts_list_sorted[i - 1]) for i in range(1, len(ts_list_sorted))]
    return intervals

# muc do dong deu cua du lieu
def calc_bowley_skewness(data):
    if len(data) < 10:
        return 0.0
    
    q1, q2, q3 = np.percentile(data, [25, 50, 75])

    if (q3 - q1) == 0:
        return 0.0
    
    bowley_skewness = (q3 + q1 - 2 * q2) / (q3 - q1)

    score = 1 - abs(bowley_skewness) # 1 is symmetric
    return score

# muc do phan tan so voi trung vi
def calc_median_absolute_deviation(data):
    if len(data) < 10:
        return 0.0

    mad = np.median(np.abs(data - np.median(data)))
    cv_mad = mad / np.median(data) if np.median(data) != 0 else 0

    score = 1.0 / (1.0 + cv_mad) # 1 is consistent
    return score

# %%
test_df = final_df.copy()
test_df['bowley_skewness'] = test_df['tsList'].apply(lambda x: calc_bowley_skewness(ts_to_interval(x)))
test_df['mad'] = test_df['tsList'].apply(lambda x: calc_median_absolute_deviation(ts_to_interval(x)))
test_df['auto_corr'] = test_df['tsList'].apply(lambda x: calc_autocorrelation(ts_to_interval(x)))
# Remove rows where bowley_skewness, mad, and auto_corr are all zero
test_df = test_df[~((test_df['bowley_skewness'] == 0) & (test_df['mad'] == 0) & (test_df['auto_corr'] == 0))]
test_df.sort_values(by=['auto_corr', 'bowley_skewness', 'mad'], ascending=False, inplace=True)

# %%
test_df

# %%
test2_df = final_df.copy()
test2_df['bowley_skewness'] = test2_df['dsList'].apply(lambda x: calc_bowley_skewness(x))
test2_df['mad'] = test2_df['dsList'].apply(lambda x: calc_median_absolute_deviation(x))
test2_df = test2_df[~((test2_df['bowley_skewness'] == 0) & (test2_df['mad'] == 0))]
test2_df.sort_values(by=['bowley_skewness', 'mad'], ascending=False, inplace=True)

# %%
test2_df

# %%
def calc_timestamp_score(tsList):
    intervals = ts_to_interval(tsList)
    bowley_skewness = calc_bowley_skewness(intervals)
    mad = calc_median_absolute_deviation(intervals)
    autocorr = calc_autocorrelation(intervals, resolution=1.0)

    score = (bowley_skewness + mad + autocorr) / 3
    return score

def calc_data_size_score(byteList):
    if len(byteList) < 2:
        return 0.0

    bowley_skewness = calc_bowley_skewness(byteList)
    mad = calc_median_absolute_deviation(byteList)

    score = (bowley_skewness + mad) / 2
    return score

# %%
grouped_df = final_df.copy()
grouped_df['tsScore'] = grouped_df['tsList'].apply(lambda x: calc_timestamp_score(x) )
grouped_df['dsScore'] = grouped_df['dsList'].apply(lambda x: calc_data_size_score(x))

# %%
grouped_df.sort_values(by=['tsScore', 'dsScore'], ascending=False)

# %%
ssl_df[ssl_df['hash'] == 7414369741906610589]

# %%
grouped_df[(grouped_df['srcIP']=='10.0.0.2') & (grouped_df['dstIP']=='10.0.0.1')]


