#!/usr/bin/env python
# coding: utf-8

# In[2]:


from elasticsearch import Elasticsearch
from elasticsearch.dsl import Search
import pandas as pd
import numpy as np
import urllib3
from datetime import datetime, timedelta
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from pprint import pprint
import json


# In[3]:


# Thiết lập kết nối đến Elasticsearch
# conn = Elasticsearch(
#     ['https://192.168.145.101:9200'], 
#     ca_certs=False, 
#     verify_certs=False,
#     basic_auth=('jupyter', 'jupyter@seconi.com'),
# )

# print(conn.info())


# In[ ]:


# print(conn.indices.get_data_stream(name="logs-zeek*"))


# In[5]:


# zlog = Search(using=conn, index='logs-zeek-so')

# conn_log = zlog.query("term", **{"event.dataset": "zeek.conn"})
# http_log = zlog.query("term", **{"event.dataset": "zeek.http"})
# dns_log = zlog.query("term", **{"event.dataset": "zeek.dns"})
# ssl_log = zlog.query("term", **{"event.dataset": "zeek.ssl"})

# conn_12h = conn_log.filter('range', **{'@timestamp': {'gte': 'now-12h', 'lt': 'now'}})
# http_12h = http_log.filter('range', **{'@timestamp': {'gte': 'now-12h', 'lt': 'now'}})
# dns_12h = dns_log.filter('range', **{'@timestamp': {'gte': 'now-12h', 'lt': 'now'}})
# ssl_12h = ssl_log.filter('range', **{'@timestamp': {'gte': 'now-12h', 'lt': 'now'}})


# In[6]:


conn_df = pd.DataFrame()
# for hit in conn_12h.scan():
#     data = hit.to_dict()['message']
#     data = json.loads(data)
#     row = pd.DataFrame([data])
#     conn_df = pd.concat([conn_df, row], ignore_index=True)

http_df = pd.DataFrame()
# for hit in http_12h.scan():
#     data = hit.to_dict()['message']
#     data = json.loads(data)
#     row = pd.DataFrame([data])
#     http_df = pd.concat([http_df, row], ignore_index=True)

dns_df = pd.DataFrame()
# for hit in dns_12h.scan():
#     data = hit.to_dict()['message']
#     data = json.loads(data)
#     row = pd.DataFrame([data])
#     dns_df = pd.concat([dns_df, row], ignore_index=True)

ssl_df = pd.DataFrame()
# for hit in ssl_12h.scan():
#     data = hit.to_dict()['message']
#     data = json.loads(data)
#     row = pd.DataFrame([data])
#     ssl_df = pd.concat([ssl_df, row], ignore_index=True)


# In[ ]:


# hashmap = {}
# # --- CONN LOG ---
# conn_grouped = conn_df.groupby(['id.orig_h', 'id.resp_h'])
# conn_df_result = {}
# for name, group in conn_grouped:
#     h = hash(name)
#     conn_df_result[h] = {
#         "tsList": group["ts"].tolist(),
#         "byteList": group["orig_ip_bytes"].tolist()
#     }
#     hashmap[h] = name   # lưu lại tuple gốc

# # --- SSL LOG ---
# ssl_grouped = ssl_df.groupby(['id.orig_h', 'server_name'])
# ssl_result = {}
# for name, group in ssl_grouped:
#     h = hash(name)
#     ssl_result[h] = {
#         "tsList": group["ts"].tolist()
#     }
#     hashmap[h] = name

# # --- HTTP LOG ---
# http_grouped = http_df.groupby(['id.orig_h', 'host'])
# http_result = {}
# for name, group in http_grouped:
#     # get 
#     h = hash(name)
#     http_result[h] = {
#         "ts": group["ts"].tolist()
#     }
#     hashmap[h] = name

# # --- DNS LOG ---
# dns_grouped = dns_df.groupby(['id.orig_h', 'id.resp_h', 'query'])
# dns_result = {}
# for name, group in dns_grouped:
#     h = hash(name)
#     dns_result[h] = {
#         "ts": group["ts"].tolist()
#     }
#     hashmap[h] = name

# full_dict_log = conn_df_result | ssl_result | http_result | dns_result

# grouped_df = pd.DataFrame.from_dict(full_dict_log, orient='index')


# ==================== Ver2 ========================
conn_df = pd.read_csv('zeek_conn_12h.csv')
http_df = pd.read_csv('zeek_http_12h.csv')
dns_df = pd.read_csv('zeek_dns_12h.csv')
ssl_df = pd.read_csv('zeek_ssl_12h.csv')
import pandas as pd

def aggregate_with_log_source(conn_df: pd.DataFrame, http_df: pd.DataFrame, dns_df: pd.DataFrame, ssl_df: pd.DataFrame) -> (pd.DataFrame, dict):
    """
    Aggregate các log ứng dụng và làm giàu kết quả với byteList và log_source.

    Args:
        conn_df: DataFrame từ conn.log.
        http_df: DataFrame từ http.log.
        dns_df: DataFrame từ dns.log.
        ssl_df: DataFrame từ ssl.log.

    Returns:
        Một tuple chứa:
        - DataFrame tổng hợp đã được làm giàu.
        - Hashmap để tra cứu ngược từ hash ra key gốc.
    """
    
    # --- Bước 1: Tạo map để tra cứu nhanh từ uid -> orig_ip_bytes ---
    uid_to_bytes_map = conn_df[['uid', 'orig_ip_bytes']].drop_duplicates('uid').set_index('uid')['orig_ip_bytes']
    full_dict_log = {}
    hashmap = {}

    # --- SSL LOG ---
    ssl_grouped = ssl_df.groupby(['id.orig_h', 'server_name'])
    for name, group in ssl_grouped:
        h = hash(name)
        # Dùng .map() để đảm bảo thứ tự
        byte_list = group['uid'].map(uid_to_bytes_map).tolist()
        full_dict_log[h] = {
            "log_source": "ssl",
            "tsList": group["ts"].tolist(),
            "byteList": byte_list
        }
        hashmap[h] = name

    # --- HTTP LOG ---
    http_grouped = http_df.groupby(['id.orig_h', 'host'])
    for name, group in http_grouped:
        h = hash(name)
        # Dùng .map() để đảm bảo thứ tự
        byte_list = group['uid'].map(uid_to_bytes_map).tolist()
        full_dict_log[h] = {
            "log_source": "http",
            "tsList": group["ts"].tolist(),
            "byteList": byte_list
        }
        hashmap[h] = name
        
    # --- DNS LOG ---
    dns_grouped = dns_df.groupby(['id.orig_h', 'id.resp_h', 'query'])
    for name, group in dns_grouped:
        h = hash(name)
        # Dùng .map() để đảm bảo thứ tự
        byte_list = group['uid'].map(uid_to_bytes_map).tolist()
        full_dict_log[h] = {
            "log_source": "dns",
            "tsList": group["ts"].tolist(),
            "byteList": byte_list
        }
        hashmap[h] = name

    final_df = pd.DataFrame.from_dict(full_dict_log, orient='index')
    if not final_df.empty:
        final_df = final_df[['log_source', 'tsList', 'byteList']]
    
    return final_df, hashmap

# --- CÁCH SỬ DỤNG ---

# Gọi hàm
final_df, hashmap = aggregate_with_log_source(conn_df, http_df, dns_df, ssl_df)

# In kết quả
# print("--- Final DataFrame (with log_source only) ---")
# print(final_df)

# Tra cứu ngược vẫn hữu ích
if not final_df.empty:
    second_hash_key = final_df.index[1]
    original_key = hashmap[second_hash_key]
    print(f"\n--- Reverse Lookup Example ---")
    print(f"Hash '{second_hash_key}' corresponds to the original key: {original_key}")

def test_aggregation_correctness(
    final_df: pd.DataFrame, 
    hashmap: dict,
    conn_df: pd.DataFrame, 
    http_df: pd.DataFrame, 
    dns_df: pd.DataFrame, 
    ssl_df: pd.DataFrame
):
    """
    Kiểm tra xem final_df có được tổng hợp chính xác từ các log gốc không.
    - Kiểm tra sự toàn vẹn về số lượng (length).
    - Kiểm tra sự tương ứng và chính xác của tsList và byteList.
    """
    print("--- Bắt đầu kiểm tra tính đúng đắn của dữ liệu ---")
    
    # Cấu hình để dễ dàng truy cập vào DataFrame và các cột gốc
    source_map = {
        "http": http_df,
        "dns": dns_df,
        "ssl": ssl_df
    }
    group_cols_map = {
        "http": ['id.orig_h', 'host'],
        "dns": ['id.orig_h', 'id.resp_h', 'query'],
        "ssl": ['id.orig_h', 'server_name']
    }
    
    # Tạo lại uid_to_bytes_map làm "nguồn chân lý" (source of truth)
    uid_to_bytes_map = conn_df[['uid', 'orig_ip_bytes']].drop_duplicates('uid').set_index('uid')['orig_ip_bytes']

    passed_tests = 0
    failed_tests = 0

    # Lặp qua từng dòng trong kết quả cuối cùng để kiểm tra
    for h, row in final_df.iterrows():
        test_name = f"Hash {h}"
        try:
            # 1. Lấy thông tin từ kết quả
            log_source = row['log_source']
            ts_list_result = row['tsList']
            byte_list_result = row['byteList']
            
            # 2. Tìm lại group gốc trong DataFrame nguồn
            original_key = hashmap[h]
            source_df = source_map[log_source]
            group_cols = group_cols_map[log_source]
            
            # Dùng query để lọc ra chính xác group gốc
            query_str = ' & '.join([f'`{col}` == {repr(val)}' for col, val in zip(group_cols, original_key)])
            original_group = source_df.query(query_str)

            # 3. THỰC HIỆN CÁC BƯỚC KIỂM TRA
            
            # Test A: Kiểm tra số lượng bản ghi có khớp không
            assert len(ts_list_result) == len(original_group), f"Số lượng timestamp không khớp ({len(ts_list_result)} vs {len(original_group)})"
            assert len(byte_list_result) == len(original_group), f"Số lượng byte không khớp ({len(byte_list_result)} vs {len(original_group)})"

            # Test B: Kiểm tra danh sách timestamp có khớp không (sắp xếp để chắc chắn)
            ts_list_original = original_group['ts'].tolist()
            assert sorted(ts_list_result) == sorted(ts_list_original), "Danh sách timestamp không khớp"
            
            # Test C: Tạo ra byte_list "chuẩn" từ group gốc và so sánh
            # Đây là bài test quan trọng nhất, xác minh logic của hàm .map()
            expected_byte_list = original_group['uid'].map(uid_to_bytes_map).tolist()
            assert byte_list_result == expected_byte_list, "Giá trị hoặc thứ tự của byteList không chính xác"

            print(f"✅ Test PASSED for {test_name} (Source: {log_source}, Key: {original_key})")
            passed_tests += 1

        except AssertionError as e:
            print(f"❌ Test FAILED for {test_name} (Source: {log_source}, Key: {original_key})")
            print(f"   Lỗi: {e}")
            failed_tests += 1
        except Exception as e:
            print(f"💥 An unexpected error occurred during test for {test_name}: {e}")
            failed_tests += 1
            
    print("\n--- Tổng kết kiểm tra ---")
    print(f"👍 Số test thành công: {passed_tests}")
    print(f"👎 Số test thất bại: {failed_tests}")
    if failed_tests == 0:
        print("\n🎉 Tuyệt vời! Tất cả dữ liệu đều chính xác.")
    else:
        print("\n⚠️ Có lỗi xảy ra, vui lòng kiểm tra lại logic xử lý.")

    return failed_tests == 0

# --- CÁCH SỬ DỤNG ---
# Giả sử bạn đã chạy hàm `aggregate_with_log_source_corrected` và có `final_df`, `hashmap`
# từ các câu trả lời trước.

# final_df, hashmap = aggregate_with_log_source_corrected(conn_df, http_df, dns_df, ssl_df)

# Chạy hàm test
is_correct = test_aggregation_correctness(final_df, hashmap, conn_df, http_df, dns_df, ssl_df)
# ====================== END =======================

# In[8]:


# grouped_df


# In[9]:


# muc do phan bo doi xung quanh trung vi
def calc_bowley_skewness(data):
    if len(data) < 3:
        return 0.0

    q1, q2, q3 = np.percentile(data, [25, 50, 75])

    if (q3 - q1) == 0:
        return 0.0

    bowley_skewness = (q3 + q1 - 2 * q2) / (q3 - q1)
    score = abs(bowley_skewness)
    return score


# In[10]:


# muc do phan tan xung quanh trung vi
def calc_median_absolute_deviation(data):
    if len(data) == 0:
        return 0.0

    mad = np.median(np.abs(data - np.median(data)))
    score = mad
    return score


# In[ ]:


# muc do tuong quan giua cac chu ki
def calc_auto_correlation(data, lag=1):
    if len(data) < lag + 1:
        return 0.0

    n = len(data)
    mean = np.mean(data)
    c_lag = np.sum((data[:n - lag] - mean) * (data[lag:] - mean))
    c0 = np.sum((data - mean) ** 2)

    if c0 == 0:
        return 0.0

    autocorr = c_lag / c0
    score = abs(autocorr)
    return score


# In[12]:


def ts_to_interval(ts_list):
    if len(ts_list) < 2:
        return []

    ts_list_sorted = sorted(ts_list)
    intervals = [(ts_list_sorted[i] - ts_list_sorted[i - 1]) for i in range(1, len(ts_list_sorted))]
    return intervals


# In[ ]:


# calc interval score


# In[ ]:


def calc_timestamp_score(tsList):
    if(type(tsList) is float):
        return 0.0
    if len(tsList) < 2:
        return 0.0

    intervals = ts_to_interval(tsList)
    bowley_skewness = calc_bowley_skewness(intervals)
    mad = calc_median_absolute_deviation(intervals)
    # autocorr = calc_auto_correlation(intervals, lag=1)

    score = (bowley_skewness + mad) / 2
    return score


# In[ ]:


def calc_data_size_score(byteList):
    if(type(byteList) is float):
        return 0.0

    if len(byteList) < 2:
        return 0.0

    bowley_skewness = calc_bowley_skewness(byteList)
    mad = calc_median_absolute_deviation(byteList)
    # autocorr = calc_auto_correlation(byteList, lag=1)

    score = (bowley_skewness + mad) / 2
    return score


# In[14]:

# grouped_df['tsScore'] = grouped_df['tsList'].apply(lambda x: calc_timestamp_score(x))
# grouped_df['dsScore'] = grouped_df['byteList'].apply(lambda x: calc_data_size_score(x))

# grouped_df



#  ================================== new ==================================
HistogramModeSensitivity = 0.05
HistogramBimodalOutlierRemoval = 1
HistogramBimodalMinHoursSeen = 11

def get_frequency_counts(
    connection_histogram: List[int], 
    mode_sensitivity: float
) -> Tuple[Dict[int, int], int, int]:
    """
    Phân tích một biểu đồ tần suất để lấy các thông số tổng hợp.

    Hàm này được tái tạo lại dựa trên các giá trị trả về của hàm cùng tên trong code Go.

    Args:
        connection_histogram: Danh sách tần suất (kết quả của histogram).
        mode_sensitivity: (Chưa sử dụng trong phiên bản này) Ngưỡng độ nhạy. 
                          Có thể dùng để lọc các bin có giá trị thấp.

    Returns:
        Một tuple chứa:
        - freq_count: Một dictionary đếm số lần xuất hiện của mỗi mức tần suất.
        - total_bars: Tổng số "ngăn" (bin) có hoạt động (tần suất > 0).
        - longest_run: Chuỗi dài nhất các "ngăn" có hoạt động liên tiếp.
    """
    # Lọc ra các giá trị tần suất > 0 để tính toán
    active_counts = [count for count in connection_histogram if count > 0]
    
    # 1. freq_count: Đếm số lần xuất hiện của mỗi mức tần suất.
    # Ví dụ: [2, 0, 2, 5, 2] -> active_counts là [2, 2, 5, 2] -> freq_count là {2: 3, 5: 1}
    freq_count = Counter(active_counts)

    # 2. total_bars: Tổng số ngăn có giá trị > 0.
    total_bars = len(active_counts)

    # 3. longest_run: Tìm chuỗi dài nhất các ngăn có giá trị > 0 liên tiếp.
    longest_run = 0
    current_run = 0
    for count in connection_histogram:
        # Trong phiên bản này, ta coi mọi hoạt động > 0 là hợp lệ.
        # có thể thay đổi điều kiện thành `count > mode_sensitivity` nếu cần.
        if count > 0:
            current_run += 1
        else:
            longest_run = max(longest_run, current_run)
            current_run = 0
    # Cập nhật lần cuối để xử lý trường hợp chuỗi kết thúc ở cuối danh sách
    longest_run = max(longest_run, current_run)

    return freq_count, total_bars, longest_run

def create_histogram(
    bin_edges: List[float], 
    timestamps: List[int], 
    mode_sensitivity: float = 0.0
) -> Tuple[List[int], Dict[int, int], int, int]:
    """
    Tạo biểu đồ tần suất bằng cách đếm số lượng timestamp rơi vào mỗi "ngăn" (bin).

    Args:
        bin_edges: Danh sách các cạnh của ngăn. Ví dụ: [0, 10, 20, 30].
        timestamps: Danh sách các timestamp cần phân loại.
        mode_sensitivity: Ngưỡng độ nhạy để chuyển cho hàm phân tích con.

    Returns:
        Một tuple chứa:
        - connection_histogram: Biểu đồ tần suất.
        - freq_count: Map đếm tần suất.
        - total_bars: Tổng số ngăn có hoạt động.
        - longest_run: Chuỗi hoạt động dài nhất.
        
    Raises:
        ValueError: Nếu đầu vào không hợp lệ.
    """
    # --- Bước 1: Kiểm tra đầu vào ---
    if len(bin_edges) < 2:
        raise ValueError("bin_edges phải chứa ít nhất 2 phần tử.")
    if not timestamps:
        raise ValueError("timestamps không được rỗng.")

    # --- Bước 2: Tạo histogram ---
    # Thay vì dùng vòng lặp thủ công như Go, ta dùng numpy.histogram.
    # Hàm này cực kỳ hiệu quả, nhanh và là tiêu chuẩn trong Python.
    # Nó tự động xử lý việc sắp xếp và phân loại vào các ngăn.
    connection_histogram_np, _ = np.histogram(timestamps, bins=bin_edges)
    
    # Chuyển đổi kết quả từ mảng numpy về list int tiêu chuẩn của Python
    connection_histogram = [int(count) for count in connection_histogram_np]
    
    # --- Bước 3: Lấy các thông số tổng hợp ---
    # Gọi hàm trợ giúp, tương tự như cấu trúc của code Go
    freq_count, total_bars, longest_run = get_frequency_counts(
        connection_histogram, mode_sensitivity
    )

    return connection_histogram, freq_count, total_bars, longest_run

def compute_histogram_bins(start_time: int, end_time: int, num_bins: int) -> List[float]:
    """
    Tạo ra các "cạnh ngăn" (bin edges) được chia đều cho một biểu đồ histogram.

    Hàm này nhận vào một khoảng thời gian và số lượng ngăn mong muốn, sau đó trả về
    một danh sách các điểm thời gian (dưới dạng float) chia đều khoảng thời gian đó.

    Args:
        start_time: Timestamp bắt đầu (dưới dạng Unix timestamp, kiểu int).
        end_time: Timestamp kết thúc (dưới dạng Unix timestamp, kiểu int).
        num_bins: Số lượng "ngăn" (bin) mong muốn.

    Returns:
        Một danh sách gồm `num_bins + 1` cạnh ngăn (dưới dạng float).

    Raises:
        ValueError: Nếu các tham số đầu vào không hợp lệ.
    """
    # --- Bước 1: Kiểm tra đầu vào ---
    if num_bins <= 0:
        raise ValueError("Số lượng ngăn (num_bins) phải lớn hơn 0.")
    
    if end_time <= start_time:
        raise ValueError("Khoảng thời gian không hợp lệ: end_time phải lớn hơn start_time.")

    # --- Bước 2: Tính toán các cạnh ngăn bằng NumPy ---
    # Hàm numpy.linspace là công cụ hoàn hảo cho việc này.
    # Nó tạo ra một chuỗi các số được chia đều trong một khoảng cho trước.
    # Để có N ngăn, chúng ta cần N + 1 cạnh.
    edge_count = num_bins + 1
    
    # np.linspace(start, stop, num) sẽ tạo ra `num` điểm từ `start` đến `stop`.
    bin_edges_np = np.linspace(start_time, end_time, num=edge_count)
    
    # Chuyển đổi từ mảng numpy sang list float tiêu chuẩn của Python để giống với
    # kiểu trả về `[]float64` của Go.
    bin_edges = bin_edges_np.tolist()

    return bin_edges


def get_histogram_score(dataset, datasetMax, tsList, modeSensitivity, bimodalOutlierRemoval,bimodalMinHoursSeen,beaconTimeSpan):
    binEdges = compute_histogram_bins(datasetMin, datasetMax, beaconTimeSpan) # TODO
    freqList, freqCount, totalBars, longestRun = create_histogram(binEdges, tsList, modeSensitivity) 
    svscore = calculate_coefficient_of_variation_score_final(freqList)
    # bitmodel
    bitmodalFitScore = calculate_bimodal_fit_score(freqCount, totalBars, longestRun, bimodalOutlierRemoval, bimodalMinHoursSeen)
    score = math.Max(cvScore, bimodalFitScore)
    return score


def GetBeaconMinMaxTimestamps():
    # lấy timestamp max trong data
    # lấy timestamp max - 24h
    # if timestamp max - timestamp min < 24h thì lấy timestamp min
    # ngược lại thì lấy timestamp max - 24h
    return minTS, maxTS

minTSBeacon, maxTSBeacon = GetBeaconMinMaxTimestamps()

get_histogram_score(
    minTSBeacon,
    maxTSBeacon,
    TSList,
    HistogramModeSensitivity, # 0.05
    HistogramBimodalOutlierRemoval, # 1
    HistogramBimodalMinHoursSeen, # 11
    24 # 24 hours span for beacon detection
)
# ================================== end ==================================