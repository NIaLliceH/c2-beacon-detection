HistogramModeSensitivity = 0.05
HistogramBimodalOutlierRemoval = 1
HistogramBimodalMinHoursSeen = 11

import numpy as np
import math


from collections import Counter
import math
import heapq
from typing import List, Tuple, Dict

def _calculate_bimodal_fit_score_final(
    freq_count: dict, 
    total_bars: int, 
    modal_outlier_removal: int, 
    min_hours_for_bimodal_analysis: int
) -> float:
    """
    Hàm lõi tính toán điểm Bimodal Fit, mô phỏng chặt chẽ logic từ code Go.
    """
    # --- Bước 1: Kiểm tra đầu vào ---
    if not freq_count:
        raise ValueError("Lỗi: freq_count không được rỗng.")
    if total_bars <= 0:
        raise ValueError("Lỗi: total_bars phải lớn hơn 0.")

    # --- Bước 2: Áp dụng quy tắc nghiệp vụ cho số giờ tối thiểu ---
    # Logic này đảm bảo phân tích chỉ chạy trên các mẫu đủ lớn để có ý nghĩa,
    # tránh việc các mẫu hình quá nhỏ (2-3 giờ hoạt động) luôn có điểm cao.
    if min_hours_for_bimodal_analysis < 6:
        min_hours_for_bimodal_analysis = 11

    # --- Bước 3: Kiểm tra điều kiện để phân tích ---
    # Nếu tổng số giờ có hoạt động không đủ lớn, coi như không có mẫu hình bimodal.
    if total_bars < min_hours_for_bimodal_analysis:
        return 0.0

    # --- Bước 4: Tìm hai đỉnh (modes) có số lần xuất hiện lớn nhất ---
    # freq_count.values() là số lần xuất hiện của mỗi mức tần suất.
    # Ví dụ: {50: 8, 2: 12} -> values là [8, 12]
    all_mode_counts = list(freq_count.values())
    
    largest = 0
    second_largest = 0
    if len(all_mode_counts) >= 2:
        # heapq.nlargest là cách hiệu quả để lấy N phần tử lớn nhất
        largest, second_largest = heapq.nlargest(2, all_mode_counts)
    elif len(all_mode_counts) == 1:
        largest = all_mode_counts[0]
        second_largest = 0 # Không có đỉnh thứ hai

    # --- Bước 5: Tính toán điểm số với việc loại bỏ outliers ---
    # Cho phép "bỏ qua" một số giờ hoạt động bị nhiễu (outliers).
    # Điều này làm cho điểm số linh hoạt hơn với dữ liệu thực tế.
    adjusted_total_bars = max(total_bars - modal_outlier_removal, 1)

    # Điểm số là tỷ lệ các giờ thuộc về hai chế độ chính so với tổng số giờ (đã điều chỉnh)
    modal_fit = (largest + second_largest) / adjusted_total_bars
    
    # --- Bước 6: Định dạng và "kẹp" (clamp) điểm số cuối cùng ---
    score = round(modal_fit, 3)
    
    # Đảm bảo điểm không bao giờ vượt quá 1.0
    final_score = min(score, 1.0)

    return final_score

def analyze_bimodal_fit(
    freq_list: list, 
    modal_outlier_removal: int = 1, 
    min_hours_for_bimodal_analysis: int = 11
) -> float:
    """
    Hàm tiện ích để phân tích Bimodal Fit từ một danh sách tần suất thô.
    """
    # Tiền xử lý: Tạo freq_count và total_bars từ freq_list
    active_hours_list = [freq for freq in freq_list if freq > 0]
    total_bars = len(active_hours_list)
    
    if total_bars == 0:
        return 0.0
        
    freq_count = Counter(active_hours_list)
    
    try:
        score = _calculate_bimodal_fit_score_final(
            freq_count=freq_count,
            total_bars=total_bars,
            modal_outlier_removal=modal_outlier_removal,
            min_hours_for_bimodal_analysis=min_hours_for_bimodal_analysis
        )
        return score
    except ValueError as e:
        # In lỗi nếu có vấn đề, nhưng trả về 0.0 cho các kịch bản phân tích tự động.
        print(f"Không thể tính toán Bimodal Fit: {e}")
        return 0.0

def calculate_coefficient_of_variation_score_final(freq_list: list) -> float:
    """
    Tính điểm hành vi dựa trên Hệ số Biến thiên (CV) một cách chặt chẽ.

    Hàm này được cập nhật để bao gồm các bước kiểm tra và xử lý biên
    chi tiết tương tự như phiên bản Go:
    1. Kiểm tra đầu vào chi tiết (không rỗng, không chứa số âm, tổng > 0).
    2. Làm tròn kết quả cuối cùng đến 3 chữ số thập phân.
    3. Xử lý các trường hợp biên và kẹp (clamp) giá trị một cách tường minh.

    Args:
        freq_list (list): Một danh sách các số nguyên đại diện cho tần suất.

    Returns:
        float: Điểm số hành vi trong khoảng [0.0, 1.0].

    Raises:
        ValueError: Nếu dữ liệu đầu vào không hợp lệ.
    """
    # Yếu tố 1 & 3: Kiểm tra đầu vào và xử lý biên tường minh
    # -----------------------------------------------------------
    if not freq_list:
        raise ValueError("Lỗi: Danh sách đầu vào không được rỗng.")

    total = 0
    for entry in freq_list:
        if entry < 0:
            raise ValueError("Lỗi: Danh sách không được chứa giá trị âm.")
        total += entry
    
    if total <= 0:
        # Nếu tổng bằng 0 (ví dụ: [0, 0, 0]), có nghĩa là không có hoạt động.
        # Theo logic của code Go, đây được coi là dữ liệu không hợp lệ để chấm điểm.
        # Điểm số 1.0 (nhất quán tuyệt đối) cũng là một lựa chọn, nhưng ta tuân thủ logic gốc.
        raise ValueError("Lỗi: Tổng của các tần suất phải lớn hơn 0.")

    # Tính toán giá trị trung bình và độ lệch chuẩn
    # -----------------------------------------------------------
    mean = np.mean(freq_list)
    std_dev = np.std(freq_list)

    # Tính toán CV, sử dụng abs(mean) để đảm bảo an toàn dù đã kiểm tra
    cv = std_dev / mean

    # Yếu tố 3: Xử lý logic tính điểm và "kẹp" giá trị một cách tường minh
    # -----------------------------------------------------------
    score = 0.0
    if cv > 1.0:
        score = 0.0
    else:
        score = 1.0 - cv

    # Đảm bảo điểm số luôn nằm trong khoảng [0.0, 1.0] để tránh các lỗi
    # về số thực dấu phẩy động.
    score = max(0.0, min(1.0, score))

    # Yếu tố 2: Làm tròn kết quả đầu ra
    # -----------------------------------------------------------
    final_score = round(score, 3)

    return final_score

# --- Ví dụ sử dụng ---
# Kịch bản hợp lệ
flat_pattern = [10, 11, 10, 9, 12, 10, 11, 10]
random_pattern = [2, 15, 7, 25, 1, 18, 10, 30]

print(f"Mẫu hình nhất quán, điểm số: {calculate_coefficient_of_variation_score_final(flat_pattern)}")
print(f"Mẫu hình ngẫu nhiên, điểm số: {calculate_coefficient_of_variation_score_final(random_pattern)}")
print("-" * 20)

# Kịch bản không hợp lệ (sẽ gây ra lỗi ValueError)
try:
    calculate_coefficient_of_variation_score_final([])
except ValueError as e:
    print(e)

try:
    calculate_coefficient_of_variation_score_final([10, 5, -1, 8])
except ValueError as e:
    print(e)

try:
    calculate_coefficient_of_variation_score_final([0, 0, 0, 0])
except ValueError as e:
    print(e)

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




def GetBeaconMinMaxTimestamps():
    # lấy timestamp max trong data
    # if timestamp max - time
    # lấy timestamp max - 24h
    # if timestamp max - timestamp min < 24h thì lấy timestamp min
    # ngược lại thì lấy timestamp max - 24h
    return minTS, maxTS

minTSBeacon, maxTSBeacon = GetBeaconMinMaxTimestamps()


def get_histogram_score(datasetMin, datasetMax, tsList, modeSensitivity, bimodalOutlierRemoval,bimodalMinHoursSeen,beaconTimeSpan):
    """
    Tính điểm histogram kết hợp cả hệ số biến thiên và điểm bimodal fit.
    Args:
        datasetMin (int): Thời gian bắt đầu của tập dữ liệu (Unix timestamp).
        datasetMax (int): Thời gian kết thúc của tập dữ liệu (Unix timestamp).
        tsList (List[int]): Danh sách các timestamp cần phân tích.
        modeSensitivity (float): Độ nhạy cho việc phân tích bimodal.
        bimodalOutlierRemoval (int): Số giờ hoạt động bị coi là nhiễu và loại bỏ.
        bimodalMinHoursSeen (int): Số giờ tối thiểu để thực hiện phân tích bimodal.
        beaconTimeSpan (int): Khoảng thời gian (tính bằng giờ) để chia biểu đồ histogram.
        Returns:
        float: Điểm số histogram tổng hợp.
    """
    binEdges = compute_histogram_bins(datasetMin, datasetMax, beaconTimeSpan) # TODO
    freqList, freqCount, totalBars, longestRun = create_histogram(binEdges, tsList, modeSensitivity) 
    svscore = calculate_coefficient_of_variation_score_final(freqList)
    # bitmodel
    bitmodalFitScore = _calculate_bimodal_fit_score_final(freqCount, totalBars, longestRun, bimodalOutlierRemoval, bimodalMinHoursSeen)
    score = math.Max(svscore, bitmodalFitScore)
    return score


get_histogram_score(
    minTSBeacon,
    maxTSBeacon,
    TSList, 
    HistogramModeSensitivity, # 0.05
    HistogramBimodalOutlierRemoval, # 1
    HistogramBimodalMinHoursSeen, # 11
    24 # 24 hours span for beacon detection
)