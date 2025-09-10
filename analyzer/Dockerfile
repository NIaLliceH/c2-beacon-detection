FROM python:3.9-slim

# Thiết lập thư mục làm việc trong container
WORKDIR /app

# Sao chép file requirements và cài đặt các thư viện
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Sao chép script phân tích và entrypoint vào container
COPY sus-score-calc.py .
COPY entrypoint.sh .

# Cấp quyền thực thi cho entrypoint script
RUN chmod +x entrypoint.sh

# Lệnh sẽ được chạy khi container khởi động
CMD ["./entrypoint.sh"]