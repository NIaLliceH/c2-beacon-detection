#!/bin/sh

# Chờ 30 giây để đảm bảo Elasticsearch đã sẵn sàng khi khởi động lần đầu
echo "Analyzer service starting... Waiting 30 seconds for Elasticsearch to be ready."
sleep 30

# Vòng lặp vô hạn để chạy script mỗi 5 phút (300 giây)
while true
do
  echo "-----------------------------------------------------"
  echo "Running C2 Beaconing analysis at $(date)"
  python /app/sus-score-calc.py
  echo "Analysis finished. Sleeping for 5 minutes."
  echo "-----------------------------------------------------"
  sleep 30
done