#!/bin/zsh
# ESP-IDF QEMU 启动脚本 - ESP32-S3 with TF Card Simulation

# 设置 ESP-IDF 环境变量
source /opt/esp-idf/export.sh
idf.py qemu --qemu-extra-args="-nic user,model=open_eth,hostfwd=tcp::8080-:80,hostfwd=tcp::1234-:1234" monitor

