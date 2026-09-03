#!/bin/zsh
# ESP-IDF QEMU 启动脚本 - ESP32-S3 with TF Card Simulation
# 使用 8MB(N8R8) 布局(build-8m)，与 tools/build.sh 8m 保持一致

# 设置 ESP-IDF 环境变量
source /opt/esp-idf/export.sh
idf.py -B build-8m -DSDKCONFIG=build-8m/sdkconfig qemu \
  --qemu-extra-args="-nic user,model=open_eth,hostfwd=tcp::8080-:80,hostfwd=tcp::1234-:1234" monitor

