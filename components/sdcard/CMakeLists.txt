# SD/TF 卡(SDSPI) 组件。
# 通过 SPI 挂载/卸载/格式化 FAT 格式 TF 卡，挂载点为 /sdcard。
# 引脚通过 menuconfig (SD Card Configuration) 配置，默认适合常见
# microSD SPI 模块(DuPont 接线)。

idf_component_register(
    SRCS "sdcard.c"
    INCLUDE_DIRS "include"
    REQUIRES fatfs sdmmc esp_driver_sdspi esp_driver_spi
)