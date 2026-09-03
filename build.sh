#!/usr/bin/env bash
# ============================================================
# gyscan 固件构建/烧录脚本 —— 编译时选择 Flash 版本
#
#   支持 ESP32-S3 两个芯片型号:
#     8m   N8R8   (Flash 8MB  + 8MB OPI PSRAM)   默认
#     16m  N16R8  (Flash 16MB + 8MB OPI PSRAM)
#
#   用法:
#     ./tools/build.sh                # 8m 版本，构建(等价 build 8m)
#     ./tools/build.sh 8m             # 8m 版本，构建
#     ./tools/build.sh 16m            # 16m 版本，构建
#     ./tools/build.sh 16m flash      # 16m 版本，构建并烧录
#     ./tools/build.sh 16m flash monitor   # 构建 + 烧录 + 串口监视
#     ./tools/build.sh 16m menuconfig # 16m 版本，打开 menuconfig
#
#   两个版本使用独立的 build 目录(build-8m / build-16m)，sdkconfig
#   分别存放在各自目录内(build-8m/sdkconfig 与 build-16m/sdkconfig)，
#   互不干扰；切换版本只需换目录，无需删除配置。
#   公共配置见 sdkconfig.defaults；16m 差异见 sdkconfig.defaults.16m。
# ============================================================
set -euo pipefail
cd "$(dirname "$0")/.."

FLASH="${1:-8m}"
if [[ "$FLASH" == "16m" ]]; then
    shift || true
    EXTRA_ARGS=(-DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.16m")
    BUILDDIR="build-16m"
    PARTTABLE="partitions_16m.csv"
elif [[ "$FLASH" == "8m" ]]; then
    shift || true
    EXTRA_ARGS=()
    BUILDDIR="build-8m"
    PARTTABLE="partitions.csv"
else
    echo "错误: 未知 Flash 版本 '$FLASH'（支持: 8m | 16m）" >&2
    exit 1
fi
# sdkconfig 固定在各自 build 目录内，避免与项目根 sdkconfig 互相覆盖
EXTRA_ARGS+=(-DSDKCONFIG="$BUILDDIR/sdkconfig")

# 加载 ESP-IDF 环境（若尚未加载）
if [[ -z "${IDF_PATH:-}" ]]; then
    if [[ -f /opt/esp-idf/export.sh ]]; then
        # shellcheck source=/dev/null
        source /opt/esp-idf/export.sh
    else
        echo "错误: 找不到 ESP-IDF(export.sh)，请先 source 环境或设置 IDF_PATH" >&2
        exit 1
    fi
fi

# 校验已有 sdkconfig 与目标版本一致（防止误用旧目录/旧配置）
SDKCFG="$BUILDDIR/sdkconfig"
if [[ -f "$SDKCFG" ]]; then
    if grep -q "CONFIG_ESPTOOLPY_FLASHSIZE_16MB=y" "$SDKCFG"; then
        CUR=16m
    else
        CUR=8m
    fi
    if [[ "$CUR" != "$FLASH" ]]; then
        echo "警告: $BUILDDIR 的 sdkconfig 是按 ${CUR} 生成的，与目标 ${FLASH} 不符。" >&2
        echo "      请先删除该目录重新生成: rm -rf $BUILDDIR" >&2
        exit 1
    fi
    CUR_TBL=$(grep '^CONFIG_PARTITION_TABLE_CUSTOM_FILENAME=' "$SDKCFG" | head -1 | cut -d'"' -f2)
    if [[ -n "$CUR_TBL" && "$CUR_TBL" != "$PARTTABLE" ]]; then
        echo "警告: $BUILDDIR 分区表是 $CUR_TBL，与目标 $PARTTABLE 不符。" >&2
        echo "      请先删除该目录重新生成: rm -rf $BUILDDIR" >&2
        exit 1
    fi
fi

echo "==> Flash 版本: ${FLASH}  ($([[ $FLASH == 8m ]] && echo N8R8 || echo N16R8))"
echo "==> 构建目录 : ${BUILDDIR}"
echo "==> 分区表   : ${PARTTABLE}"
[[ ${#EXTRA_ARGS[@]} -gt 0 ]] && echo "==> 附加配置 : ${EXTRA_ARGS[*]}"
echo ""

exec idf.py "${EXTRA_ARGS[@]}" -B "$BUILDDIR" "$@"
