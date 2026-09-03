/*
 * sdcard.c - SD/TF 卡(SDSPI)挂载/卸载/格式化
 *
 * 通过 SPI 总线驱动外置 microSD/TF 卡模块，FAT 文件系统挂载到 /sdcard。
 * 引脚与 SPI host 由 menuconfig "SD Card Configuration" 配置。
 */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_log.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include "driver/sdspi_host.h"
#include "driver/spi_common.h"
#include "sdkconfig.h"

#include "sdcard.h"

static const char *TAG = "sdcard";

/* 当前挂载的卡句柄；NULL 表示未挂载 */
static sdmmc_card_t *s_card = NULL;
static bool s_bus_owned = false;
static SemaphoreHandle_t s_lock = NULL;

/* 后台操作(mount/format)完成事件 */
static EventGroupHandle_t s_op_evt = NULL;
#define SD_EVT_DONE        (1 << 0)
#define SD_OP_TIMEOUT_MS   (10000)

#define SD_MAX_FILES 8

static bool sdcard_try_lock(TickType_t wait_ticks)
{
    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateMutex();
    }
    return (xSemaphoreTake(s_lock, wait_ticks) == pdTRUE);
}

static void sdcard_unlock(void)
{
    xSemaphoreGive(s_lock);
}

bool sdcard_is_mounted(void)
{
    /* 查询不阻塞：若正在挂载/格式化(锁被占用)则保守返回 false */
    if (!sdcard_try_lock(0)) {
        return false;
    }
    bool mounted = (s_card != NULL);
    sdcard_unlock();
    return mounted;
}

/* 真正执行挂载（在后台任务里、已持锁调用） */
static esp_err_t sdcard_do_mount_locked(void)
{
    if (s_card != NULL) {
        return ESP_OK;   /* 已挂载 */
    }

#ifdef CONFIG_GYSCAN_SDCARD_ENABLE
    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    host.max_freq_khz = 20000;

    esp_err_t ret;

    /* 初始化 SPI 总线 */
    spi_bus_config_t bus_cfg = {
        .mosi_io_num = CONFIG_GYSCAN_SDCARD_PIN_MOSI,
        .miso_io_num = CONFIG_GYSCAN_SDCARD_PIN_MISO,
        .sclk_io_num = CONFIG_GYSCAN_SDCARD_PIN_CLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 8192,
    };
    spi_host_device_t host_id = (spi_host_device_t)CONFIG_GYSCAN_SDCARD_SPI_HOST;

    ret = spi_bus_initialize(host_id, &bus_cfg, SDSPI_DEFAULT_DMA);
    ESP_LOGI(TAG, "spi_bus_initialize 返回: %s", esp_err_to_name(ret));
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "SPI 总线初始化失败: %s", esp_err_to_name(ret));
        return ret;
    }
    s_bus_owned = (ret == ESP_OK);

    sdspi_device_config_t slot_cfg = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot_cfg.host_id = host_id;
    slot_cfg.gpio_cs = CONFIG_GYSCAN_SDCARD_PIN_CS;

    esp_vfs_fat_sdmmc_mount_config_t mount_cfg = {
        .format_if_mount_failed = false,   /* 挂载失败不自动格式化，避免误删数据 */
        .max_files = SD_MAX_FILES,
        .allocation_unit_size = 16 * 1024,
    };

    ESP_LOGI(TAG, "开始探测并挂载 TF 卡...");
    sdmmc_card_t *card = NULL;
    ret = esp_vfs_fat_sdspi_mount(SDCARD_MOUNT_POINT, &host, &slot_cfg,
                                  &mount_cfg, &card);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "TF 卡挂载失败: %s (检查接线/供电/卡格式)",
                 esp_err_to_name(ret));
        if (s_bus_owned) {
            spi_bus_free(host_id);
            s_bus_owned = false;
        }
        return ret;
    }

    s_card = card;
    ESP_LOGI(TAG, "TF 卡已挂载到 %s", SDCARD_MOUNT_POINT);
    sdmmc_card_print_info(stdout, card);
    return ESP_OK;
#else
    ESP_LOGE(TAG, "SD 卡支持未启用(menuconfig: SD Card Configuration)");
    return ESP_ERR_NOT_SUPPORTED;
#endif
}

/* 后台挂载任务 */
static void sdcard_mount_task(void *arg)
{
    esp_err_t *result = (esp_err_t *)arg;

    if (!sdcard_try_lock(0)) {
        ESP_LOGW(TAG, "另一个 TF 卡操作正在进行，跳过本次挂载");
        *result = ESP_ERR_INVALID_STATE;
    } else {
        *result = sdcard_do_mount_locked();
        sdcard_unlock();
    }

    xEventGroupSetBits(s_op_evt, SD_EVT_DONE);
    vTaskDelete(NULL);
}

/* 确保事件组存在并清零 */
static void sdcard_op_prepare(void)
{
    if (s_op_evt == NULL) {
        s_op_evt = xEventGroupCreate();
    }
    xEventGroupClearBits(s_op_evt, SD_EVT_DONE);
}

/*
 * mount 在后台任务执行，调用方限时等待结果。
 * 原因：无卡/坏卡时 SD 探测可能长时间阻塞；独立任务 + 超时可防止
 * 卡死调用方（如菜单任务），QEMU 模拟器等无真实卡场景能及时返回。
 */
esp_err_t sdcard_mount(void)
{
    sdcard_op_prepare();
    esp_err_t result = ESP_FAIL;

    BaseType_t cr = xTaskCreate(sdcard_mount_task, "sd_mount", 8192,
                                &result, 6, NULL);
    if (cr != pdPASS) {
        ESP_LOGE(TAG, "无法创建挂载任务");
        return ESP_ERR_NO_MEM;
    }

    EventBits_t bits = xEventGroupWaitBits(s_op_evt, SD_EVT_DONE, pdFALSE,
                                           pdTRUE, pdMS_TO_TICKS(SD_OP_TIMEOUT_MS));
    if ((bits & SD_EVT_DONE) == 0) {
        ESP_LOGW(TAG, "TF 卡探测超时(无卡? 接线不良?)，已放弃本次挂载");
        return ESP_ERR_TIMEOUT;
    }
    return result;
}

esp_err_t sdcard_unmount(void)
{
    if (!sdcard_try_lock(pdMS_TO_TICKS(SD_OP_TIMEOUT_MS))) {
        ESP_LOGW(TAG, "TF 卡忙(挂载/格式化中)，暂不能卸载");
        return ESP_ERR_TIMEOUT;
    }

    if (s_card == NULL) {
        sdcard_unlock();
        return ESP_OK;   /* 幂等 */
    }

    esp_err_t ret = esp_vfs_fat_sdcard_unmount(SDCARD_MOUNT_POINT, s_card);
    s_card = NULL;

    if (s_bus_owned) {
        spi_bus_free((spi_host_device_t)CONFIG_GYSCAN_SDCARD_SPI_HOST);
        s_bus_owned = false;
    }

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "TF 卡卸载失败: %s", esp_err_to_name(ret));
        sdcard_unlock();
        return ret;
    }

    ESP_LOGI(TAG, "TF 卡已卸载");
    sdcard_unlock();
    return ESP_OK;
}

/* 后台格式化任务 */
static void sdcard_format_task(void *arg)
{
    esp_err_t *result = (esp_err_t *)arg;

    if (!sdcard_try_lock(0)) {
        ESP_LOGW(TAG, "另一个 TF 卡操作正在进行，跳过本次格式化");
        *result = ESP_ERR_INVALID_STATE;
    } else {
        if (s_card == NULL) {
            ESP_LOGE(TAG, "格式化失败: TF 卡未挂载");
            *result = ESP_ERR_INVALID_STATE;
        } else {
            ESP_LOGW(TAG, "正在格式化 TF 卡(将删除所有数据)...");
            *result = esp_vfs_fat_sdcard_format(SDCARD_MOUNT_POINT, s_card);
            if (*result != ESP_OK) {
                ESP_LOGE(TAG, "格式化失败: %s", esp_err_to_name(*result));
            } else {
                ESP_LOGI(TAG, "TF 卡格式化完成");
            }
        }
        sdcard_unlock();
    }

    xEventGroupSetBits(s_op_evt, SD_EVT_DONE);
    vTaskDelete(NULL);
}

/* 格式化也在后台任务执行，带超时防止卡死调用方 */
esp_err_t sdcard_format(void)
{
    if (!sdcard_is_mounted()) {
        ESP_LOGE(TAG, "格式化失败: TF 卡未挂载");
        return ESP_ERR_INVALID_STATE;
    }

    sdcard_op_prepare();
    esp_err_t result = ESP_FAIL;

    BaseType_t cr = xTaskCreate(sdcard_format_task, "sd_format", 8192,
                                &result, 6, NULL);
    if (cr != pdPASS) {
        ESP_LOGE(TAG, "无法创建格式化任务");
        return ESP_ERR_NO_MEM;
    }

    EventBits_t bits = xEventGroupWaitBits(s_op_evt, SD_EVT_DONE, pdFALSE,
                                           pdTRUE, pdMS_TO_TICKS(SD_OP_TIMEOUT_MS));
    if ((bits & SD_EVT_DONE) == 0) {
        ESP_LOGW(TAG, "TF 卡格式化超时");
        return ESP_ERR_TIMEOUT;
    }
    return result;
}

uint64_t sdcard_get_capacity(void)
{
	uint64_t bytes = 0;
	if (!sdcard_try_lock(100)) {
		return 0;
	}
	if (s_card != NULL) {
		bytes = ((uint64_t)s_card->csd.capacity) *
		        ((uint64_t)s_card->csd.sector_size);
	}
	sdcard_unlock();
	return bytes;
}

esp_err_t sdcard_status(char *buf, size_t buf_sz)
{
    if (buf == NULL || buf_sz == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!sdcard_try_lock(100)) {
        snprintf(buf, buf_sz, "busy");
        return ESP_OK;
    }
    if (s_card == NULL) {
        snprintf(buf, buf_sz, "not mounted");
        sdcard_unlock();
        return ESP_OK;
    }

    uint64_t bytes = ((uint64_t)s_card->csd.capacity) *
                     ((uint64_t)s_card->csd.sector_size);
    snprintf(buf, buf_sz, "mounted, %llu MB", (unsigned long long)(bytes >> 20));
    sdcard_unlock();
    return ESP_OK;
}