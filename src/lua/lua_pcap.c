/*
 * lua_pcap.c - firmware built-in Lua pcap module (WiFi promiscuous capture)
 *
 * Based entirely on ESP-IDF esp_wifi promiscuous APIs (same primitives as
 * arp_mitm); no luarocks / libpcap. Script-facing API (single active handle):
 *
 *   pcap.open([snaplen])             -> handle | nil, err
 *   pcap.next(handle[, timeout_ms])   -> frame | nil (timeout), err
 *   pcap.close(handle)                -> true
 *   pcap.filter(handle[, bpf])        -> true   (set/clear filter string)
 *   pcap.interfaces()                 -> { "wlan0", ... }
 *   pcap.parse(data[, offset])        -> {src,dst,ethertype,payload}
 *
 * The esp_wifi promiscuous callback runs in the WiFi RX task context and
 * must return quickly; frames are snapshotted into a global queue and
 * Lua-side pcap.next blocks pulling from it. While a handle stays open
 * the radio remains in promiscuous mode.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"

#include "lua.h"
#include "lauxlib.h"

#include "lua_pcap.h"

static const char *TAG = "lua_pcap";

#define PCAP_MAX_SNAP     1024
#define PCAP_QUEUE_LEN   16
#define PCAP_MT          "gyscan.pcap"

typedef struct {
    uint32_t ts_ms;
    uint16_t frame_len;
    uint16_t ethertype;
    int8_t   rssi;
    uint8_t  src[6];
    uint8_t  dst[6];
    uint16_t data_len;
    uint8_t  data[PCAP_MAX_SNAP];
} pcap_frame_t;

/* global capture engine (single active handle) */
static SemaphoreHandle_t s_lock;
static QueueHandle_t     s_queue;
static bool              s_open;
static char             *s_filter;

static void mac_to_str(const uint8_t mac[6], char *buf, size_t sz)
{
    snprintf(buf, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
              mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* snapshot inner LLC/SNAP + payload of a DATA 802.11 frame */
static void pcap_ingest(const uint8_t *payload, uint16_t sig_len, int8_t rssi)
{
    if (sig_len < 24)
        return;
    uint16_t fc = payload[0] | (payload[1] << 8);
    if (((fc >> 2) & 0x3) != 2)
        return;
    int hdrlen = 24;
    if ((fc >> 4) & 0x08)
        hdrlen = 26;
    if (sig_len <= (uint16_t)hdrlen)
        return;
    uint16_t body = sig_len - (uint16_t)hdrlen;
    uint8_t src[6], dst[6];
    memcpy(dst, payload + 4, 6);
    memcpy(src, payload + 10, 6);
    uint16_t ethertype = 0;
    if (body >= 8)
        ethertype = (uint16_t)((payload[hdrlen + 6] << 8) | payload[hdrlen + 7]);
    uint16_t copy = body > PCAP_MAX_SNAP ? PCAP_MAX_SNAP : body;
    pcap_frame_t *frame = (pcap_frame_t *)malloc(sizeof(pcap_frame_t));
    if (frame == NULL)
        return;
    frame->ts_ms = (uint32_t)(esp_timer_get_time() / 1000);
    frame->frame_len = sig_len;
    frame->ethertype = ethertype;
    frame->rssi = rssi;
    memcpy(frame->src, src, 6);
    memcpy(frame->dst, dst, 6);
    frame->data_len = copy;
    if (copy > 0)
        memcpy(frame->data, payload + hdrlen, copy);
    if (xSemaphoreTake(s_lock, 0) == pdTRUE) {
        if (s_open) {
            pcap_frame_t *copy_ptr = frame;
            if (xQueueSend(s_queue, &copy_ptr, 0) != pdTRUE)
                free(frame);
        } else {
            free(frame);
        }
        xSemaphoreGive(s_lock);
    } else {
        free(frame);
    }
}

/* promiscuous-mode RX callback (WiFi RX task context; must be fast) */
static void pcap_promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (buf == NULL || type != WIFI_PKT_DATA)
        return;
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    int8_t rssi = (int8_t)pkt->rx_ctrl.rssi;
    pcap_ingest(pkt->payload, pkt->rx_ctrl.sig_len, rssi);
}

/* engine open/close */
static esp_err_t pcap_engine_open(void)
{
    if (s_lock == NULL)
        s_lock = xSemaphoreCreateMutex();
    if (s_queue == NULL)
        s_queue = xQueueCreate(PCAP_QUEUE_LEN, sizeof(pcap_frame_t *));
    if (s_lock == NULL || s_queue == NULL)
        return ESP_ERR_NO_MEM;
    esp_wifi_set_promiscuous_rx_cb(pcap_promisc_cb);
    wifi_promiscuous_filter_t flt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA };
    esp_wifi_set_promiscuous_filter(&flt);
    esp_err_t err = esp_wifi_set_promiscuous(true);
    if (err != ESP_OK)
        return err;
    esp_wifi_set_ps(WIFI_PS_NONE);
    s_open = true;
    return ESP_OK;
}

static void pcap_engine_close(void)
{
    if (!s_open)
        return;
    s_open = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_ps(WIFI_PS_MIN_MODEM);
}

static void pcap_queue_flush(void)
{
    if (s_queue == NULL)
        return;
    pcap_frame_t *frame = NULL;
    while (xQueueReceive(s_queue, &frame, 0) == pdTRUE) {
        if (frame != NULL)
            free(frame);
    }
}

static void pcap_push_frame(lua_State *L, const pcap_frame_t *f)
{
    char s[20], d[20];
    mac_to_str(f->src, s, sizeof(s));
    mac_to_str(f->dst, d, sizeof(d));
    lua_createtable(L, 0, 8);
    lua_pushlstring(L, (const char *)f->data, f->data_len);
    lua_setfield(L, -2, "data");
    lua_pushstring(L, s);
    lua_setfield(L, -2, "src");
    lua_pushstring(L, d);
    lua_setfield(L, -2, "dst");
    lua_pushinteger(L, f->ethertype);
    lua_setfield(L, -2, "ethertype");
    lua_pushinteger(L, (lua_Integer)f->ts_ms * 1000000);
    lua_setfield(L, -2, "timestamp");
    lua_pushinteger(L, f->data_len);
    lua_setfield(L, -2, "length");
    lua_pushinteger(L, f->rssi);
    lua_setfield(L, -2, "rssi");
}

static int pcap_open(lua_State *L)
{
    (void)luaL_optinteger(L, 1, 256);
    if (s_open)
        return luaL_error(L, "pcap: already open (single active handle)");
    if (pcap_engine_open() != ESP_OK)
        return luaL_error(L, "pcap: open failed (WiFi not connected?)");
    lua_newuserdata(L, 1);
    luaL_setmetatable(L, PCAP_MT);
    return 1;
}

static int pcap_next(lua_State *L)
{
    luaL_checkudata(L, 1, PCAP_MT);
    int timeout = (int)luaL_optinteger(L, 2, -1);
    TickType_t ticks = timeout < 0 ? portMAX_DELAY : pdMS_TO_TICKS(timeout);
    pcap_frame_t *frame = NULL;
    if (xQueueReceive(s_queue, &frame, ticks) == pdTRUE && frame != NULL) {
        pcap_push_frame(L, frame);
        free(frame);
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

static int pcap_close(lua_State *L)
{
    luaL_checkudata(L, 1, PCAP_MT);
    pcap_engine_close();
    pcap_queue_flush();
    return 0;
}

static int pcap_filter(lua_State *L)
{
    luaL_checkudata(L, 1, PCAP_MT);
    if (lua_type(L, 2) != LUA_TSTRING) {
        free(s_filter);
        s_filter = NULL;
        return 0;
    }
    const char *flt = luaL_checkstring(L, 2);
    char *copy = strdup(flt);
    if (copy == NULL)
        return luaL_error(L, "pcap: OOM");
    free(s_filter);
    s_filter = copy;
    return 0;
}

static int pcap_interfaces(lua_State *L)
{
    lua_createtable(L, 1, 0);
    lua_pushstring(L, "wlan0");
    lua_rawseti(L, -2, 1);
    return 1;
}

static int pcap_parse(lua_State *L)
{
    size_t len = 0;
    const char *data = luaL_checklstring(L, 1, &len);
    int off = (int)luaL_optinteger(L, 2, 0);
    if (off < 0 || (size_t)off + 14 > len)
        return luaL_error(L, "pcap.parse: truncated");
    char s[20], d[20];
    mac_to_str((const uint8_t *)data + off + 6, s, sizeof(s));
    mac_to_str((const uint8_t *)data + off, d, sizeof(d));
    uint16_t eth = (uint16_t)(((uint8_t)data[off + 12] << 8) | (uint8_t)data[off + 13]);
    lua_createtable(L, 0, 4);
    lua_pushstring(L, s);
    lua_setfield(L, -2, "src");
    lua_pushstring(L, d);
    lua_setfield(L, -2, "dst");
    lua_pushinteger(L, eth);
    lua_setfield(L, -2, "ethertype");
    lua_pushlstring(L, data + off + 14, len - (size_t)off - 14);
    lua_setfield(L, -2, "payload");
    return 1;
}

static int pcap_gc(lua_State *L)
{
    (void)L;
    pcap_engine_close();
    pcap_queue_flush();
    return 0;
}

static const luaL_Reg pcap_methods[] = {
    { "open",       pcap_open },
    { "next",       pcap_next },
    { "close",      pcap_close },
    { "filter",     pcap_filter },
    { "interfaces", pcap_interfaces },
    { "parse",      pcap_parse },
    { NULL, NULL },
};

static int luaopen_pcap(lua_State *L)
{
    luaL_newlib(L, pcap_methods);
    if (luaL_newmetatable(L, PCAP_MT)) {
        lua_pushliteral(L, "__gc");
        lua_pushcfunction(L, pcap_gc);
        lua_rawset(L, -3);
    }
    lua_pop(L, 1);
    return 1;
}

void gyscan_lua_pcap_register(lua_State *L)
{
    luaL_requiref(L, "pcap", luaopen_pcap, 1);
    lua_pop(L, 1);
    ESP_LOGI(TAG, "Lua pcap registered (WiFi promiscuous capture, no libpcap)");
}

