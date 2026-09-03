/*
 * lua_ble.c - firmware built-in Lua BLE module (NimBLE scan/pair)
 *
 * Based entirely on ESP-IDF NimBLE stack (same primitives as
 * ble_scan.c); no luarocks. Script-facing API:
 *
 *   ble.scan([duration_ms])  -> { devices } | nil, err
 *   ble.status()            -> string
 *   ble.pair(addr)          -> true | nil, err
 *   ble.disconnect()        -> true | nil, err
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_err.h"
#include "esp_log.h"

#include "lua.h"
#include "lauxlib.h"

#include "lua_ble.h"
#include "ble_scan.h"

static const char *TAG = "lua_ble";

#define BLE_SCAN_DEF_DURATION  5000
#define BLE_MAX_NAME  32
#define BLE_MAX_ADDR  18

/* ble.scan([duration_ms]) -> { devices } | nil, err */
static int l_ble_scan(lua_State *L)
{
    int duration = (int)luaL_optinteger(L, 1, BLE_SCAN_DEF_DURATION);
    if (duration < 500 || duration > 60000)
        return luaL_error(L, "ble.scan: duration must be 500..60000 ms");

    int n = ble_scan_perform(duration);
    if (n < 0)
        return luaL_error(L, "ble.scan: failed to start scan");

    lua_createtable(L, n, 0);
    for (int i = 0; i < n; i++) {
        char name[BLE_MAX_NAME];
        char addr[BLE_MAX_ADDR];
        int8_t rssi = 0;
        ble_scan_result_get(i, name, sizeof(name), addr, sizeof(addr), &rssi);
        lua_createtable(L, 0, 3);
        lua_pushstring(L, name);
        lua_setfield(L, -2, "name");
        lua_pushstring(L, addr);
        lua_setfield(L, -2, "addr");
        lua_pushinteger(L, rssi);
        lua_setfield(L, -2, "rssi");
        lua_rawseti(L, -2, i + 1);
    }
    return 1;
}

/* ble.status() -> string */
static int l_ble_status(lua_State *L)
{
    char buf[48];
    ble_get_status_text(buf, sizeof(buf));
    lua_pushstring(L, buf);
    return 1;
}

/* ble.pair(addr) -> true | nil, err */
static int l_ble_pair(lua_State *L)
{
    const char *addr = luaL_checkstring(L, 1);
    if (addr == NULL || strlen(addr) < 17)
        return luaL_error(L, "ble.pair: invalid address (expect aa:bb:cc:dd:ee:ff)");
    esp_err_t err = ble_pair_address(addr);
    if (err != ESP_OK) {
        lua_pushnil(L);
        lua_pushfstring(L, "ble.pair failed: %s", esp_err_to_name(err));
        return 2;
    }
    lua_pushboolean(L, 1);
    return 1;
}

/* ble.disconnect() -> true | nil, err */
static int l_ble_disconnect(lua_State *L)
{
    (void)L;
    esp_err_t err = ble_disconnect();
    if (err != ESP_OK) {
        lua_pushnil(L);
        lua_pushfstring(L, "ble.disconnect failed: %s", esp_err_to_name(err));
        return 2;
    }
    lua_pushboolean(L, 1);
    return 1;
}

static const luaL_Reg ble_methods[] = {
    { "scan",       l_ble_scan },
    { "status",     l_ble_status },
    { "pair",       l_ble_pair },
    { "disconnect", l_ble_disconnect },
    { NULL, NULL },
};

static int luaopen_ble(lua_State *L)
{
    luaL_newlib(L, ble_methods);
    return 1;
}

void gyscan_lua_ble_register(lua_State *L)
{
    luaL_requiref(L, "ble", luaopen_ble, 1);
    lua_pop(L, 1);
    ESP_LOGI(TAG, "Lua BLE registered (NimBLE scan/pair, no luarocks)");
}

