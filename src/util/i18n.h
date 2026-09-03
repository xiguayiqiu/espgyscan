#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    LANG_ZH = 0,
    LANG_EN = 1,
} i18n_lang_t;

/* 设置/获取当前语言 */
void i18n_set_lang(i18n_lang_t lang);
i18n_lang_t i18n_lang(void);

/* 当前是否为英文界面 */
int i18n_is_en(void);

/*
 * 翻译：以中文为字典 key。英文模式下命中返回英文，否则返回原文(中文)。
 * 中文模式下始终返回原文。
 */
const char *i18n_t(const char *zh);

/* 便捷宏：根据当前语言选择中/英文格式串（用于带参 printf） */
#define I18N(zh, en) (i18n_is_en() ? (en) : (zh))

#ifdef __cplusplus
}
#endif
