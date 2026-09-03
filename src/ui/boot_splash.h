/*
 * boot_splash.h - 开机 ASCII 动画
 */
#ifndef BOOT_SPLASH_H
#define BOOT_SPLASH_H

/* 播放开机动画（清屏 + ESP32/GYscan 大字 + 进度条）。阻塞约 2~3 秒。 */
void boot_splash_show(void);

#endif /* BOOT_SPLASH_H */
