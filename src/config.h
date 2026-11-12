#pragma once

// ---- WiFi ----
#define WIFI_SSID        "Userpoint"
#define WIFI_PASS        "FgN56RedgTesgt5S3rr54Ft"
#define AP_SSID          "OPi-Console"
#define AP_PASS          "opi-console-ap"     // >= 8 символов
#define HOSTNAME         "opi-console"        // -> opi-console.local
#define STA_TIMEOUT_MS   15000
#define AP_AFTER_LOST_MS 30000          // сколько ждать после потери STA до запуска AP

// ---- UART к Orange Pi (3.3 В, параметры настраиваются в админке) ----
#define UART_BAUD        115200
#define PIN_P1_RX        20   // RX ESP32 <- TX Pi#1
#define PIN_P1_TX        21   // TX ESP32 -> RX Pi#1
#define PIN_P2_RX        3
#define PIN_P2_TX        4
#define UART_RX_BUF      4096

// ---- Измерение напряжения и тока ----
#define PIN_VOLTAGE1_ADC 0
#define PIN_VOLTAGE2_ADC 1
#define PIN_CURRENT_ADC  2
#define VOLTAGE_DIVIDER_TOP_OHMS    56000UL
#define VOLTAGE_DIVIDER_BOTTOM_OHMS 10000UL
#define CURRENT_SHUNT_OHMS          0.05f // сопротивление шунта для измерения тока
#define VOLTAGE_SAMPLE_COUNT        4 // усреднение по 4 отсчетам
#define VOLTAGE_SAMPLE_INTERVAL_MS  10 // 10 мс между отсчетами

// ---- OLED 0.91" SSD1306 128x32, I2C (адрес 0x3C) ----
#define PIN_OLED_SDA     5
#define PIN_OLED_SCL     6

// ---- Реле питания плат ----
#define PIN_RELAY1       7
#define PIN_RELAY2       10
#define RELAY_ACTIVE_HIGH 1   // 0 для модулей с активным низким уровнем
#define RELAY_CYCLE_OFF_MS 3000

// ---- Консоль ----
#define HIST_LINES       50
#define LINE_MAX         200
#define OUT_MAX          1024
#define FLUSH_MS         20

// ---- Безопасность ----
#define MAX_USERS        8
#define MAX_SESS         16
#define SESSION_MS       (8UL*3600UL*1000UL)
#define PW_ITER          2000
#define LOCK_FAILS       5
#define LOCK_MS          30000UL

// ---- Кнопка BOOT (замыкает на GND, внутренняя подтяжка) ----
#define PIN_BTN_BOOT     9
#define BTN_LONG_MS      1500
#define BTN_DEBOUNCE_MS  40
#define SCREENS          5
