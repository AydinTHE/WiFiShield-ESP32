/**
 * ESP32 Wi-Fi Security Monitor - Configuration Header
 * 
 * This file contains customizable constants for hardware pin assignments,
 * attack detection thresholds, and trusted network profiles.
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <Arduino.h>

// ==========================================
// 1. HARDWARE PIN OUTS & CONFIGURATION
// ==========================================

// I2C Liquid Crystal Display Configuration
#define LCD_I2C_ADDR      0x27  // Standard I2C address for LiquidCrystal PCF8574. Use 0x3F if 0x27 fails.
#define LCD_COLUMNS       20    // 20 Columns
#define LCD_ROWS          4     // 4 Rows

// ESP32 I2C Pins (Default are SDA=21, SCL=22, customize if using custom board)
#define I2C_SDA_PIN       21
#define I2C_SCL_PIN       22

// Alert Hardware
#define BUZZER_PIN        13    // Pin connected to positive terminal of Piezo Buzzer
#define ALERT_LED_PIN     12    // Pin connected to Red Alarm LED
#define STATUS_LED_PIN    14    // Pin connected to Green System Status LED

// ==========================================
// 2. DETECTION THRESHOLDS & TIMERS
// ==========================================

// Channel Hopping Timing
#define CHANNEL_HOP_INTERVAL_MS   150  // Duration (ms) to sniff on a single channel before hopping (range: 100-300ms)

// Deauthentication Sniffer Settings
#define DEAUTH_ALERT_THRESHOLD     5    // Number of Deauth/Disassociation frames per second to trigger active attack state
#define THREAT_COOLDOWN_MS      5000    // Alert state remains active for 5 seconds after the last attack packet

// Evil Twin / Access Point Scan Settings
#define BG_SCAN_INTERVAL_MS    30000    // Perform a background network scan every 30 seconds for duplicate SSIDs
#define RSSI_VARIANCE_LIMIT       25    // Maximum expected signal difference (dBm) between access points before raising alert

// ==========================================
// 3. TRUSTED NETWORKS & WHITELIST
// ==========================================

// Structure defining a trusted home or business Access Point
struct TrustedNetwork {
    const char* ssid;          // Exact Network Name (SSID)
    const char* bssid;         // MAC Address of router (BSSID) in format "xx:xx:xx:xx:xx:xx". Set to NULL to whitelist by SSID only.
    int authMode;              // Expected security mode (e.g. WIFI_AUTH_WPA2_PSK)
};

// List of authorized wireless networks. The Evil Twin Detector will compare 
// scanned networks against these settings. If a scanned network matches a whitelisted 
// SSID but has a different BSSID or open security, it flags an Evil Twin warning!
const TrustedNetwork TRUSTED_NETWORKS[] = {
    {"MyHomeNetwork_5G", "AA:BB:CC:11:22:33", 4},  // Example: SSID, authentic MAC, WPA2_PSK (4)
    {"Office_WiFi_Regular", NULL, 3},             // Example: Whitelist by SSID only, security WPA_WPA2_PSK (3)
    {"Secure_IoT_Vault", "00:11:22:33:44:55", 4}
};

// Size calculation for trusted networks list
#define TRUSTED_NETWORKS_COUNT (sizeof(TRUSTED_NETWORKS) / sizeof(TRUSTED_NETWORKS[0]))

// ==========================================
// 4. PROTOCOL REFERENCE VALUES
// ==========================================
// 802.11 Frame Type and Subtype Definitions
#define FRAME_TYPE_MANAGEMENT      0x00
#define SUBTYPE_DISASSOCIATION     0x0A
#define SUBTYPE_DEAUTHENTICATION   0x0C

#endif // CONFIG_H
