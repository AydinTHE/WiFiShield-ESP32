/**
 * ESP32 Wi-Fi Security Monitor - Main Source Code
 */

#include "config.h"
#include "esp_wifi.h"
#include <LiquidCrystal_I2C.h>
#include <WiFi.h>
#include <Wire.h>

// Initialize LCD Display (Address, Columns, Rows from config.h)
LiquidCrystal_I2C lcd(LCD_I2C_ADDR, LCD_COLUMNS, LCD_ROWS);

// Global Variables
volatile unsigned long deauth_packets_sec =
    0; // Track deauth packets in current second window
volatile unsigned long total_deauth_packets =
    0; // Total deauth packets detected since boot
volatile unsigned long last_packet_rx_time =
    0;                            // Time the last deauth frame was caught
uint8_t active_sniff_channel = 1; // Live channel the sniffer is on

bool in_attack_state = false;        // True if active attack is ongoing
unsigned long attack_start_time = 0; // When the active attack was first flagged
String last_offending_mac = "N/A";   // MAC Address of the rogue actor

unsigned long next_scan_execution_time =
    0;                           // Timer for scheduling background AP scans
bool bg_scanning_active = false; // Flag to pause sniffer during network scan
int threats_identified = 0;      // Count of active threats (deauth / evil twin)
String evil_twin_ssid_alert = ""; // Saved SSID of flagged Evil Twin

// Task Handles for Multi-core Operations
TaskHandle_t SnifferChannelHopTaskHandle = NULL;

// Forward Declarations
void display_status_screen();
void display_attack_screen(String mac_addr);
void display_evil_twin_screen(String ssid, String rogue_bssid);
void trigger_alarm_signals(int severity);
void execute_evil_twin_scan();

/**
 * 802.11 Promiscuous Sniffer Callback Routine
 * Invoked by ESP32 WiFi stack whenever a management packet is observed.
 * Keeps execution brief to prevent core panic.
 */
void sniffer_packet_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
  // We are only interested in 802.11 Management Frames
  if (type != WIFI_PKT_MGMT)
    return;

  wifi_promiscuous_pkt_t *packet = (wifi_promiscuous_pkt_t *)buf;
  uint8_t *payload = packet->payload;
  uint16_t length = packet->rx_ctrl.sig_len;

  // Standard 802.11 MAC Header must be at least 24 bytes to contain addresses
  if (length < 24)
    return;

  // Frame Control Field decoding
  uint8_t frame_type = (payload[0] >> 2) & 0x03;    // Bit 2 and 3
  uint8_t frame_subtype = (payload[0] >> 4) & 0x0F; // Bit 4, 5, 6, and 7

  if (frame_type == FRAME_TYPE_MANAGEMENT) {
    if (frame_subtype == SUBTYPE_DEAUTHENTICATION ||
        frame_subtype == SUBTYPE_DISASSOCIATION) {
      deauth_packets_sec++;
      total_deauth_packets++;
      last_packet_rx_time = millis();

      // Extract Transmitter MAC (Address 2 - bytes 10-15 in MAC header)
      char tx_mac[18];
      snprintf(tx_mac, sizeof(tx_mac), "%02X:%02X:%02X:%02X:%02X:%02X",
               payload[10], payload[11], payload[12], payload[13], payload[14],
               payload[15]);
      last_offending_mac = String(tx_mac);

      // Extract Receiver MAC (Address 1 - bytes 4-9 in MAC header)
      char rx_mac[18];
      snprintf(rx_mac, sizeof(rx_mac), "%02X:%02X:%02X:%02X:%02X:%02X",
               payload[4], payload[5], payload[6], payload[7], payload[8],
               payload[9]);

      // Output CSV format to Serial for companion dashboard streaming
      Serial.printf("LOG,DEAUTH,%lu,%s,%s,%d,%d\n", millis(), tx_mac, rx_mac,
                    packet->rx_ctrl.channel, packet->rx_ctrl.rssi);
    }
  }
}

/**
 * Task Dedicated to Non-Blocking Channel Hopping
 * Runs on Core 0 to prevent interference with loop() processes on Core 1
 */
void channel_hop_execution_task(void *pvParameters) {
  for (;;) {
    if (!bg_scanning_active) {
      // Rotate active channel from 1 to 13 (2.4GHz Wi-Fi range)
      active_sniff_channel++;
      if (active_sniff_channel > 13) {
        active_sniff_channel = 1;
      }

      // Tell ESP32 radio to switch channels
      esp_wifi_set_channel(active_sniff_channel, WIFI_SECOND_CHAN_NONE);

      // Output active scan channel for UI syncing
      Serial.printf("SYS,CHANNEL,%u\n", active_sniff_channel);
    }
    // Delays task execution (non-blocking scheduler sleep)
    vTaskDelay(pdMS_TO_TICKS(CHANNEL_HOP_INTERVAL_MS));
  }
}

/**
 * Setup and Initialization
 */
void setup() {
  // Initialize USB Serial interface for data streaming
  Serial.begin(115200);
  delay(500);
  Serial.println("\nSYS,STARTUP,Initializing Wi-Fi Security Monitor...");

  // Initialize Pin Modes
  pinMode(BUZZER_PIN, OUTPUT);
  pinMode(ALERT_LED_PIN, OUTPUT);
  pinMode(STATUS_LED_PIN, OUTPUT);

  // Default LEDs to Startup State (Glow both during initialization)
  digitalWrite(STATUS_LED_PIN, HIGH);
  digitalWrite(ALERT_LED_PIN, HIGH);

  // Initialize Wire (I2C) and LCD screen
  Wire.begin(I2C_SDA_PIN, I2C_SCL_PIN);
  lcd.init();
  lcd.backlight();

  // Display boot splash (adapts to LCD size in config.h)
  lcd.clear();
#if LCD_ROWS == 2
  lcd.setCursor(0, 0);
  lcd.print("  WIFI SHIELD   ");
  lcd.setCursor(0, 1);
  lcd.print("SECURITY SCANNER");
#else
  lcd.setCursor(0, 0);
  lcd.print("====================");
  lcd.setCursor(0, 1);
  lcd.print(" WIFI SHIELD ESP32  ");
  lcd.setCursor(0, 2);
  lcd.print(" SECURITY SCANNER   ");
  lcd.setCursor(0, 3);
  lcd.print("====================");
#endif

  tone(BUZZER_PIN, 1000, 150);
  delay(150);
  tone(BUZZER_PIN, 1500, 150);
  delay(1000);

  // Initialize ESP32 Wi-Fi in Station Mode (needed for scanning and sniffer)
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  // Start Promiscuous Sniffer Stack
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&sniffer_packet_callback);
  Serial.println("SYS,STATUS,802.11 Promiscuous Sniffer operational.");

  // Spin up core-0 thread to handle rapid channel hopping
  xTaskCreatePinnedToCore(channel_hop_execution_task,   // Function to run
                          "ChannelHopTask",             // Task Name
                          2048,                         // Stack Size
                          NULL,                         // Parameter
                          1,                            // Task Priority
                          &SnifferChannelHopTaskHandle, // Task Handle
                          0                             // Core index 0
  );

  Serial.println("SYS,STATUS,Channel hopper pinned to Core 0 successfully.");

  // Configure first background scan timeline
  next_scan_execution_time = millis() + BG_SCAN_INTERVAL_MS;

  // Transition LEDs to normal running status
  digitalWrite(ALERT_LED_PIN, LOW);
  digitalWrite(STATUS_LED_PIN, HIGH); // Steady green for secure

  lcd.clear();
  Serial.println("SYS,READY,Security Scanner fully armed.");
}

/**
 * Main Controller Loop
 * Runs on Core 1 - processes threats, executes scans, updates physical UI (LCD
 * & Alarms)
 */
void loop() {
  static unsigned long last_sec_time = 0;
  unsigned long current_time = millis();

  // 1. Process packet statistics once every second
  if (current_time - last_sec_time >= 1000) {
    last_sec_time = current_time;

    // Check if packet count exceeds threshold to flag alert state
    if (deauth_packets_sec >= DEAUTH_ALERT_THRESHOLD) {
      if (!in_attack_state) {
        in_attack_state = true;
        attack_start_time = current_time;
        threats_identified++;
        Serial.printf("SYS,ALERT,DEAUTH_STORM_START,%lu,%s\n",
                      deauth_packets_sec, last_offending_mac.c_str());
      }
    }

    // Cooldown verification (if no packets seen for THREAT_COOLDOWN_MS)
    if (in_attack_state &&
        (current_time - last_packet_rx_time > THREAT_COOLDOWN_MS)) {
      in_attack_state = false;
      threats_identified = max(0, threats_identified - 1);
      Serial.println("SYS,INFO,Deauthentication flood settled. System secure.");
      digitalWrite(ALERT_LED_PIN, LOW);
      digitalWrite(STATUS_LED_PIN, HIGH);
    }

    // Print periodic telemetry report
    Serial.printf("STATS,%lu,%lu,%lu,%d,%u\n", current_time, deauth_packets_sec,
                  total_deauth_packets,
                  in_attack_state ? 2 : (threats_identified ? 1 : 0),
                  active_sniff_channel);

    // Refresh display
    if (in_attack_state) {
      display_attack_screen(last_offending_mac);
    } else if (evil_twin_ssid_alert != "") {
      // Evil Twin is active alert
      display_evil_twin_screen(evil_twin_ssid_alert, last_offending_mac);
    } else {
      display_status_screen();
    }

    // Reset periodic second counter
    deauth_packets_sec = 0;
  }

  // 2. Schedule and run background Evil Twin AP scans
  if (current_time >= next_scan_execution_time && !in_attack_state) {
    execute_evil_twin_scan();
    next_scan_execution_time = millis() + BG_SCAN_INTERVAL_MS;
  }

  // 3. Drive Active Buzzers and Alarm LED pulses
  if (in_attack_state) {
    trigger_alarm_signals(2); // High threat (Deauth flood)
  } else if (evil_twin_ssid_alert != "") {
    trigger_alarm_signals(1); // Medium threat (Evil twin found)
  } else {
    // Normal secure state
    digitalWrite(STATUS_LED_PIN, HIGH);
    digitalWrite(ALERT_LED_PIN, LOW);
  }

  // CPU yield to support underlying RTOS tasks
  delay(1);
}

/**
 * Execute Background Active scan for rogue APs matching trusted SSID signatures
 */
void execute_evil_twin_scan() {
  Serial.println("SYS,SCAN_START,Pausing sniffer to scan standard networks...");
  bg_scanning_active = true;

  // Temporarily disable promiscuous sniffer mode to enable active scanning
  esp_wifi_set_promiscuous(false);
  delay(100);

#if LCD_ROWS == 2
  lcd.setCursor(0, 1);
  lcd.print("SCANNING AP...  ");
#else
  lcd.setCursor(0, 3);
  lcd.print("[!] ACTIVE AP SCANNING");
#endif

  // Scan 2.4GHz channels
  int network_count =
      WiFi.scanNetworks(false, true); // Synchronous, show hidden networks
  Serial.printf("SYS,SCAN_END,Scanned %d active Access Points.\n",
                network_count);

  bool rogue_ap_found = false;
  String rogue_ssid = "";
  String rogue_bssid = "";

  if (network_count > 0) {
    for (int i = 0; i < network_count; ++i) {
      String ssid = WiFi.SSID(i);
      String bssid = WiFi.BSSIDstr(i);
      int rssi = WiFi.RSSI(i);
      int auth = WiFi.encryptionType(i);

      // Stream AP details to Web Console
      Serial.printf("AP,%s,%s,%d,%d,%d\n", ssid.c_str(), bssid.c_str(), rssi,
                    auth, WiFi.channel(i));

      // Audit AP against whitelisted config profiles
      for (int t = 0; t < TRUSTED_NETWORKS_COUNT; t++) {
        TrustedNetwork target = TRUSTED_NETWORKS[t];

        if (ssid.equals(target.ssid)) {
          // Rule A: SSID matches, but MAC Address is completely different
          if (target.bssid != NULL) {
            String clean_bssid_config = String(target.bssid);
            clean_bssid_config.toUpperCase();
            String clean_bssid_scanned = bssid;
            clean_bssid_scanned.toUpperCase();

            if (!clean_bssid_scanned.equals(clean_bssid_config)) {
              rogue_ap_found = true;
              rogue_ssid = ssid;
              rogue_bssid = bssid;
              break;
            }
          }

          // Rule B: Security configuration is downgraded (e.g. Open network
          // cloning secure home network)
          if (auth != target.authMode && target.authMode != 0) {
            // Flag downgrade attack
            rogue_ap_found = true;
            rogue_ssid = ssid;
            rogue_bssid = bssid;
            break;
          }
        }
      }
      if (rogue_ap_found)
        break;
    }
  }

  // Register or clear Evil Twin flag based on scan results
  if (rogue_ap_found) {
    evil_twin_ssid_alert = rogue_ssid;
    last_offending_mac = rogue_bssid;
    threats_identified = max(1, threats_identified);
    Serial.printf("SYS,ALERT,EVIL_TWIN_DETECTED,%s,%s\n", rogue_ssid.c_str(),
                  rogue_bssid.c_str());
  } else {
    if (evil_twin_ssid_alert != "") {
      evil_twin_ssid_alert = "";
      threats_identified = max(0, threats_identified - 1);
      Serial.println("SYS,INFO,Rogue access point no longer visible.");
    }
  }

  // Delete scan history cache to release memory
  WiFi.scanDelete();

  // Resume Sniffer operations
  delay(50);
  esp_wifi_set_promiscuous(true);
  bg_scanning_active = false;
  Serial.println("SYS,STATUS,802.11 Sniffer resumed.");
}

/**
 * Renders Standard LCD Monitoring Screen
 */
void display_status_screen() {
#if LCD_ROWS == 2
  lcd.setCursor(0, 0);
  lcd.print("SECURE  Ch: [");
  if (active_sniff_channel < 10)
    lcd.print("0");
  lcd.print(active_sniff_channel);
  lcd.print("]");

  lcd.setCursor(0, 1);
  lcd.print("D/s:0  TOT:");
  lcd.print(total_deauth_packets);
  lcd.print("      ");
#else
  lcd.setCursor(0, 0);
  lcd.print("=== WIRELESS SHIELD ===");

  lcd.setCursor(0, 1);
  lcd.print("SYSTEM SECURE    ");

  lcd.setCursor(0, 2);
  lcd.print("Ch Sniffer: [");
  if (active_sniff_channel < 10)
    lcd.print("0");
  lcd.print(active_sniff_channel);
  lcd.print("]    ");

  lcd.setCursor(0, 3);
  lcd.print("Deauth/s: 0   CUM:");
  lcd.print(total_deauth_packets);
  lcd.print("     ");
#endif
}

/**
 * Renders High-Priority Deauth Attack Warnings on LCD
 */
void display_attack_screen(String mac_addr) {
#if LCD_ROWS == 2
  lcd.setCursor(0, 0);
  lcd.print("! DEAUTH STORM !");

  lcd.setCursor(0, 1);
  lcd.print("MAC:" + mac_addr.substring(0, 12));
#else
  lcd.setCursor(0, 0);
  lcd.print("!!! ALERT STORM !!! ");

  lcd.setCursor(0, 1);
  lcd.print("DEAUTH ATTACK ACTIVE");

  lcd.setCursor(0, 2);
  lcd.print("Rogue MAC:          ");
  lcd.setCursor(0, 2);
  lcd.print("M: " + mac_addr.substring(0, 17));

  lcd.setCursor(0, 3);
  lcd.print("Pkts: ");
  lcd.print(deauth_packets_sec);
  lcd.print("/s  TOT:");
  lcd.print(total_deauth_packets);
#endif
}

/**
 * Renders Medium-Priority Rogue Evil Twin Warnings on LCD
 */
void display_evil_twin_screen(String ssid, String rogue_bssid) {
#if LCD_ROWS == 2
  lcd.setCursor(0, 0);
  lcd.print("! EVIL TWIN AP !");

  lcd.setCursor(0, 1);
  lcd.print("SSID:" + ssid.substring(0, 11));
#else
  lcd.setCursor(0, 0);
  lcd.print("[!] WARNING [!]     ");

  lcd.setCursor(0, 1);
  lcd.print("EVIL TWIN AP DETECTD");

  lcd.setCursor(0, 2);
  lcd.print("SSID: ");
  lcd.print(ssid.substring(0, 14));

  lcd.setCursor(0, 3);
  lcd.print("MAC: ");
  lcd.print(rogue_bssid.substring(0, 15));
#endif
}

/**
 * Drives audible (Piezo) and visual (LED) signals based on threat scale
 */
void trigger_alarm_signals(int severity) {
  unsigned long time_ms = millis();

  if (severity == 2) {
    // 1. High Threat (Deauth Storm): Fast LED toggling and warble siren buzzer
    digitalWrite(STATUS_LED_PIN, LOW); // Green Off

    // Toggle Alert LED every 100ms
    if ((time_ms / 100) % 2 == 0) {
      digitalWrite(ALERT_LED_PIN, HIGH);
      // Sweeping high frequency audio
      tone(BUZZER_PIN, 1800 + ((time_ms % 200) * 3));
    } else {
      digitalWrite(ALERT_LED_PIN, LOW);
      noTone(BUZZER_PIN);
    }
  } else if (severity == 1) {
    // 2. Medium Threat (Evil Twin Scanned): Pulsing LED and double beep every 2
    // seconds
    digitalWrite(STATUS_LED_PIN, HIGH); // Keep status on

    int cycle = time_ms % 2000;
    if (cycle < 150) {
      digitalWrite(ALERT_LED_PIN, HIGH);
      tone(BUZZER_PIN, 1200);
    } else if (cycle >= 150 && cycle < 300) {
      digitalWrite(ALERT_LED_PIN, LOW);
      noTone(BUZZER_PIN);
    } else if (cycle >= 300 && cycle < 450) {
      digitalWrite(ALERT_LED_PIN, HIGH);
      tone(BUZZER_PIN, 1200);
    } else {
      digitalWrite(ALERT_LED_PIN, LOW);
      noTone(BUZZER_PIN);
    }
  }
}
