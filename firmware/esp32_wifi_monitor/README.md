# ESP32 Wireless Security Shield & Monitor: Build Guide

This directory contains the production-ready C++ firmware to program an ESP32 micro-controller to act as a dedicated security monitor. It scans 2.4GHz frequencies using Wi-Fi promiscuous mode to detect **Deauthentication floods** and runs automated background audits to flag duplicate/rogue **Evil Twin** access points.

---

## 1. Bill of Materials (BOM)

To build the physical security device, you will need:

| Component | Description | Quantity | Recommended Specification |
| :--- | :--- | :--- | :--- |
| **ESP32 NodeMCU** | ESP-WROOM-32 Development Board | 1 | 30-pin or 38-pin DevKit V1 module |
| **I2C LCD 20x4** | Liquid Crystal Display (Yellow/Blue backlit) | 1 | With pre-soldered PCF8574 I2C Backpack |
| **Piezo Buzzer** | Audio indicator for sirens and warning sweeps | 1 | 5V Active or Passive Piezo Buzzer |
| **Red LED** | Active Alarm Warning indicator | 1 | Standard 5mm LED |
| **Green LED** | Normal Operation / Secure Status indicator | 1 | Standard 5mm LED |
| **Resistors** | Current-limiting resistors for LEDs | 2 | 220 $\Omega$ to 330 $\Omega$ Resistors |
| **Breadboard** | Mini or Full size prototyping board | 1 | 830-point or 400-point Breadboard |
| **Jumper Wires** | Connective wires | ~15 | Male-to-Male and Female-to-Male Dupont wires |

---

## 2. Wiring Schematic & Pin Connections

The ESP32 pins are mapped to the hardware peripherals as follows. Ensure your ESP32 is unplugged from the USB power source during assembly.

```
       +---------------------------------------------+
       |                  ESP32 Dev                  |
       |                                             |
       |  [GND]   [5V]   [G21]  [G22]  [G13]  [G12]  [G14]
       +----+------+-------+------+------+------+----+
            |      |       |      |      |      |    |
            |      |       |      |      |      |    +--> [Green LED] --> (330R Resistor) --> [GND]
            |      |       |      |      |      +-------> [Red LED]   --> (330R Resistor) --> [GND]
            |      |       |      |      +--------------> [Buzzer +]  --> [Buzzer -] --------> [GND]
            |      |       |      +---------------------> [LCD SCL]
            |      |       +----------------------------> [LCD SDA]
            |      +------------------------------------> [LCD VCC] (5V)
            +-------------------------------------------> [LCD GND]
```

### Pin Connectivity Table

| ESP32 Pin | Connecting Device | Peripheral Pin | Purpose |
| :--- | :--- | :--- | :--- |
| **5V / VIN** | I2C LCD Display | **VCC** (5V) | Power supply for LCD screen (Requires 5V for optimal backlighting) |
| **GND** | Shared Ground rail | **GND** | System common ground connection |
| **GPIO 21** | I2C LCD Display | **SDA** | I2C Serial Data line |
| **GPIO 22** | I2C LCD Display | **SCL** | I2C Serial Clock line |
| **GPIO 13** | Piezo Buzzer | **Positive (+)** | Tone oscillation generator pin for alarm sweeps |
| **GPIO 12** | Red LED | **Anode (Long leg)**| Triggers flashing warning sequence during active attacks |
| **GPIO 14** | Green LED | **Anode (Long leg)**| Solid green indicator when scanning and environment is secure |
| **GND (via Resistor)**| Both LEDs | **Cathode (Short leg)**| Return current line through current-limiting resistors |

---

## 3. Firmware Installation Instructions

Follow these steps to compile and flash the code onto your ESP32 using the **Arduino IDE**:

### Step 1: Install ESP32 Board Core
1. Open **Arduino IDE**. Go to `File -> Preferences`.
2. Locate the **Additional Boards Manager URLs** input and paste the official Espressif boards package URL:
   `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`
3. Go to `Tools -> Board -> Boards Manager...`.
4. Search for `esp32` and install the package by **Espressif Systems** (Version 2.x or 3.x).

### Step 2: Install Libraries
The firmware depends on the custom I2C LCD library.
1. In Arduino IDE, go to `Sketch -> Include Library -> Manage Libraries...`.
2. In the Search bar, enter: `LiquidCrystal I2C` by **Frank de Brabander**.
3. Install the library.

### Step 3: Configure settings in `config.h`
1. Open the project folder in your IDE.
2. Open [config.h](file:///c:/Users/Aydin/Documents/Cyber-project/firmware/esp32_wifi_monitor/config.h).
3. Under the **Trusted Networks & Whitelist** section, add your home Wi-Fi SSID and your router's authentic BSSID (MAC Address). You can check your router's MAC address in your phone's Wi-Fi details or by using a Wi-Fi scanning app.
4. Save the file.

### Step 4: Flash the Firmware
1. Connect your ESP32 to your PC using a micro-USB (or USB-C) data-sync cable.
2. In Arduino IDE, select your board model under `Tools -> Board -> ESP32 Arduino` (usually **ESP32 Dev Module** or **NodeMCU-32S**).
3. Select the active COM port under `Tools -> Port`.
4. Click the **Upload** button (arrow icon in the top left).
5. Open `Tools -> Serial Monitor` and set the baud rate to **115200** to watch system logs.

---

## 4. Log Parsing Format
When running, the ESP32 streams highly structured CSV events over the USB Serial interface at **115200 baud**. This telemetry format can be directly ingested by custom companion apps or scripts:

1. **System Events**: `SYS,[EVENT_TYPE],[METADATA]`
   - Startup: `SYS,STARTUP,[Description]`
   - Ready: `SYS,READY,Security Scanner fully armed.`
   - Sniff Hop: `SYS,CHANNEL,[Channel_Number_1_to_13]`
   - Deauth Alert Start: `SYS,ALERT,DEAUTH_STORM_START,[Pkts_Sec],[Rogue_MAC]`
   - Evil Twin Alert Start: `SYS,ALERT,EVIL_TWIN_DETECTED,[Spoofed_SSID],[Rogue_MAC]`

2. **Sniffer Packets**: `LOG,DEAUTH,[Timestamp_ms],[Src_MAC],[Dst_MAC],[Channel],[RSSI]`
3. **Scanned Access Points**: `AP,[SSID],[BSSID],[RSSI],[Security_Mode_Int],[Channel]`
4. **Telemetry Stats Report**: `STATS,[Timestamp_ms],[Deauth_Pkts_Sec],[Total_Deauth_Accum],[Threat_Level_0_to_2],[Active_Channel]`
