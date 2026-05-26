/**
 * ESP32 Wi-Fi Security Monitor - Web Dashboard & Simulator Core
 * 
 * Manages the reactive visual state, real-time wireless attack simulations,
 * interactive wiring highlights, Web Audio buzzer synthesizers,
 * dynamic telemetry plotting, and custom C++ header compilers.
 */

// ==========================================
// 1. STATE MACHINE & INITIALIZATION
// ==========================================
const state = {
    scenario: 'normal',       // normal, eviltwin, deauth, dual
    currentChannel: 1,
    deauthRateSec: 0,
    totalDeauths: 0,
    threatLevel: 'zero',      // zero, warning, danger
    audioMuted: true,
    lastOffendingMac: 'N/A',
    homeSsid: 'MyHomeNetwork_5G',
    homeBssid: 'AA:BB:CC:11:22:33',
    channelHoppingActive: true,
    scanTimer: 0,             // Counts down to next active AP scan
    chartHistory: Array(30).fill(0), // 30-second history for SVG graphs
    logs: []                  // Serial console logs
};

// Web Audio API Synthesizer Context (Instantiated on user interaction)
let audioCtx = null;
let buzzerOsc = null;
let buzzerGain = null;
let alarmIntervalId = null;

// DOM Selectors
const el = {
    statusGlow: document.getElementById('status-glow'),
    stateText: document.getElementById('state-text'),
    channelDisplay: document.getElementById('current-channel-display'),
    threatLevelBadge: document.getElementById('threat-level-badge'),
    
    // ESP32 simulation board
    esp32Board: document.getElementById('virtual-esp32-board'),
    esp32StatusLed: document.getElementById('esp32-status-led'),
    esp32AlarmLed: document.getElementById('esp32-alarm-led'),
    
    // LCD Lines
    lcdScreen: document.getElementById('lcd-screen-display'),
    lcdLines: [
        document.getElementById('lcd-line-1'),
        document.getElementById('lcd-line-2'),
        document.getElementById('lcd-line-3'),
        document.getElementById('lcd-line-4')
    ],
    
    // Controls
    btnNormal: document.getElementById('trigger-normal-btn'),
    btnTwin: document.getElementById('trigger-twin-btn'),
    btnDeauth: document.getElementById('trigger-deauth-btn'),
    btnMulti: document.getElementById('trigger-multi-btn'),
    btnToggleSiren: document.getElementById('toggle-siren-audio-btn'),
    sirenMuteStatus: document.getElementById('siren-mute-status'),
    simTargetMac: document.getElementById('sim-target-mac'),
    
    // Stats displays
    deauthRateDisplay: document.getElementById('deauth-rate-display'),
    totalDeauthDisplay: document.getElementById('total-deauth-display'),
    activeHopDisplay: document.getElementById('active-hop-ch-display'),
    scannerBadge: document.getElementById('scanner-pulse-badge'),
    
    // Chart SVG
    graphLine: document.getElementById('graph-line-path'),
    graphArea: document.getElementById('graph-area-path'),
    
    // Console
    consoleTerminal: document.getElementById('serial-terminal-logs'),
    consoleFilter: document.getElementById('console-filter'),
    btnClearConsole: document.getElementById('clear-console-btn'),
    btnExportLogs: document.getElementById('export-logs-btn'),
    
    // Config Form & Output
    formConfig: document.getElementById('config-settings-form'),
    cfgSda: document.getElementById('cfg-sda-pin'),
    cfgScl: document.getElementById('cfg-scl-pin'),
    cfgBuzzer: document.getElementById('cfg-buzzer-pin'),
    cfgLed: document.getElementById('cfg-led-pin'),
    cfgDeauthThresh: document.getElementById('cfg-deauth-threshold'),
    cfgSsid: document.getElementById('cfg-whitelist-ssid'),
    cfgBssid: document.getElementById('cfg-whitelist-bssid'),
    btnCompile: document.getElementById('compile-config-btn'),
    btnCopyConfig: document.getElementById('copy-config-btn'),
    configPreview: document.getElementById('config-code-preview'),
    
    // Circuit Wire Details
    circuitSvg: document.getElementById('interactive-circuit-svg'),
    wireInfoText: document.getElementById('circuit-wire-info-text')
};

// ==========================================
// 2. AUDIO SYNTHESIZER ENGINE (BUZZER)
// ==========================================
function initAudio() {
    if (audioCtx) return;
    
    // Initialize standard AudioContext
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    
    // Create oscillator (Square wave resembles cheap piezo)
    buzzerOsc = audioCtx.createOscillator();
    buzzerOsc.type = 'square';
    
    // Create gain control node for volume
    buzzerGain = audioCtx.createGain();
    buzzerGain.gain.setValueAtTime(0, audioCtx.currentTime); // Start silent
    
    // Connect routing
    buzzerOsc.connect(buzzerGain);
    buzzerGain.connect(audioCtx.destination);
    
    // Start oscillator
    buzzerOsc.start();
}

function startSirenSound(style) {
    if (state.audioMuted) return;
    initAudio();
    
    if (audioCtx.state === 'suspended') {
        audioCtx.resume();
    }
    
    // Clear any active audio timers
    if (alarmIntervalId) {
        clearInterval(alarmIntervalId);
        alarmIntervalId = null;
    }

    if (style === 'danger') {
        // High threat: Warble sweeping siren (sweeps frequency rapidly)
        let tickCount = 0;
        alarmIntervalId = setInterval(() => {
            if (state.audioMuted || !buzzerOsc) return;
            // Fluctuates tone between 1600Hz and 2200Hz
            const freq = 1600 + (tickCount % 2 === 0 ? 600 : 0);
            buzzerOsc.frequency.setValueAtTime(freq, audioCtx.currentTime);
            buzzerGain.gain.setValueAtTime(0.04, audioCtx.currentTime); // Soft volume
            tickCount++;
        }, 100);
    } 
    else if (style === 'warning') {
        // Medium threat: Pulsing beep double sweep every 2 seconds
        let phase = 0;
        alarmIntervalId = setInterval(() => {
            if (state.audioMuted || !buzzerOsc) return;
            const cycle = phase % 20; // 2-second cycle (100ms ticks)
            
            if (cycle === 0 || cycle === 3) {
                // Beep pulse
                buzzerOsc.frequency.setValueAtTime(1200, audioCtx.currentTime);
                buzzerGain.gain.setValueAtTime(0.04, audioCtx.currentTime);
            } else if (cycle === 1 || cycle === 4) {
                // Silent gap
                buzzerGain.gain.setValueAtTime(0, audioCtx.currentTime);
            } else if (cycle === 5) {
                // Final off
                buzzerGain.gain.setValueAtTime(0, audioCtx.currentTime);
            }
            phase++;
        }, 100);
    }
}

function stopSirenSound() {
    if (alarmIntervalId) {
        clearInterval(alarmIntervalId);
        alarmIntervalId = null;
    }
    if (buzzerGain && audioCtx) {
        buzzerGain.gain.setValueAtTime(0, audioCtx.currentTime);
    }
}

function toggleAudioMute() {
    state.audioMuted = !state.audioMuted;
    
    if (state.audioMuted) {
        el.sirenMuteStatus.textContent = 'MUTED (AUDIO OFF)';
        el.sirenMuteStatus.className = 'val text-muted';
        el.btnToggleSiren.textContent = 'Unmute Buzzer';
        stopSirenSound();
    } else {
        el.sirenMuteStatus.textContent = 'ACTIVE (AUDIO ON)';
        el.sirenMuteStatus.className = 'val text-secure';
        el.btnToggleSiren.textContent = 'Mute Buzzer';
        
        // Trigger sound if currently in alert state
        if (state.scenario === 'deauth' || state.scenario === 'dual') {
            startSirenSound('danger');
        } else if (state.scenario === 'eviltwin') {
            startSirenSound('warning');
        }
    }
    
    addConsoleLog('SYS', `Buzzer speaker audio ${state.audioMuted ? 'muted' : 'unmuted'}.`);
}

// ==========================================
// 3. SCENARIO TRIGGERS & CONTROLLERS
// ==========================================
function selectScenario(name) {
    // Clean up active sound sweepers
    stopSirenSound();
    
    state.scenario = name;
    
    // Remove active styles on all scenario buttons
    [el.btnNormal, el.btnTwin, el.btnDeauth, el.btnMulti].forEach(b => b.classList.remove('active'));
    el.lcdScreen.className = 'lcd-screen'; // Reset LCD class
    
    if (name === 'normal') {
        el.btnNormal.classList.add('active');
        state.threatLevel = 'zero';
        state.deauthRateSec = 0;
        state.lastOffendingMac = 'N/A';
        state.simTargetMac.textContent = 'N/A';
        
        el.statusGlow.className = 'glow-indicator';
        el.stateText.textContent = 'ARMED & SECURE';
        el.stateText.className = 'meta-value text-secure';
        el.threatLevelBadge.textContent = 'ZERO';
        el.threatLevelBadge.className = 'meta-value text-secure';
        
        addConsoleLog('OK', 'Security scan active. Environment stable.');
    } 
    else if (name === 'eviltwin') {
        el.btnTwin.classList.add('active');
        state.threatLevel = 'warning';
        state.deauthRateSec = 0;
        state.lastOffendingMac = 'A2:90:4F:7B:1C:E8';
        state.simTargetMac.textContent = 'ALL CLIENTS';
        el.lcdScreen.classList.add('warning-alert');
        
        el.statusGlow.className = 'glow-indicator warning-pulsing';
        el.stateText.textContent = 'EVIL TWIN DETECTED';
        el.stateText.className = 'meta-value text-warning';
        el.threatLevelBadge.textContent = 'WARN';
        el.threatLevelBadge.className = 'meta-value text-warning';
        
        startSirenSound('warning');
        addConsoleLog('WARN', `SYS,ALERT,EVIL_TWIN_DETECTED,${state.homeSsid},${state.lastOffendingMac}`);
    } 
    else if (name === 'deauth') {
        el.btnDeauth.classList.add('active');
        state.threatLevel = 'danger';
        state.deauthRateSec = 34; // Spike packets rate
        state.lastOffendingMac = 'EC:D0:9F:44:A2:18';
        state.simTargetMac.textContent = '54:14:E2:B0:1F:72';
        el.lcdScreen.classList.add('danger-alert');
        
        el.statusGlow.className = 'glow-indicator alarm-pulsing';
        el.stateText.textContent = 'DEAUTH FLOOD ACTIVE';
        el.stateText.className = 'meta-value text-danger';
        el.threatLevelBadge.textContent = 'CRIT';
        el.threatLevelBadge.className = 'meta-value text-danger';
        
        startSirenSound('danger');
        addConsoleLog('DANGER', `SYS,ALERT,DEAUTH_STORM_START,${state.deauthRateSec},${state.lastOffendingMac}`);
    } 
    else if (name === 'dual') {
        el.btnMulti.classList.add('active');
        state.threatLevel = 'danger';
        state.deauthRateSec = 48; // Peak spikes
        state.lastOffendingMac = 'FC:2D:E6:AA:3B:11';
        state.simTargetMac.textContent = 'MULTIPLE CLIENTS';
        el.lcdScreen.classList.add('danger-alert');
        
        el.statusGlow.className = 'glow-indicator alarm-pulsing';
        el.stateText.textContent = 'DUAL SEC VECTOR ATTACK';
        el.stateText.className = 'meta-value text-danger';
        el.threatLevelBadge.textContent = 'MAX_ALERT';
        el.threatLevelBadge.className = 'meta-value text-danger';
        
        startSirenSound('danger');
        addConsoleLog('DANGER', `SYS,ALERT,EVIL_TWIN_DETECTED,${state.homeSsid},${state.lastOffendingMac}`);
        addConsoleLog('DANGER', `SYS,ALERT,DEAUTH_STORM_START,${state.deauthRateSec},${state.lastOffendingMac}`);
    }
}

// ==========================================
// 4. PERIODIC SIMULATION TICKERS
// ==========================================

// Fast Ticker (hops channels, blinks status indicators)
function startFastTicker() {
    setInterval(() => {
        // Channel Hopping Logic (Pauses during network audits)
        if (state.channelHoppingActive) {
            state.currentChannel++;
            if (state.currentChannel > 13) {
                state.currentChannel = 1;
            }
            
            // Format and display channel values
            const channelStr = state.currentChannel < 10 ? '0' + state.currentChannel : state.currentChannel;
            el.channelDisplay.textContent = channelStr;
            el.activeHopDisplay.textContent = 'Ch ' + channelStr;
        }

        // ESP32 LED Indicators blink sequences
        if (state.threatLevel === 'zero') {
            // Safe: Slow periodic green blink, alarm red off
            const tick = Date.now() % 1500;
            if (tick < 200) {
                el.esp32StatusLed.classList.add('active');
            } else {
                el.esp32StatusLed.classList.remove('active');
            }
            el.esp32AlarmLed.classList.remove('active');
        } 
        else if (state.threatLevel === 'warning') {
            // Warning AP: Green led steady on, alarm led double pulse every 2s
            el.esp32StatusLed.classList.add('active');
            
            const tick = Date.now() % 2000;
            if ((tick > 0 && tick < 150) || (tick > 300 && tick < 450)) {
                el.esp32AlarmLed.classList.add('active');
            } else {
                el.esp32AlarmLed.classList.remove('active');
            }
        } 
        else if (state.threatLevel === 'danger') {
            // Active Deauth Attack: Green off, alarm led flashing rapidly (100ms)
            el.esp32StatusLed.classList.remove('active');
            
            const tick = Date.now() % 200;
            if (tick < 100) {
                el.esp32AlarmLed.classList.add('active');
            } else {
                el.esp32AlarmLed.classList.remove('active');
            }
        }
    }, 150); // Matches channel hop speed
}

// Slow Ticker (executes background tasks, parses graph coordinates)
function startSlowTicker() {
    setInterval(() => {
        const time = Date.now();

        // 1. Manage Active Scan timers (Every 10 seconds in simulation)
        state.scanTimer--;
        if (state.scanTimer <= 0) {
            triggerBackgroundScan();
            state.scanTimer = 10;
        }

        // 2. Adjust deauth rates in real-time based on active vectors
        if (state.scenario === 'deauth') {
            // Introduce subtle variations to make graph feel alive
            state.deauthRateSec = Math.floor(25 + Math.random() * 15);
            state.totalDeauths += state.deauthRateSec;
        } else if (state.scenario === 'dual') {
            state.deauthRateSec = Math.floor(40 + Math.random() * 20);
            state.totalDeauths += state.deauthRateSec;
        } else {
            state.deauthRateSec = 0;
        }

        // 3. Update stats displays
        el.deauthRateDisplay.textContent = state.deauthRateSec;
        el.totalDeauthDisplay.textContent = state.totalDeauths;

        // 4. Update Graphic Waveform History
        state.chartHistory.push(state.deauthRateSec);
        state.chartHistory.shift();
        drawTelemetryGraph();

        // 5. Stream STATS lines to console
        const levelCode = state.threatLevel === 'zero' ? 0 : (state.threatLevel === 'warning' ? 1 : 2);
        addConsoleLog('SYS', `STATS,${time},${state.deauthRateSec},${state.totalDeauths},${levelCode},${state.currentChannel}`);

        // 6. Update virtual 20x4 LCD screen contents
        renderVirtualLcd();

    }, 1000);
}

// ==========================================
// 5. SIMULATED BACKGROUND SCAN ROUTINES
// ==========================================
function triggerBackgroundScan() {
    if (state.scenario === 'deauth') return; // Bypass scan during intensive flood attacks
    
    state.channelHoppingActive = false;
    el.scannerBadge.textContent = 'SCANNING...';
    el.scannerBadge.className = 'badge text-warning';
    
    addConsoleLog('SYS', 'SYS,SCAN_START,Pausing sniffer to scan standard networks...');
    
    // Simulate short network scan lag
    setTimeout(() => {
        state.channelHoppingActive = true;
        el.scannerBadge.textContent = 'HOPPING...';
        el.scannerBadge.className = 'badge badge-pulse';
        
        const apsFound = 4 + Math.floor(Math.random() * 3);
        addConsoleLog('SYS', `SYS,SCAN_END,Scanned ${apsFound} active Access Points.`);
        
        // Log standard surrounding networks
        addConsoleLog('AP', 'AP,Office_WiFi_Regular,00:1E:5A:F4:D2:C1,-72,3,1');
        addConsoleLog('AP', 'AP,Guest_Airport_Zone,14:CC:20:AA:99:5B,-81,0,11');
        addConsoleLog('AP', `AP,${state.homeSsid},${state.homeBssid},-44,4,6`);

        if (state.scenario === 'eviltwin' || state.scenario === 'dual') {
            // Inject rogue twin MAC during malicious scenarios
            addConsoleLog('AP', `AP,${state.homeSsid},${state.lastOffendingMac},-35,0,6`); // downgraded to open (0) and closer (-35 RSSI)
            addConsoleLog('DANGER', `SYS,ALERT,EVIL_TWIN_DETECTED,${state.homeSsid},${state.lastOffendingMac}`);
        }

    }, 800);
}

// ==========================================
// 6. VIRTUAL LCD RENDERER
// ==========================================
function renderVirtualLcd() {
    const chStr = state.currentChannel < 10 ? '0' + state.currentChannel : state.currentChannel;

    if (state.scenario === 'normal') {
        el.lcdLines[0].textContent = '=== WIRELESS SHIELD ===';
        el.lcdLines[1].textContent = 'SYSTEM SECURE    ';
        el.lcdLines[2].textContent = `Ch Sniffer: [${chStr}]    `;
        el.lcdLines[3].textContent = `Deauth/s: 0   CUM:${state.totalDeauths}`;
    } 
    else if (state.scenario === 'eviltwin') {
        el.lcdLines[0].textContent = '[!] WARNING [!]     ';
        el.lcdLines[1].textContent = 'EVIL TWIN AP DETECTD';
        el.lcdLines[2].textContent = `SSID: ${state.homeSsid.substring(0, 14)}`;
        el.lcdLines[3].textContent = `MAC: ${state.lastOffendingMac.substring(0, 15)}`;
    } 
    else if (state.scenario === 'deauth') {
        el.lcdLines[0].textContent = '!!! ALERT STORM !!! ';
        el.lcdLines[1].textContent = 'DEAUTH ATTACK ACTIVE';
        el.lcdLines[2].textContent = `M: ${state.lastOffendingMac.substring(0, 17)}`;
        el.lcdLines[3].textContent = `Pkts: ${state.deauthRateSec}/s  TOT:${state.totalDeauths}`;
    } 
    else if (state.scenario === 'dual') {
        el.lcdLines[0].textContent = '!! HYBRID ATTACK !! ';
        el.lcdLines[1].textContent = 'DEAUTH & ROGUE AP   ';
        el.lcdLines[2].textContent = `M: ${state.lastOffendingMac.substring(0, 17)}`;
        el.lcdLines[3].textContent = `Storm: ${state.deauthRateSec}/s Pkts`;
    }
}

// ==========================================
// 7. TELEMETRY GRAPH PLOTTER (SVG)
// ==========================================
function drawTelemetryGraph() {
    const width = 600;
    const height = 150;
    const padding = 10;
    
    const count = state.chartHistory.length;
    
    // Find max value in history to scale graph dynamically (min scale = 20 pkts)
    const maxVal = Math.max(20, ...state.chartHistory);
    
    let points = [];
    for (let i = 0; i < count; i++) {
        // Calculate X: spaced evenly across graph width
        const x = (i / (count - 1)) * width;
        // Calculate Y: flipped (SVG y=0 is top) and scaled to height
        const val = state.chartHistory[i];
        const y = height - padding - ((val / maxVal) * (height - 2 * padding));
        points.push(`${x},${y}`);
    }
    
    // Update SVG Line path
    const pathD = 'M ' + points.join(' L ');
    el.graphLine.setAttribute('d', pathD);
    
    // Update SVG Fill Area path (closes loop to bottom corner lines)
    const areaD = `${pathD} L ${width},${height} L 0,${height} Z`;
    el.graphArea.setAttribute('d', areaD);
}

// ==========================================
// 8. LOG CONSOLE CONTROLLER
// ==========================================
function addConsoleLog(type, message) {
    // Filter and add log values
    const logTime = new Date().toLocaleTimeString();
    let formattedText = `[${logTime}] ${message}`;
    let logClass = 'sys-log';
    
    if (type === 'OK') logClass = 'ok-log';
    else if (type === 'WARN') logClass = 'warn-log';
    else if (type === 'DANGER') logClass = 'danger-log';
    else if (type === 'AP') logClass = 'ap-log';

    // Store in global memory (for export)
    state.logs.push(formattedText);
    if (state.logs.length > 200) {
        state.logs.shift();
    }

    // Append element to log window
    const logDiv = document.createElement('div');
    logDiv.className = `log-entry ${logClass}`;
    logDiv.textContent = formattedText;
    
    el.consoleTerminal.appendChild(logDiv);
    
    // Apply search filters dynamically
    applyConsoleFilterSingle(logDiv);

    // Scroll to bottom
    el.consoleTerminal.scrollTop = el.consoleTerminal.scrollHeight;
}

function applyConsoleFilters() {
    const filterText = el.consoleFilter.value.toUpperCase();
    const entries = el.consoleTerminal.getElementsByClassName('log-entry');
    
    Array.from(entries).forEach(entry => {
        if (entry.textContent.toUpperCase().includes(filterText)) {
            entry.style.display = 'block';
        } else {
            entry.style.display = 'none';
        }
    });
}

function applyConsoleFilterSingle(divNode) {
    const filterText = el.consoleFilter.value.toUpperCase();
    if (divNode.textContent.toUpperCase().includes(filterText)) {
        divNode.style.display = 'block';
    } else {
        divNode.style.display = 'none';
    }
}

function clearConsoleLogs() {
    el.consoleTerminal.innerHTML = '';
    state.logs = [];
    addConsoleLog('OK', 'Serial output buffer cleared.');
}

function exportConsoleLogs() {
    if (state.logs.length === 0) return;
    
    const blob = new Blob([state.logs.join('\n')], { type: 'text/plain;charset=utf-8' });
    const blobUrl = URL.createObjectURL(blob);
    
    const link = document.createElement('a');
    link.href = blobUrl;
    link.download = `esp32_security_shield_logs_${Date.now()}.txt`;
    
    document.body.appendChild(link);
    link.click();
    
    document.body.removeChild(link);
    URL.revokeObjectURL(blobUrl);
    
    addConsoleLog('OK', 'Exported serial logs successfully.');
}

// ==========================================
// 9. DYNAMIC C++ config.h GENERATOR
// ==========================================
function compileCustomConfig() {
    // Pull form parameters
    const sda = parseInt(el.cfgSda.value) || 21;
    const scl = parseInt(el.cfgScl.value) || 22;
    const buzzer = parseInt(el.cfgBuzzer.value) || 13;
    const led = parseInt(el.cfgLed.value) || 12;
    const thresh = parseInt(el.cfgDeauthThresh.value) || 5;
    
    const ssid = el.cfgSsid.value.replace(/["\\]/g, '\\$&') || "MyHomeNetwork_5G";
    const bssid = el.cfgBssid.value.trim().toUpperCase() || "";
    
    // Save to active whitelists in frontend simulator
    state.homeSsid = el.cfgSsid.value || "MyHomeNetwork_5G";
    state.homeBssid = bssid || "AA:BB:CC:11:22:33";

    // Validate MAC structure if entered
    let bssidLine = `    {"${ssid}", NULL, 4}`;
    if (bssid !== "") {
        const macRegex = /^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$/;
        if (!macRegex.test(bssid)) {
            alert("Invalid MAC address syntax. Please use format AA:BB:CC:11:22:33 or leave blank.");
            return;
        }
        bssidLine = `    {"${ssid}", "${bssid}", 4}`;
    }

    // Construct customizable C++ config content
    const code = `/**
 * Generated config.h - Custom Configuration File
 * Copy and save this file inside your esp32_wifi_monitor/ directory!
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <Arduino.h>

// 1. HARDWARE PIN OUTS
#define LCD_I2C_ADDR      0x27
#define LCD_COLUMNS       20
#define LCD_ROWS          4

#define I2C_SDA_PIN       ${sda}
#define I2C_SCL_PIN       ${scl}

#define BUZZER_PIN        ${buzzer}
#define ALERT_LED_PIN     ${led}
#define STATUS_LED_PIN    14

// 2. DETECTION THRESHOLDS
#define CHANNEL_HOP_INTERVAL_MS   150
#define DEAUTH_ALERT_THRESHOLD     ${thresh}
#define THREAT_COOLDOWN_MS      5000
#define BG_SCAN_INTERVAL_MS    30000
#define RSSI_VARIANCE_LIMIT       25

// 3. TRUSTED NETWORKS WHITELIST
struct TrustedNetwork {
    const char* ssid;
    const char* bssid;
    int authMode;
};

const TrustedNetwork TRUSTED_NETWORKS[] = {
${bssidLine},
    {"Office_WiFi_Regular", NULL, 3}
};

#define TRUSTED_NETWORKS_COUNT (sizeof(TRUSTED_NETWORKS) / sizeof(TRUSTED_NETWORKS[0]))

// 4. PROTOCOL REFERENCE VALUES
#define FRAME_TYPE_MANAGEMENT      0x00
#define SUBTYPE_DISASSOCIATION     0x0A
#define SUBTYPE_DEAUTHENTICATION   0x0C

#endif // CONFIG_H`;

    el.configPreview.textContent = code;
    addConsoleLog('OK', 'Recompiled C++ firmware configuration profile.');
}

function copyConfigToClipboard() {
    const codeText = el.configPreview.textContent;
    if (codeText.includes('Click "Compile')) return;
    
    navigator.clipboard.writeText(codeText)
        .then(() => {
            el.btnCopyConfig.textContent = "Copied!";
            setTimeout(() => {
                el.btnCopyConfig.textContent = "Copy Code";
            }, 2000);
            addConsoleLog('OK', 'Copied firmware config profile to OS clipboard.');
        })
        .catch(err => {
            console.error("Clipboard copy failed: ", err);
        });
}

// ==========================================
// 10. INTERACTIVE CIRCUIT SCHEMATIC HOVER
// ==========================================
const circuitData = {
    'wire-gnd': {
        title: 'Common Ground Wire (Black)',
        desc: 'Returns current from all peripherals back to the ESP32 GND pin. Ensures a unified ground reference plane across modules.'
    },
    'wire-vcc': {
        title: '5V VCC Power Rail (Red)',
        desc: 'Supplies 5V electrical power from the ESP32 VIN/5V pin directly to the I2C LCD screen. Critical for driving the LCD fluorescent backlight.'
    },
    'wire-sda': {
        title: 'I2C SDA - Data Connection (Yellow)',
        desc: 'Serial Data line connecting ESP32 GPIO pin 21 to the LCD display PCF8574 backpack. Operates as the bidirectional channel for display byte packets.'
    },
    'wire-scl': {
        title: 'I2C SCL - Clock Reference (Orange)',
        desc: 'Serial Clock line connecting ESP32 GPIO pin 22 to the LCD screen PCF8574 backpack. Provides synched clock signals driven by the master micro-controller.'
    },
    'wire-buzzer': {
        title: 'GPIO 13 - Buzzer Driver Wire (Blue)',
        desc: 'Bridges ESP32 GPIO 13 to the positive pole of the Piezoelectric speaker. Drives PWM audio sweeps to make security alarms audible.'
    },
    'wire-led-alert': {
        title: 'GPIO 12 - Red Alarm LED Wire (Purple)',
        desc: 'Connects ESP32 GPIO 12 anode line to the Red alert indicator, passing through a current-limiting resistor to protect the circuit.'
    },
    'wire-led-status': {
        title: 'GPIO 14 - Green Status LED Wire (Green)',
        desc: 'Connects ESP32 GPIO 14 anode line to the Green status indicator, providing stable pulses when scanning operations are secure.'
    },
    'comp-esp32': {
        title: 'ESP32 NodeMCU Module Controller',
        desc: 'Core micro-controller compiling logic. Pinned on Core 0 to hop channels and capture raw 802.11 packets, and Core 1 to scan networks and sound alarms.'
    },
    'comp-lcd': {
        title: 'I2C Liquid Crystal LCD Module',
        desc: '20x4 visual screen panel with custom PCF8574 backpack, which converts 2-wire serial I2C bus streams into full character matrix readouts.'
    },
    'comp-buzzer': {
        title: 'Piezoelectric Audio Speaker',
        desc: 'Transducer device designed to convert electrical oscillations into localized high-intensity siren tones.'
    },
    'comp-leds': {
        title: 'Alert & Status LED Diodes',
        desc: 'Bipolar indicators reflecting real-time danger scales: solid green for normal secure states, pulsing green for scans, and fast red strobes for storms.'
    }
};

function initCircuitInteractivity() {
    // Query wiring elements in SVG
    const wires = el.circuitSvg.querySelectorAll('.circuit-wire');
    const nodes = el.circuitSvg.querySelectorAll('.circuit-node');

    function highlightElement(id, active) {
        const item = document.getElementById(id);
        if (!item) return;

        if (active) {
            item.classList.add('highlighted');
            const data = circuitData[id];
            if (data) {
                el.wireInfoText.innerHTML = `<strong>${data.title}</strong><br>${data.desc}`;
                el.wireInfoText.parentElement.style.borderColor = 'var(--color-cyan)';
            }
        } else {
            item.classList.remove('highlighted');
            el.wireInfoText.innerHTML = 'Hover over any wire path, LED, or component module above to display detailed wiring and connection details.';
            el.wireInfoText.parentElement.style.borderColor = 'var(--color-border)';
        }
    }

    // Attach listeners to path wires
    wires.forEach(wire => {
        const id = wire.getAttribute('id');
        wire.addEventListener('mouseenter', () => highlightElement(id, true));
        wire.addEventListener('mouseleave', () => highlightElement(id, false));
    });

    // Attach listeners to hardware component group tags
    nodes.forEach(node => {
        const id = node.getAttribute('id');
        node.addEventListener('mouseenter', () => highlightElement(id, true));
        node.addEventListener('mouseleave', () => highlightElement(id, false));
    });
}

// ==========================================
// 11. BIND EVENT LISTENERS
// ==========================================
function bindEventHandlers() {
    // Scenario Buttons
    el.btnNormal.addEventListener('click', () => selectScenario('normal'));
    el.btnTwin.addEventListener('click', () => selectScenario('eviltwin'));
    el.btnDeauth.addEventListener('click', () => selectScenario('deauth'));
    el.btnMulti.addEventListener('click', () => selectScenario('dual'));

    // Siren Audio Muter
    el.btnToggleSiren.addEventListener('click', toggleAudioMute);

    // Console buttons
    el.consoleFilter.addEventListener('input', applyConsoleFilters);
    el.btnClearConsole.addEventListener('click', clearConsoleLogs);
    el.btnExportLogs.addEventListener('click', exportConsoleLogs);

    // Form compilers
    el.btnCompile.addEventListener('click', compileCustomConfig);
    el.btnCopyConfig.addEventListener('click', copyConfigToClipboard);
}

// ==========================================
// 12. RUN CRON ENGINE
// ==========================================
document.addEventListener('DOMContentLoaded', () => {
    // Bind interactions
    bindEventHandlers();
    
    // Init SVG circuit actions
    initCircuitInteractivity();

    // Compile initial config code preview
    compileCustomConfig();

    // Start simulation loops
    startFastTicker();
    startSlowTicker();

    addConsoleLog('OK', 'Security scanning sandbox initialized.');
    addConsoleLog('SYS', 'Standard 115200 Baud serial interface established.');
});
