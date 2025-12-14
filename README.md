# iOSRASPManager

**Swift Package Manager** • **MIT License**

Production-grade iOS Runtime Application Self-Protection (RASP) library. Detects debuggers, code tampering, runtime manipulation, and network interception with App Store-safe APIs and thread-safe actor isolation.

<div align="center">

![Swift](https://img.shields.io/badge/Swift-5.9+-orange.svg)
![Platform](https://img.shields.io/badge/Platform-iOS14+-blue.svg)
![Xcode](https://img.shields.io/badge/Xcode-15.0+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

</div>

## Documentation

Find full documentation [here](https://jcentercreation.github.io/iOSRASPManager/documentation/iosraspmanager/)

## Overview

Key features include:

- **Debugger Detection**: `P_TRACED` flag via `sysctl` (Xcode, LLDB)
- **Code Integrity**: SHA256 hashing of Mach-O critical sections vs Keychain baseline
- **Runtime Analysis**: Timing attacks detecting Frida/Objection overhead
- **Network Protection**: System HTTP/HTTPS proxy detection (Charles, Burp)
- **Actor isolation**: 100% thread-safe async API
- **No external dependencies**: Pure Foundation + CryptoKit + Darwin
- **Performance**: <15ms total across all checks

## Requirements

| Platform | Minimum Version |
|----------|-----------------|
| iOS | 14.0+ |
| Xcode | 15.0+ |
| Swift | 5.9+ |

## Installation

### Swift Package Manager

Add to `Package.swift`:
```swift
dependencies: .package(url: “https://github.com/jcentercreation/iOSRASPManager.git”, from: “1.0.0”)
```


### Xcode

1. File → Add Package Dependencies
2. Enter package URL: `https://github.com/jcentercreation/iOSRASPManager.git`
3. Select version rule: "Up to Next Major Version"

## Usage

### Basic Threat Scanning
```swift
import iOSRASPManager
let rasp = iOSRASPManager.shared
Task {
  // Debugger check
  if let debuggerThreat = await rasp.checkDebuggerAttachment() {
    print(“🚨 CRITICAL: $$debuggerThreat.type)”) // Terminate immediately
  }

  // Code integrity
  if let codeThreat = await rasp.checkCodeIntegrity(logger: logger) {
      print("🚨 CRITICAL: $$codeThreat.type)")
      // Wipe sensitive data
  }
  
  // Network proxies
  if let proxyThreat = await rasp.checkNetworkInterception() {
      print("🚨 Proxy: $$proxyThreat.details["proxies"] ?? [])")
      // Disable network features
  }
}
```

## Detection Methods

### Core Checks (4 methods)

| Method | Threat Type | Level | Performance |
|--------|-------------|-------|-------------|
| `checkDebuggerAttachment()` | `debugger_attachment` | **critical** | 0.5ms |
| `checkCodeIntegrity(logger:)` | `code_integrity_violation` | **critical** | 10ms |
| `checkRuntimeManipulation()` | `runtime_manipulation` | **high** | 5ms |
| `checkNetworkInterception()` | `network_interception` | **medium** | 0.1ms |

### ThreatDetection Structure
```swift
public struct ThreatDetection {
  public let type: String           // “debugger_attachment”
  public let level: ThreatLevel     // .critical, .high, .medium, .zero
  public let timeStamp: Date        // Detection moment
   public let details: String: Any // Rich context
}
```

## Threat Response Strategy

| Level | Action |
|-------|--------|
| `.critical` | **Terminate immediately** |
| `.high` | Disable sensitive features |
| `.medium` | Rate-limit + telemetry |
| `.low` | Log + monitor |

## What It Detects
✅ Xcode/LLDB debugger (P_TRACED flag)
✅ Binary patching (Mach-O hash mismatch) 
✅ Frida/Objection (timing slowdown >100ms)
✅ Charles/Burp/mitmproxy (system proxies)

## Security & Compliance

✅ **App Store Safe**: Public APIs only (`sysctl`, `CFNetwork`, Keychain)  
✅ **No entitlements**: Works in sandbox  
✅ **Thread-safe**: Actor isolation  
✅ **Persistent**: Keychain baseline survives restarts  
🔒 **Low footprint**: 5MB peak (code integrity)  
⚠️ **Bypassable**: Advanced attackers/root

## License

MIT License © 2025 Javier Carrillo

<div align="center">

**Made for iOS Development**  
**Deploy responsibly for threat detection only.**

[⬆ Back to Top](#iOSRASPManager)

</div>
