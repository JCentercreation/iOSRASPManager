//
//  ThreatDetection.swift
//  iOSRASPManager

import Foundation

/// Immutable value type representing a detected security threat in the iOS RASP system.
///
/// Encapsulates all essential threat information including type classification, severity level,
/// detection timestamp, and contextual details. Designed for structured logging, telemetry,
/// and automated threat response workflows.
///
/// ## Properties
///
/// - **type**: Unique threat identifier (snake_case convention).
///   - `"debugger_attachment"`
///   - `"code_integrity_violation"`
///   - `"runtime_manipulation"`
///   - `"network_interception"`
///
/// - **level**: Severity classification using `ThreatLevel` enum.
///   - Recommended response actions:
///     | Level     | Action                  |
///     |-----------|-------------------------|
///     | `.low`    | Log + monitor           |
///     | `.medium` | Rate-limit + telemetry  |
///     | `.high`   | Disable sensitive ops   |
///     | `.critical` | **Terminate immediately** |
///
/// - **timeStamp**: Exact `Date` when threat was detected (high-precision forensics).
///
/// - **details**: Rich contextual dictionary. Common keys:
///   ```
///   {
///     "p_flag": 1234,
///     "timing_anomaly_ms": "152.34",
///     "proxies": ["HTTP: 192.168..."],
///     "expected_hash": "a1b2c3...",
///     "actual_hash": "x9y8z7...",
///     "pid": 1234,
///     "count": 2
///   }
///   ```
///
/// ## Usage Examples
///
/// ```
/// // Debugger threat
/// ThreatDetection(
///     type: "debugger_attachment",
///     level: .critical,
///     timeStamp: Date(),
///     details: ["p_flag": 0x800]
/// )
///
/// // Proxy interception
/// ThreatDetection(
///     type: "network_interception",
///     level: .medium,
///     timeStamp: Date(),
///     details: ["proxies": ["HTTP: 192.168..."]]
/// )
/// ```
public struct ThreatDetection {
    public let type: String
    public let level: ThreatLevel
    public let timeStamp: Date
    public let details: [String: Any]
}
