//! Source adapters — the [`CsiSource`] plugin trait (ADR-095 D15) plus the
//! [`AdapterProfile`] capability descriptor and [`SourceConfig`] open params.

use serde::{Deserialize, Serialize};

use crate::error::RvcsiError;
use crate::frame::CsiFrame;
use crate::ids::SessionId;

/// Which family of source produced a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AdapterKind {
    /// A recorded `.rvcsi` capture file.
    File,
    /// Deterministic replay of a capture session.
    Replay,
    /// Nexmon CSI (via the isolated C shim).
    Nexmon,
    /// ESP32 CSI over serial/UDP.
    Esp32,
    /// Intel `iwlwifi` CSI tool logs.
    Intel,
    /// Atheros CSI tool logs.
    Atheros,
    /// An in-memory / synthetic source (tests, simulation).
    Synthetic,
}

impl AdapterKind {
    /// Stable lower-case slug (`"file"`, `"nexmon"`, ...).
    pub fn slug(self) -> &'static str {
        match self {
            AdapterKind::File => "file",
            AdapterKind::Replay => "replay",
            AdapterKind::Nexmon => "nexmon",
            AdapterKind::Esp32 => "esp32",
            AdapterKind::Intel => "intel",
            AdapterKind::Atheros => "atheros",
            AdapterKind::Synthetic => "synthetic",
        }
    }
}

impl core::fmt::Display for AdapterKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.slug())
    }
}

/// Capability descriptor for a source — used by validation to bound frames and
/// by health checks to flag unsupported firmware/driver state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterProfile {
    /// Adapter family.
    pub adapter_kind: AdapterKind,
    /// Radio chip, if known (`"BCM43455c0"`, `"ESP32-S3"`, ...).
    pub chip: Option<String>,
    /// Firmware version string, if known.
    pub firmware_version: Option<String>,
    /// Driver version string, if known.
    pub driver_version: Option<String>,
    /// Channels the source can capture on.
    pub supported_channels: Vec<u16>,
    /// Bandwidths (MHz) the source supports.
    pub supported_bandwidths_mhz: Vec<u16>,
    /// Subcarrier counts the source is expected to emit (e.g. `[52, 56, 114, 234]`).
    pub expected_subcarrier_counts: Vec<u16>,
    /// Whether live capture is possible (false for files/replay).
    pub supports_live_capture: bool,
    /// Whether frame injection is possible.
    pub supports_injection: bool,
    /// Whether monitor mode is available.
    pub supports_monitor_mode: bool,
}

impl AdapterProfile {
    /// A permissive profile for file/replay/synthetic sources: any channel,
    /// any bandwidth, any subcarrier count, no live capabilities.
    pub fn offline(adapter_kind: AdapterKind) -> Self {
        AdapterProfile {
            adapter_kind,
            chip: None,
            firmware_version: None,
            driver_version: None,
            supported_channels: Vec::new(),
            supported_bandwidths_mhz: Vec::new(),
            expected_subcarrier_counts: Vec::new(),
            supports_live_capture: false,
            supports_injection: false,
            supports_monitor_mode: false,
        }
    }

    /// A typical ESP32-S3 HT20 CSI profile (192 raw subcarriers on HT40,
    /// 64 on HT20 — both listed; channels 1–13, 2.4 GHz).
    pub fn esp32_default() -> Self {
        AdapterProfile {
            adapter_kind: AdapterKind::Esp32,
            chip: Some("ESP32-S3".to_string()),
            firmware_version: None,
            driver_version: None,
            supported_channels: (1..=13).collect(),
            supported_bandwidths_mhz: vec![20, 40],
            expected_subcarrier_counts: vec![64, 128, 192],
            supports_live_capture: true,
            supports_injection: false,
            supports_monitor_mode: false,
        }
    }

    /// A typical Nexmon (BCM43455c0) CSI profile: 802.11ac, 20/40/80 MHz.
    pub fn nexmon_default() -> Self {
        AdapterProfile {
            adapter_kind: AdapterKind::Nexmon,
            chip: Some("BCM43455c0".to_string()),
            firmware_version: None,
            driver_version: None,
            supported_channels: vec![1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161],
            supported_bandwidths_mhz: vec![20, 40, 80],
            expected_subcarrier_counts: vec![64, 128, 256],
            supports_live_capture: true,
            supports_injection: true,
            supports_monitor_mode: true,
        }
    }

    /// `true` if `count` is acceptable for this profile (always true when the
    /// expected list is empty, e.g. offline sources).
    pub fn accepts_subcarrier_count(&self, count: u16) -> bool {
        self.expected_subcarrier_counts.is_empty()
            || self.expected_subcarrier_counts.contains(&count)
    }

    /// `true` if `channel` is acceptable (always true when the list is empty).
    pub fn accepts_channel(&self, channel: u16) -> bool {
        self.supported_channels.is_empty() || self.supported_channels.contains(&channel)
    }
}

/// Health snapshot for a source (returned by [`CsiSource::health`] and the
/// `rvcsi health` CLI / `rvcsi_health_report` MCP tool).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceHealth {
    /// `true` while the source is producing frames.
    pub connected: bool,
    /// Frames delivered since the session started.
    pub frames_delivered: u64,
    /// Frames rejected by validation since the session started.
    pub frames_rejected: u64,
    /// Optional human-readable status / last error.
    pub status: Option<String>,
}

impl SourceHealth {
    /// A "just opened, nothing yet" snapshot.
    pub fn fresh(connected: bool) -> Self {
        SourceHealth {
            connected,
            frames_delivered: 0,
            frames_rejected: 0,
            status: None,
        }
    }
}

/// Parameters for opening a source (mirrors the TS SDK `RvCsi.open(...)` shape).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceConfig {
    /// Source slug: `"file"`, `"replay"`, `"nexmon"`, `"esp32"`, `"intel"`, `"atheros"`.
    pub source: String,
    /// Network interface (`"wlan0"`), serial port (`"/dev/ttyUSB0"`), or file path.
    #[serde(default)]
    pub target: Option<String>,
    /// WiFi channel (live sources only).
    #[serde(default)]
    pub channel: Option<u16>,
    /// Bandwidth in MHz (live sources only).
    #[serde(default)]
    pub bandwidth_mhz: Option<u16>,
    /// Replay speed multiplier (`1.0` = real time); replay source only.
    #[serde(default)]
    pub replay_speed: Option<f32>,
    /// Free-form adapter-specific options.
    #[serde(default)]
    pub options_json: Option<String>,
}

impl SourceConfig {
    /// Build a config for the given source slug with no other options set.
    pub fn new(source: impl Into<String>) -> Self {
        SourceConfig {
            source: source.into(),
            target: None,
            channel: None,
            bandwidth_mhz: None,
            replay_speed: None,
            options_json: None,
        }
    }

    /// Builder: set the target (iface/port/path).
    pub fn target(mut self, t: impl Into<String>) -> Self {
        self.target = Some(t.into());
        self
    }

    /// Builder: set the channel.
    pub fn channel(mut self, c: u16) -> Self {
        self.channel = Some(c);
        self
    }

    /// Builder: set the bandwidth.
    pub fn bandwidth_mhz(mut self, b: u16) -> Self {
        self.bandwidth_mhz = Some(b);
        self
    }
}

/// The plugin trait every CSI source implements.
///
/// Object-safe so the runtime can hold `Box<dyn CsiSource>`. Adapters produce
/// frames with `validation = Pending`; the runtime runs [`crate::validate_frame`]
/// before exposing anything.
pub trait CsiSource: Send {
    /// The source's capability descriptor.
    fn profile(&self) -> &AdapterProfile;

    /// The capture session id this source is bound to.
    fn session_id(&self) -> SessionId;

    /// Stable source id for logs / RuVector records.
    fn source_id(&self) -> &crate::ids::SourceId;

    /// Pull the next frame. `Ok(None)` signals end-of-stream (file exhausted,
    /// replay finished). Live sources block until a frame is available or
    /// return an [`RvcsiError::Adapter`] on disconnect.
    fn next_frame(&mut self) -> Result<Option<CsiFrame>, RvcsiError>;

    /// Current health snapshot.
    fn health(&self) -> SourceHealth;

    /// Stop the source and release resources. Default: no-op.
    fn stop(&mut self) -> Result<(), RvcsiError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_profile_accepts_anything() {
        let p = AdapterProfile::offline(AdapterKind::File);
        assert!(p.accepts_subcarrier_count(57));
        assert!(p.accepts_channel(999));
        assert!(!p.supports_live_capture);
    }

    #[test]
    fn esp32_profile_bounds() {
        let p = AdapterProfile::esp32_default();
        assert!(p.accepts_subcarrier_count(64));
        assert!(!p.accepts_subcarrier_count(57));
        assert!(p.accepts_channel(6));
        assert!(!p.accepts_channel(36));
        assert!(p.supports_live_capture);
    }

    #[test]
    fn source_config_builder() {
        let c = SourceConfig::new("nexmon").target("wlan0").channel(6).bandwidth_mhz(20);
        assert_eq!(c.source, "nexmon");
        assert_eq!(c.target.as_deref(), Some("wlan0"));
        assert_eq!(c.channel, Some(6));
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(serde_json::from_str::<SourceConfig>(&json).unwrap(), c);
    }

    #[test]
    fn adapter_kind_slug_display() {
        assert_eq!(AdapterKind::Nexmon.slug(), "nexmon");
        assert_eq!(AdapterKind::Esp32.to_string(), "esp32");
    }

    #[test]
    fn health_fresh() {
        let h = SourceHealth::fresh(true);
        assert!(h.connected);
        assert_eq!(h.frames_delivered, 0);
    }
}
