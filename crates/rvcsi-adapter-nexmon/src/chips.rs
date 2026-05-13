//! The Nexmon-supported Broadcom chip registry and Raspberry Pi model map
//! (ADR-095 D15, ADR-096) — including the **Raspberry Pi 5**.
//!
//! nexmon_csi runs on a handful of patched Broadcom/Cypress chips. This module
//! names them ([`NexmonChip`]), maps Raspberry Pi models to their chip
//! ([`RaspberryPiModel`]), resolves the on-the-wire `chip_ver` word back to a
//! chip (best-effort — the raw value is always preserved), and builds a
//! [`rvcsi_core::AdapterProfile`] (supported channels / bandwidths / expected
//! subcarrier counts) for each — so `validate_frame` can bound CSI frames
//! against the device that produced them.
//!
//! The Raspberry Pi 5 carries the same **CYW43455 (BCM43455c0)** 802.11ac
//! wireless as the Pi 3B+ / Pi 4 / Pi 400 — the chip with the most mature
//! nexmon_csi support — so Pi 5 CSI captures use the [`NexmonChip::Bcm43455c0`]
//! profile (20/40/80 MHz, 64/128/256 subcarriers, 2.4 + 5 GHz). The chip is also
//! auto-detected at runtime from each frame's `chip_ver` (see
//! [`crate::NexmonPcapAdapter`]).

use rvcsi_core::{AdapterKind, AdapterProfile};

/// A Broadcom/Cypress WiFi chip nexmon_csi is known to run on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NexmonChip {
    /// BCM43455c0 / CYW43455 — 802.11ac, 2.4 + 5 GHz, 20/40/80 MHz. The
    /// flagship nexmon_csi target: **Raspberry Pi 3B+, Pi 4, Pi 400 and Pi 5**,
    /// plus the Pi Zero W. Modern int16 I/Q CSI export.
    Bcm43455c0,
    /// BCM43436b0 — 802.11n, 2.4 GHz only, 20/40 MHz. Raspberry Pi Zero 2 W.
    Bcm43436b0,
    /// BCM4366c0 — 802.11ac, 2.4 + 5 GHz, up to 80 MHz. ASUS RT-AC86U. Modern int16 export.
    Bcm4366c0,
    /// BCM4375b1 — 802.11ax-class, 2.4 + 5 GHz. Some Samsung Galaxy S10/S20.
    Bcm4375b1,
    /// BCM4358 — 802.11ac. Nexus 6P (and similar). Some firmwares use the legacy
    /// packed-float CSI export (see [`NexmonChip::uses_int16_iq`]).
    Bcm4358,
    /// BCM4339 — 802.11ac. Nexus 5. Legacy packed-float CSI export.
    Bcm4339,
    /// A chip we don't recognise — the raw `chip_ver` word from the packet.
    Unknown {
        /// The `chip_ver` word as it appeared on the wire.
        chip_ver: u16,
    },
}

impl NexmonChip {
    /// Stable lower-case slug (`"bcm43455c0"`, `"bcm4366c0"`, ...; `"unknown:0xNNNN"` for [`NexmonChip::Unknown`]).
    pub fn slug(self) -> String {
        match self {
            NexmonChip::Bcm43455c0 => "bcm43455c0".to_string(),
            NexmonChip::Bcm43436b0 => "bcm43436b0".to_string(),
            NexmonChip::Bcm4366c0 => "bcm4366c0".to_string(),
            NexmonChip::Bcm4375b1 => "bcm4375b1".to_string(),
            NexmonChip::Bcm4358 => "bcm4358".to_string(),
            NexmonChip::Bcm4339 => "bcm4339".to_string(),
            NexmonChip::Unknown { chip_ver } => format!("unknown:0x{chip_ver:04x}"),
        }
    }

    /// A friendlier display name including a typical host device.
    pub fn description(self) -> &'static str {
        match self {
            NexmonChip::Bcm43455c0 => "BCM43455c0 / CYW43455 (Raspberry Pi 3B+/4/400/5, Pi Zero W) — 802.11ac, 2.4+5 GHz",
            NexmonChip::Bcm43436b0 => "BCM43436b0 (Raspberry Pi Zero 2 W) — 802.11n, 2.4 GHz",
            NexmonChip::Bcm4366c0 => "BCM4366c0 (ASUS RT-AC86U) — 802.11ac, 2.4+5 GHz",
            NexmonChip::Bcm4375b1 => "BCM4375b1 (Samsung Galaxy S10/S20) — 802.11ax-class, 2.4+5 GHz",
            NexmonChip::Bcm4358 => "BCM4358 (Nexus 6P) — 802.11ac",
            NexmonChip::Bcm4339 => "BCM4339 (Nexus 5) — 802.11ac",
            NexmonChip::Unknown { .. } => "unknown Broadcom/Cypress chip",
        }
    }

    /// Whether this chip's nexmon_csi firmware exports CSI in the modern int16
    /// LE I/Q format ([`crate::NEXMON_CSI_FMT_INT16_IQ`]). The BCM4339 and some
    /// BCM4358 firmwares use the legacy *packed-float* export instead (not yet
    /// implemented by the shim — see `ffi::NEXMON_CSI_FMT_INT16_IQ`).
    pub fn uses_int16_iq(self) -> bool {
        !matches!(self, NexmonChip::Bcm4339 | NexmonChip::Bcm4358)
    }

    /// Whether the chip supports the 5 GHz band (and therefore 802.11ac wide channels).
    pub fn dual_band(self) -> bool {
        matches!(
            self,
            NexmonChip::Bcm43455c0 | NexmonChip::Bcm4366c0 | NexmonChip::Bcm4375b1 | NexmonChip::Bcm4358 | NexmonChip::Bcm4339
        )
    }

    /// Resolve a `chip_ver` word from a nexmon_csi UDP header to a chip
    /// (best-effort — matches the Broadcom chip-ID convention `0x4345` = BCM4345
    /// family, `0x4339`, `0x4358`, `0x4366`, `0x4375`; anything else is
    /// [`NexmonChip::Unknown`]). The c0/b0 revision suffix isn't carried by this
    /// word; the int16-vs-packed-float export distinction is handled separately.
    pub fn from_chip_ver(chip_ver: u16) -> NexmonChip {
        match chip_ver {
            0x4345 => NexmonChip::Bcm43455c0,
            0x4339 => NexmonChip::Bcm4339,
            0x4358 => NexmonChip::Bcm4358,
            0x4366 => NexmonChip::Bcm4366c0,
            0x4375 => NexmonChip::Bcm4375b1,
            // 43436's chip id varies by source; treat it as unknown unless we see it.
            other => NexmonChip::Unknown { chip_ver: other },
        }
    }

    /// Parse a chip name/slug (`"bcm43455c0"`, `"43455c0"`, `"cyw43455"`, ...).
    pub fn from_slug(s: &str) -> Option<NexmonChip> {
        let s = s.trim().to_ascii_lowercase();
        match s.as_str() {
            "bcm43455c0" | "43455c0" | "43455" | "bcm43455" | "cyw43455" => Some(NexmonChip::Bcm43455c0),
            "bcm43436b0" | "43436b0" | "43436" | "bcm43436" => Some(NexmonChip::Bcm43436b0),
            "bcm4366c0" | "4366c0" | "4366" | "bcm4366" => Some(NexmonChip::Bcm4366c0),
            "bcm4375b1" | "4375b1" | "4375" | "bcm4375" => Some(NexmonChip::Bcm4375b1),
            "bcm4358" | "4358" => Some(NexmonChip::Bcm4358),
            "bcm4339" | "4339" => Some(NexmonChip::Bcm4339),
            _ => None,
        }
    }
}

/// 5 GHz UNII channels (a representative set; nexmon picks a control channel via `makecsiparams`).
const FIVE_GHZ_CHANNELS: &[u16] = &[
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149,
    153, 157, 161, 165,
];

fn channels_for(chip: NexmonChip) -> Vec<u16> {
    let mut v: Vec<u16> = (1..=13).collect();
    if chip.dual_band() {
        v.extend_from_slice(FIVE_GHZ_CHANNELS);
    }
    v
}

fn bandwidths_for(chip: NexmonChip) -> Vec<u16> {
    match chip {
        NexmonChip::Bcm43455c0 | NexmonChip::Bcm4366c0 | NexmonChip::Bcm4358 | NexmonChip::Bcm4339 => vec![20, 40, 80],
        NexmonChip::Bcm4375b1 => vec![20, 40, 80, 160],
        NexmonChip::Bcm43436b0 => vec![20, 40],
        NexmonChip::Unknown { .. } => vec![20, 40, 80],
    }
}

/// Subcarrier (FFT) count per supported bandwidth: 20→64, 40→128, 80→256, 160→512.
fn subcarrier_counts_for(chip: NexmonChip) -> Vec<u16> {
    bandwidths_for(chip)
        .iter()
        .map(|bw| (bw / 20) * 64)
        .collect()
}

/// Build the [`rvcsi_core::AdapterProfile`] for a Nexmon chip — the channels /
/// bandwidths / expected subcarrier counts `validate_frame` will bound CSI
/// frames against, plus the live-capability flags (Nexmon supports monitor mode
/// and injection on these chips).
pub fn nexmon_adapter_profile(chip: NexmonChip) -> AdapterProfile {
    AdapterProfile {
        adapter_kind: AdapterKind::Nexmon,
        chip: Some(chip.slug()),
        firmware_version: None,
        driver_version: None,
        supported_channels: channels_for(chip),
        supported_bandwidths_mhz: bandwidths_for(chip),
        expected_subcarrier_counts: subcarrier_counts_for(chip),
        supports_live_capture: true,
        supports_injection: true,
        supports_monitor_mode: true,
    }
}

/// Raspberry Pi models with on-board WiFi that nexmon_csi can extract CSI from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RaspberryPiModel {
    /// Raspberry Pi 3 Model B+ — CYW43455 / BCM43455c0.
    Pi3BPlus,
    /// Raspberry Pi 4 Model B — CYW43455 / BCM43455c0.
    Pi4,
    /// Raspberry Pi 400 — CYW43455 / BCM43455c0.
    Pi400,
    /// **Raspberry Pi 5** — CYW43455 / BCM43455c0 (same wireless as the Pi 4).
    Pi5,
    /// Raspberry Pi Zero W — CYW43438? No — the Zero W uses the BCM43438 (2.4 GHz
    /// only), which nexmon_csi does **not** support; included here only so callers
    /// can detect and reject it. Use a Zero 2 W instead.
    PiZeroW,
    /// Raspberry Pi Zero 2 W — BCM43436b0 (2.4 GHz only).
    PiZero2W,
}

impl RaspberryPiModel {
    /// The Broadcom/Cypress WiFi chip on this board.
    pub fn nexmon_chip(self) -> NexmonChip {
        match self {
            RaspberryPiModel::Pi3BPlus
            | RaspberryPiModel::Pi4
            | RaspberryPiModel::Pi400
            | RaspberryPiModel::Pi5 => NexmonChip::Bcm43455c0,
            RaspberryPiModel::PiZero2W => NexmonChip::Bcm43436b0,
            RaspberryPiModel::PiZeroW => NexmonChip::Unknown { chip_ver: 0x4343 }, // BCM43438 — not CSI-capable
        }
    }

    /// Whether nexmon_csi can extract CSI from this board's WiFi.
    pub fn csi_supported(self) -> bool {
        !matches!(self, RaspberryPiModel::PiZeroW)
    }

    /// Stable slug (`"pi5"`, `"pi4"`, `"pi3b+"`, `"pi400"`, `"pizero2w"`, `"pizerow"`).
    pub fn slug(self) -> &'static str {
        match self {
            RaspberryPiModel::Pi3BPlus => "pi3b+",
            RaspberryPiModel::Pi4 => "pi4",
            RaspberryPiModel::Pi400 => "pi400",
            RaspberryPiModel::Pi5 => "pi5",
            RaspberryPiModel::PiZeroW => "pizerow",
            RaspberryPiModel::PiZero2W => "pizero2w",
        }
    }

    /// Parse a model slug (accepts `pi5`, `pi 5`, `rpi5`, `raspberrypi5`, `pi3b+`/`pi3bplus`, ...).
    pub fn from_slug(s: &str) -> Option<RaspberryPiModel> {
        let s: String = s.trim().to_ascii_lowercase().chars().filter(|c| !c.is_whitespace() && *c != '_' && *c != '-').collect();
        let s = s.strip_prefix("raspberrypi").or_else(|| s.strip_prefix("rpi")).unwrap_or(&s);
        match s {
            "pi5" | "5" => Some(RaspberryPiModel::Pi5),
            "pi4" | "4" | "pi4b" => Some(RaspberryPiModel::Pi4),
            "pi400" | "400" => Some(RaspberryPiModel::Pi400),
            "pi3b+" | "pi3bplus" | "3b+" | "3bplus" => Some(RaspberryPiModel::Pi3BPlus),
            "pizero2w" | "zero2w" | "pizero2" => Some(RaspberryPiModel::PiZero2W),
            "pizerow" | "zerow" => Some(RaspberryPiModel::PiZeroW),
            _ => None,
        }
    }
}

/// Build the [`rvcsi_core::AdapterProfile`] for a Raspberry Pi model (its
/// [`RaspberryPiModel::nexmon_chip`]'s profile, with the `chip` string tagged
/// with the model for legibility).
pub fn raspberry_pi_profile(model: RaspberryPiModel) -> AdapterProfile {
    let mut p = nexmon_adapter_profile(model.nexmon_chip());
    p.chip = Some(format!("{} ({})", model.nexmon_chip().slug(), model.slug()));
    p
}

/// The full registry of Nexmon-supported chips, for `rvcsi nexmon-chips` and SDK callers.
pub fn known_chips() -> &'static [NexmonChip] {
    &[
        NexmonChip::Bcm43455c0,
        NexmonChip::Bcm43436b0,
        NexmonChip::Bcm4366c0,
        NexmonChip::Bcm4375b1,
        NexmonChip::Bcm4358,
        NexmonChip::Bcm4339,
    ]
}

/// The full registry of Raspberry Pi models this crate knows about.
pub fn known_pi_models() -> &'static [RaspberryPiModel] {
    &[
        RaspberryPiModel::Pi5,
        RaspberryPiModel::Pi4,
        RaspberryPiModel::Pi400,
        RaspberryPiModel::Pi3BPlus,
        RaspberryPiModel::PiZero2W,
        RaspberryPiModel::PiZeroW,
    ]
}

impl crate::ffi::NexmonCsiHeader {
    /// Resolve this packet's chip from its `chip_ver` word (best-effort; the raw
    /// `chip_ver` field is always preserved). For a Raspberry Pi 5 (or 4/400/3B+)
    /// capture this returns [`NexmonChip::Bcm43455c0`].
    pub fn chip(&self) -> NexmonChip {
        NexmonChip::from_chip_ver(self.chip_ver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pi5_uses_the_same_chip_as_pi4() {
        assert_eq!(RaspberryPiModel::Pi5.nexmon_chip(), NexmonChip::Bcm43455c0);
        assert_eq!(RaspberryPiModel::Pi4.nexmon_chip(), NexmonChip::Bcm43455c0);
        assert!(RaspberryPiModel::Pi5.csi_supported());
        let p = raspberry_pi_profile(RaspberryPiModel::Pi5);
        assert_eq!(p.adapter_kind, AdapterKind::Nexmon);
        assert!(p.chip.as_deref().unwrap().contains("pi5"));
        assert_eq!(p.supported_bandwidths_mhz, vec![20, 40, 80]);
        assert_eq!(p.expected_subcarrier_counts, vec![64, 128, 256]);
        assert!(p.accepts_channel(36)); // 5 GHz
        assert!(p.accepts_channel(6)); // 2.4 GHz
        assert!(p.accepts_subcarrier_count(256)); // VHT80
        assert!(!p.accepts_subcarrier_count(57));
        assert!(p.supports_monitor_mode && p.supports_injection);
    }

    #[test]
    fn chip_ver_resolution_best_effort() {
        assert_eq!(NexmonChip::from_chip_ver(0x4345), NexmonChip::Bcm43455c0);
        assert_eq!(NexmonChip::from_chip_ver(0x4339), NexmonChip::Bcm4339);
        assert_eq!(NexmonChip::from_chip_ver(0x4366), NexmonChip::Bcm4366c0);
        assert!(matches!(NexmonChip::from_chip_ver(0xABCD), NexmonChip::Unknown { chip_ver: 0xABCD }));
    }

    #[test]
    fn chip_traits() {
        assert!(NexmonChip::Bcm43455c0.uses_int16_iq());
        assert!(!NexmonChip::Bcm4339.uses_int16_iq());
        assert!(NexmonChip::Bcm43455c0.dual_band());
        assert!(!NexmonChip::Bcm43436b0.dual_band());
        assert_eq!(nexmon_adapter_profile(NexmonChip::Bcm43436b0).supported_bandwidths_mhz, vec![20, 40]);
        assert_eq!(nexmon_adapter_profile(NexmonChip::Bcm43436b0).expected_subcarrier_counts, vec![64, 128]);
        // unknown chip -> a permissive-ish 802.11ac default
        let u = nexmon_adapter_profile(NexmonChip::Unknown { chip_ver: 0 });
        assert_eq!(u.supported_bandwidths_mhz, vec![20, 40, 80]);
    }

    #[test]
    fn slug_parsing() {
        assert_eq!(NexmonChip::from_slug("CYW43455"), Some(NexmonChip::Bcm43455c0));
        assert_eq!(NexmonChip::from_slug("bcm4366c0"), Some(NexmonChip::Bcm4366c0));
        assert_eq!(NexmonChip::from_slug("nope"), None);
        assert_eq!(RaspberryPiModel::from_slug("Pi 5"), Some(RaspberryPiModel::Pi5));
        assert_eq!(RaspberryPiModel::from_slug("raspberry-pi-5"), Some(RaspberryPiModel::Pi5));
        assert_eq!(RaspberryPiModel::from_slug("pi3bplus"), Some(RaspberryPiModel::Pi3BPlus));
        assert_eq!(RaspberryPiModel::from_slug("pi42"), None);
        assert_eq!(NexmonChip::Bcm43455c0.slug(), "bcm43455c0");
        assert_eq!(RaspberryPiModel::Pi5.slug(), "pi5");
    }

    #[test]
    fn registries_nonempty_and_pi5_present() {
        assert!(known_chips().contains(&NexmonChip::Bcm43455c0));
        assert!(known_pi_models().contains(&RaspberryPiModel::Pi5));
    }
}
