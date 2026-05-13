//! Implementations of the `rvcsi` subcommands (ADR-095 FR7).
//!
//! Each command writes to a caller-supplied `&mut dyn Write` so the bodies can
//! be unit-tested against an in-memory buffer.

use std::io::Write;

use anyhow::{Context, Result};

use rvcsi_adapter_file::{read_all, CaptureHeader, FileRecorder, FileReplayAdapter};
use rvcsi_adapter_nexmon::NexmonAdapter;
use rvcsi_core::{
    validate_frame, AdapterKind, AdapterProfile, CsiFrame, CsiSource, SessionId, SourceId,
    ValidationPolicy,
};
use rvcsi_runtime as runtime;

/// `rvcsi record --in <nexmon.bin> --out <cap.rvcsi>` — transcode a buffer of
/// "rvCSI Nexmon records" (the napi-c shim format) into a `.rvcsi` capture file,
/// validating each frame on the way in. This gives the CLI a way to produce
/// `.rvcsi` files without a live radio (which needs the not-yet-shipped daemon).
pub fn record_from_nexmon(
    out: &mut dyn Write,
    nexmon_path: &str,
    out_path: &str,
    source_id: &str,
    session_id: u64,
) -> Result<()> {
    let bytes = std::fs::read(nexmon_path).with_context(|| format!("reading {nexmon_path}"))?;
    let mut src = NexmonAdapter::from_bytes(SourceId::from(source_id), SessionId(session_id), bytes);
    let profile = AdapterProfile::offline(AdapterKind::Nexmon);
    let policy = ValidationPolicy::default();
    let header = CaptureHeader::new(SessionId(session_id), SourceId::from(source_id), profile.clone());
    let mut rec = FileRecorder::create(out_path, &header).with_context(|| format!("creating {out_path}"))?;
    let (mut written, mut skipped, mut prev_ts) = (0u64, 0u64, None);
    loop {
        match src.next_frame() {
            Ok(None) => break,
            Ok(Some(mut f)) => {
                let ts = f.timestamp_ns;
                match validate_frame(&mut f, &profile, &policy, prev_ts) {
                    Ok(()) if f.is_exposable() => {
                        prev_ts = Some(ts);
                        rec.write_frame(&f)?;
                        written += 1;
                    }
                    _ => skipped += 1,
                }
            }
            Err(e) => {
                writeln!(out, "warning: stopped at a malformed Nexmon record: {e}")?;
                break;
            }
        }
    }
    rec.finish()?;
    writeln!(out, "recorded {written} frame(s) to {out_path} ({skipped} dropped by validation)")?;
    Ok(())
}

/// `rvcsi record --source nexmon-pcap --in <csi.pcap> --out <cap.rvcsi> [--chip pi5]` —
/// transcode the real nexmon_csi UDP payloads inside a libpcap capture
/// (`tcpdump -i wlan0 dst port 5500 -w csi.pcap`) into a `.rvcsi` capture file,
/// validating each frame. `port` is the CSI UDP port (`None` ⇒ 5500). `chip` is
/// an optional chip / Raspberry-Pi-model spec (`"pi5"`, `"bcm43455c0"`, ...) —
/// when given, frames are validated against that device's profile and the
/// non-conforming ones dropped (and the profile is stamped on the capture).
pub fn record_from_nexmon_pcap(
    out: &mut dyn Write,
    pcap_path: &str,
    out_path: &str,
    source_id: &str,
    session_id: u64,
    port: Option<u16>,
    chip: Option<&str>,
) -> Result<()> {
    let bytes = std::fs::read(pcap_path).with_context(|| format!("reading {pcap_path}"))?;
    let frames = runtime::decode_nexmon_pcap_for(&bytes, source_id, session_id, port, chip)
        .with_context(|| format!("parsing nexmon pcap {pcap_path}"))?;
    let profile = match chip {
        Some(spec) => runtime::nexmon_profile_for(spec)
            .ok_or_else(|| anyhow::anyhow!("unknown nexmon chip / Raspberry Pi model `{spec}`"))?,
        None => AdapterProfile::nexmon_default(),
    };
    let header = CaptureHeader::new(SessionId(session_id), SourceId::from(source_id), profile);
    let mut rec = FileRecorder::create(out_path, &header).with_context(|| format!("creating {out_path}"))?;
    for f in &frames {
        rec.write_frame(f)?;
    }
    rec.finish()?;
    let chip_note = chip.map(|c| format!(" (chip {c})")).unwrap_or_default();
    writeln!(out, "recorded {} frame(s) from {pcap_path} to {out_path}{chip_note}", frames.len())?;
    Ok(())
}

/// `rvcsi nexmon-chips` — list the Broadcom/Cypress chips nexmon_csi runs on and
/// the Raspberry Pi models that carry them (incl. the Pi 5 → BCM43455c0).
pub fn nexmon_chips_cmd(out: &mut dyn Write, json: bool) -> Result<()> {
    use rvcsi_adapter_nexmon::{known_chips, known_pi_models, nexmon_adapter_profile, NexmonChip};
    if json {
        let chips: Vec<_> = known_chips()
            .iter()
            .map(|c| {
                let p = nexmon_adapter_profile(*c);
                serde_json::json!({
                    "slug": c.slug(), "description": c.description(),
                    "dual_band": c.dual_band(), "int16_iq_export": c.uses_int16_iq(),
                    "bandwidths_mhz": p.supported_bandwidths_mhz,
                    "expected_subcarrier_counts": p.expected_subcarrier_counts,
                })
            })
            .collect();
        let pis: Vec<_> = known_pi_models()
            .iter()
            .map(|m| serde_json::json!({
                "slug": m.slug(), "chip": m.nexmon_chip().slug(), "csi_supported": m.csi_supported(),
            }))
            .collect();
        writeln!(out, "{}", serde_json::to_string_pretty(&serde_json::json!({ "chips": chips, "raspberry_pi_models": pis }))?)?;
        return Ok(());
    }
    writeln!(out, "Nexmon-supported Broadcom/Cypress chips:")?;
    for c in known_chips() {
        let p = nexmon_adapter_profile(*c);
        writeln!(
            out,
            "  {:<12} {}  [bw {:?} MHz, sc {:?}{}]",
            c.slug(),
            c.description(),
            p.supported_bandwidths_mhz,
            p.expected_subcarrier_counts,
            if c.uses_int16_iq() { "" } else { ", legacy packed-float export" }
        )?;
    }
    writeln!(out, "\nRaspberry Pi models:")?;
    for m in known_pi_models() {
        let chip = m.nexmon_chip();
        let chip_slug = if matches!(chip, NexmonChip::Unknown { .. }) { "(no CSI support)".to_string() } else { chip.slug() };
        writeln!(out, "  {:<10} -> {}{}", m.slug(), chip_slug, if m.csi_supported() { "" } else { "  [WiFi present but not CSI-capable]" })?;
    }
    Ok(())
}

/// `rvcsi inspect-nexmon <csi.pcap>` — summarize a nexmon_csi `.pcap` (link
/// type, CSI frame count, channels, bandwidths, chip versions, RSSI range,
/// time span). `port` is the CSI UDP port (`None` ⇒ 5500).
pub fn inspect_nexmon(out: &mut dyn Write, pcap_path: &str, port: Option<u16>, json: bool) -> Result<()> {
    let s = runtime::summarize_nexmon_pcap(pcap_path, port).with_context(|| format!("inspecting {pcap_path}"))?;
    if json {
        writeln!(out, "{}", serde_json::to_string_pretty(&s)?)?;
        return Ok(());
    }
    writeln!(out, "nexmon pcap    : {pcap_path}")?;
    writeln!(out, "  link type    : {}", s.link_type)?;
    writeln!(out, "  CSI frames   : {}", s.csi_frame_count)?;
    writeln!(out, "  skipped pkts : {}", s.skipped_packets)?;
    writeln!(
        out,
        "  time span    : {} .. {} ns ({} ns)",
        s.first_timestamp_ns,
        s.last_timestamp_ns,
        s.last_timestamp_ns.saturating_sub(s.first_timestamp_ns)
    )?;
    writeln!(out, "  channels     : {:?}", s.channels)?;
    writeln!(out, "  bandwidths   : {:?} MHz", s.bandwidths_mhz)?;
    writeln!(out, "  subcarriers  : {:?}", s.subcarrier_counts)?;
    writeln!(
        out,
        "  chip versions: {}",
        s.chip_versions.iter().map(|v| format!("0x{v:04x}")).collect::<Vec<_>>().join(", ")
    )?;
    writeln!(out, "  chip         : {} (seen: {})", s.detected_chip, s.chip_names.join(", "))?;
    match s.rssi_dbm_range {
        Some((lo, hi)) => writeln!(out, "  rssi range   : {lo} .. {hi} dBm")?,
        None => writeln!(out, "  rssi range   : (none)")?,
    }
    Ok(())
}

/// `rvcsi decode-chanspec <hex-or-dec>` — decode a Broadcom d11ac chanspec word
/// to `{channel, bandwidth_mhz, is_5ghz}` (JSON, or a human line).
pub fn decode_chanspec_cmd(out: &mut dyn Write, chanspec_str: &str, json: bool) -> Result<()> {
    let s = chanspec_str.trim();
    let value: u32 = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).with_context(|| format!("not a hex u16: {s}"))?
    } else {
        s.parse::<u32>().with_context(|| format!("not a decimal u16: {s}"))?
    };
    let d = rvcsi_adapter_nexmon::decode_chanspec((value & 0xFFFF) as u16);
    if json {
        writeln!(
            out,
            "{}",
            serde_json::to_string(&serde_json::json!({
                "chanspec": d.chanspec, "channel": d.channel,
                "bandwidth_mhz": d.bandwidth_mhz, "is_5ghz": d.is_5ghz
            }))?
        )?;
    } else {
        writeln!(
            out,
            "chanspec 0x{:04x}: channel {} @ {} MHz ({})",
            d.chanspec,
            d.channel,
            d.bandwidth_mhz,
            if d.is_5ghz { "5 GHz" } else { "2.4 GHz" }
        )?;
    }
    Ok(())
}

/// `rvcsi inspect <path>` — print a summary of a `.rvcsi` capture file.
pub fn inspect(out: &mut dyn Write, path: &str, json: bool) -> Result<()> {
    let summary = runtime::summarize_capture(path).with_context(|| format!("inspecting {path}"))?;
    if json {
        writeln!(out, "{}", serde_json::to_string_pretty(&summary)?)?;
        return Ok(());
    }
    writeln!(out, "capture        : {path}")?;
    writeln!(out, "  version      : {}", summary.capture_version)?;
    writeln!(out, "  session      : {}", summary.session_id)?;
    writeln!(out, "  source       : {}", summary.source_id)?;
    writeln!(out, "  adapter      : {}", summary.adapter_kind)?;
    if let Some(chip) = &summary.chip {
        writeln!(out, "  chip         : {chip}")?;
    }
    writeln!(out, "  frames       : {}", summary.frame_count)?;
    writeln!(
        out,
        "  time span    : {} .. {} ns ({} ns)",
        summary.first_timestamp_ns,
        summary.last_timestamp_ns,
        summary.last_timestamp_ns.saturating_sub(summary.first_timestamp_ns)
    )?;
    writeln!(out, "  channels     : {:?}", summary.channels)?;
    writeln!(out, "  subcarriers  : {:?}", summary.subcarrier_counts)?;
    writeln!(out, "  mean quality : {:.3}", summary.mean_quality)?;
    let b = summary.validation_breakdown;
    writeln!(
        out,
        "  validation   : accepted={} degraded={} recovered={} rejected={} pending={}",
        b.accepted, b.degraded, b.recovered, b.rejected, b.pending
    )?;
    writeln!(out, "  calibration  : {}", summary.calibration_version.as_deref().unwrap_or("(none)"))?;
    Ok(())
}

/// `rvcsi replay <path>` / `rvcsi stream --in <path> --format json` — emit one
/// line per frame. With `json`, the full `CsiFrame` JSON; otherwise a compact
/// `frame_id ts ch rssi quality validation` line. `limit` caps the count
/// (`None` = all). `speed` is accepted but not enforced here (the daemon paces
/// real-time replay); a non-1.0 value is noted on stderr by the caller.
pub fn replay(out: &mut dyn Write, path: &str, json: bool, limit: Option<usize>) -> Result<()> {
    let mut adapter = FileReplayAdapter::open(path).with_context(|| format!("opening {path}"))?;
    let mut n = 0usize;
    while let Some(frame) = adapter.next_frame()? {
        if json {
            writeln!(out, "{}", serde_json::to_string(&frame)?)?;
        } else {
            writeln!(
                out,
                "{:>8} {:>16} ch{:<3} rssi={:>5} q={:.3} {:?}",
                frame.frame_id.value(),
                frame.timestamp_ns,
                frame.channel,
                frame.rssi_dbm.map(|r| r.to_string()).unwrap_or_else(|| "-".into()),
                frame.quality_score,
                frame.validation,
            )?;
        }
        n += 1;
        if let Some(lim) = limit {
            if n >= lim {
                break;
            }
        }
    }
    if !json {
        writeln!(out, "-- {n} frame(s)")?;
    }
    Ok(())
}

/// `rvcsi events <path>` — replay the capture through DSP + the event pipeline
/// and print the emitted events (compact, or full JSON with `json`).
pub fn events(out: &mut dyn Write, path: &str, json: bool) -> Result<()> {
    let evs = runtime::events_from_capture(path).with_context(|| format!("processing {path}"))?;
    if json {
        writeln!(out, "{}", serde_json::to_string_pretty(&evs)?)?;
        return Ok(());
    }
    for e in &evs {
        writeln!(
            out,
            "{:>16} ns  {:<22} conf={:.3}  evidence={:?}{}",
            e.timestamp_ns,
            e.kind.slug(),
            e.confidence,
            e.evidence_window_ids.iter().map(|w| w.value()).collect::<Vec<_>>(),
            e.calibration_version.as_deref().map(|c| format!("  calib={c}")).unwrap_or_default(),
        )?;
    }
    writeln!(out, "-- {} event(s)", evs.len())?;
    Ok(())
}

/// `rvcsi health --source <slug> [--target <path>]` — open the source, drain it,
/// and print the final `SourceHealth` as JSON. File and Nexmon sources work
/// offline; live radios are not available in this build.
pub fn health(out: &mut dyn Write, source: &str, target: Option<&str>) -> Result<()> {
    let h = match source {
        "file" | "replay" => {
            let path = target.context("`--target <path>` is required for the file source")?;
            let mut a = FileReplayAdapter::open(path)?;
            while a.next_frame()?.is_some() {}
            a.health()
        }
        "nexmon" => {
            let path = target.context("`--target <path>` is required for the nexmon source")?;
            let bytes = std::fs::read(path)?;
            let mut a = NexmonAdapter::from_bytes(SourceId::from("nexmon"), SessionId(0), bytes);
            // pull until exhausted or a malformed record stops us
            while let Ok(Some(_)) = a.next_frame() {}
            a.health()
        }
        "esp32" | "intel" | "atheros" => {
            anyhow::bail!("live capture for source `{source}` is not available in this build; use the `rvcsi-daemon` (not yet shipped) or replay a `.rvcsi` capture");
        }
        other => anyhow::bail!("unknown source `{other}` (expected: file, replay, nexmon, esp32, intel, atheros)"),
    };
    writeln!(out, "{}", serde_json::to_string_pretty(&h)?)?;
    Ok(())
}

/// `rvcsi export ruvector --in <capture> --out <jsonl>` — window the capture and
/// store each window's embedding into a JSONL RF-memory file.
pub fn export_ruvector(out: &mut dyn Write, capture: &str, out_jsonl: &str) -> Result<()> {
    let stored = runtime::export_capture_to_rf_memory(capture, out_jsonl)
        .with_context(|| format!("exporting {capture} -> {out_jsonl}"))?;
    writeln!(out, "stored {stored} window embedding(s) to {out_jsonl}")?;
    Ok(())
}

/// `rvcsi calibrate --in <capture> [--out <baseline.json>]` — a v0 calibration:
/// learn the per-subcarrier mean amplitude (the "baseline") over all exposable
/// frames in a capture and emit it as JSON. Real, versioned, room-scoped
/// calibration (ADR-095 D14) lands with the daemon.
pub fn calibrate(out: &mut dyn Write, capture: &str, out_path: Option<&str>) -> Result<()> {
    let (header, frames) = read_all(capture).with_context(|| format!("reading {capture}"))?;
    let exposable: Vec<&CsiFrame> = frames.iter().filter(|f| f.is_exposable()).collect();
    if exposable.is_empty() {
        anyhow::bail!("no exposable frames in {capture} — cannot calibrate");
    }
    let n = exposable[0].subcarrier_count as usize;
    let mut acc = vec![0.0f64; n];
    let mut count = 0usize;
    for f in &exposable {
        if f.subcarrier_count as usize != n {
            continue;
        }
        for (a, v) in acc.iter_mut().zip(f.amplitude.iter()) {
            *a += *v as f64;
        }
        count += 1;
    }
    let baseline: Vec<f32> = acc.iter().map(|a| (*a / count.max(1) as f64) as f32).collect();
    #[derive(serde::Serialize)]
    struct Baseline<'a> {
        source_id: &'a str,
        session_id: u64,
        version: String,
        subcarrier_count: usize,
        frames_used: usize,
        baseline_amplitude: Vec<f32>,
    }
    let payload = Baseline {
        source_id: header.source_id.as_str(),
        session_id: header.session_id.value(),
        version: format!("{}@auto-{count}", header.source_id.as_str()),
        subcarrier_count: n,
        frames_used: count,
        baseline_amplitude: baseline,
    };
    let json = serde_json::to_string_pretty(&payload)?;
    if let Some(p) = out_path {
        std::fs::write(p, &json)?;
        writeln!(out, "wrote baseline ({n} subcarriers, {count} frames) to {p}")?;
    } else {
        writeln!(out, "{json}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvcsi_adapter_nexmon::{encode_record, NexmonRecord};
    use rvcsi_core::{FrameId, ValidationStatus};

    fn write_capture(path: &std::path::Path, n: usize) {
        let header = CaptureHeader::new(
            SessionId(2),
            SourceId::from("cli-it"),
            AdapterProfile::offline(AdapterKind::File),
        );
        let mut rec = FileRecorder::create(path, &header).unwrap();
        for k in 0..n {
            let amp_scale = if (k / 8) % 2 == 0 { 0.0 } else { 1.5 };
            let i: Vec<f32> = (0..32).map(|s| 1.0 + amp_scale * (((k + s) % 5) as f32 - 2.0)).collect();
            let q: Vec<f32> = (0..32).map(|_| 0.5).collect();
            let mut f = CsiFrame::from_iq(
                FrameId(k as u64),
                SessionId(2),
                SourceId::from("cli-it"),
                AdapterKind::File,
                1_000 + k as u64 * 50_000_000,
                6,
                20,
                i,
                q,
            )
            .with_rssi(-55);
            f.validation = ValidationStatus::Accepted;
            f.quality_score = 0.9;
            rec.write_frame(&f).unwrap();
        }
        rec.finish().unwrap();
    }

    fn run<F: FnOnce(&mut Vec<u8>) -> Result<()>>(f: F) -> String {
        let mut buf = Vec::new();
        f(&mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn inspect_human_and_json() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_capture(tmp.path(), 12);
        let p = tmp.path().to_str().unwrap();
        let human = run(|o| inspect(o, p, false));
        assert!(human.contains("frames       : 12"));
        assert!(human.contains("channels     : [6]"));
        let json = run(|o| inspect(o, p, true));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["frame_count"], 12);
    }

    #[test]
    fn replay_compact_and_json_and_limit() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_capture(tmp.path(), 5);
        let p = tmp.path().to_str().unwrap();
        let compact = run(|o| replay(o, p, false, None));
        assert!(compact.contains("-- 5 frame(s)"));
        let json = run(|o| replay(o, p, true, Some(3)));
        assert_eq!(json.lines().count(), 3);
        for line in json.lines() {
            let _: CsiFrame = serde_json::from_str(line).unwrap();
        }
    }

    #[test]
    fn events_command_emits_something() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_capture(tmp.path(), 64);
        let p = tmp.path().to_str().unwrap();
        let out = run(|o| events(o, p, false));
        assert!(out.contains("event(s)"));
        let json = run(|o| events(o, p, true));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.is_array());
    }

    #[test]
    fn health_file_source() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_capture(tmp.path(), 7);
        let p = tmp.path().to_str().unwrap();
        let out = run(|o| health(o, "file", Some(p)));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["frames_delivered"], 7);
        assert_eq!(v["connected"], false);
        // unknown / live sources error cleanly
        let mut buf = Vec::new();
        assert!(health(&mut buf, "esp32", Some(p)).is_err());
        assert!(health(&mut buf, "bogus", None).is_err());
        assert!(health(&mut buf, "file", None).is_err()); // missing --target
    }

    #[test]
    fn export_and_calibrate() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_capture(tmp.path(), 64);
        let p = tmp.path().to_str().unwrap();
        let out_jsonl = tempfile::NamedTempFile::new().unwrap();
        let out = run(|o| export_ruvector(o, p, out_jsonl.path().to_str().unwrap()));
        assert!(out.contains("stored "));
        // calibrate to stdout
        let calib = run(|o| calibrate(o, p, None));
        let v: serde_json::Value = serde_json::from_str(&calib).unwrap();
        assert_eq!(v["subcarrier_count"], 32);
        assert!(v["baseline_amplitude"].as_array().unwrap().len() == 32);
        // calibrate to file
        let baseline_file = tempfile::NamedTempFile::new().unwrap();
        let out2 = run(|o| calibrate(o, p, Some(baseline_file.path().to_str().unwrap())));
        assert!(out2.contains("wrote baseline"));
        let written = std::fs::read_to_string(baseline_file.path()).unwrap();
        assert!(written.contains("baseline_amplitude"));
    }

    #[test]
    fn record_from_nexmon_then_inspect_and_replay() {
        // build a small Nexmon record dump (64-subcarrier, the default profile)
        let mut dump = Vec::new();
        for k in 0..6u64 {
            let rec = NexmonRecord {
                subcarrier_count: 64,
                channel: 36,
                bandwidth_mhz: 80,
                rssi_dbm: Some(-60 - k as i16),
                noise_floor_dbm: Some(-92),
                timestamp_ns: 1_000 + k * 50_000_000,
                i_values: (0..64).map(|s| (s as f32 % 3.0) - 1.0).collect(),
                q_values: (0..64).map(|s| (s as f32 % 5.0) * 0.1).collect(),
            };
            dump.extend(encode_record(&rec).unwrap());
        }
        let dump_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(dump_file.path(), &dump).unwrap();
        let cap_file = tempfile::NamedTempFile::new().unwrap();

        let out = run(|o| {
            record_from_nexmon(
                o,
                dump_file.path().to_str().unwrap(),
                cap_file.path().to_str().unwrap(),
                "nexmon-rec",
                3,
            )
        });
        assert!(out.contains("recorded 6 frame(s)"), "{out}");

        // the produced capture is a real .rvcsi the other commands can read
        let summary = run(|o| inspect(o, cap_file.path().to_str().unwrap(), false));
        assert!(summary.contains("frames       : 6"));
        assert!(summary.contains("source       : nexmon-rec"));
        let replayed = run(|o| replay(o, cap_file.path().to_str().unwrap(), false, None));
        assert!(replayed.contains("-- 6 frame(s)"));
    }

    #[test]
    fn nexmon_pcap_record_and_inspect_roundtrip() {
        use rvcsi_adapter_nexmon::NexmonCsiHeader;
        let chanspec = 0xc000u16 | 0x2000 | 36; // 5 GHz ch36 80 MHz
        let nsub = 256u16;
        let frames: Vec<(u64, NexmonCsiHeader, Vec<f32>, Vec<f32>)> = (0..8u64)
            .map(|k| {
                let i: Vec<f32> = (0..nsub).map(|s| (s as i16 - 128 + k as i16) as f32).collect();
                let q: Vec<f32> = (0..nsub).map(|s| (s as i16 % 5 + k as i16) as f32).collect();
                (
                    1_000_000_000 + k * 50_000_000,
                    NexmonCsiHeader {
                        rssi_dbm: -55 - k as i16,
                        fctl: 8,
                        src_mac: [0, 1, 2, 3, 4, 5],
                        seq_cnt: k as u16,
                        core: 0,
                        spatial_stream: 0,
                        chanspec,
                        chip_ver: 0x4345,
                        channel: 0,
                        bandwidth_mhz: 0,
                        is_5ghz: false,
                        subcarrier_count: nsub,
                    },
                    i,
                    q,
                )
            })
            .collect();
        let pcap_bytes = rvcsi_adapter_nexmon::synthetic_nexmon_pcap(&frames, 5500).unwrap();
        let pcap_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(pcap_file.path(), &pcap_bytes).unwrap();
        let pcap_path = pcap_file.path().to_str().unwrap();

        // inspect-nexmon (human + json) — chip_ver 0x4345 resolves to the BCM43455c0
        // (the Raspberry Pi 3B+/4/400/5 chip)
        let human = run(|o| inspect_nexmon(o, pcap_path, None, false));
        assert!(human.contains("CSI frames   : 8"), "{human}");
        assert!(human.contains("channels     : [36]"));
        assert!(human.contains("0x4345"));
        assert!(human.contains("chip         : bcm43455c0"), "{human}");
        let j = run(|o| inspect_nexmon(o, pcap_path, None, true));
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["csi_frame_count"], 8);
        assert_eq!(v["bandwidths_mhz"][0], 80);
        assert_eq!(v["detected_chip"], "bcm43455c0");
        assert_eq!(v["chip_names"][0], "bcm43455c0");

        // record --source nexmon-pcap --chip pi5 -> .rvcsi; the 256-sc VHT80 ch36
        // frames all fit a Raspberry Pi 5 (BCM43455c0)
        let cap_file = tempfile::NamedTempFile::new().unwrap();
        let cap_path = cap_file.path().to_str().unwrap();
        let out = run(|o| record_from_nexmon_pcap(o, pcap_path, cap_path, "nx-pcap", 3, None, Some("pi5")));
        assert!(out.contains("recorded 8 frame(s)") && out.contains("chip pi5"), "{out}");
        let summary = run(|o| inspect(o, cap_path, false));
        assert!(summary.contains("frames       : 8"));
        assert!(summary.contains("source       : nx-pcap"));
        assert!(summary.contains("channels     : [36]"));
        assert!(summary.contains("pi5"), "{summary}"); // the Pi 5 profile was stamped on the capture

        // --chip pizero2w (2.4 GHz only, ≤128 sc) drops every 256-sc frame
        let cap2 = tempfile::NamedTempFile::new().unwrap();
        let out2 = run(|o| record_from_nexmon_pcap(o, pcap_path, cap2.path().to_str().unwrap(), "z", 0, None, Some("pizero2w")));
        assert!(out2.contains("recorded 0 frame(s)"), "{out2}");
        // unknown --chip is an error
        let mut buf = Vec::new();
        assert!(record_from_nexmon_pcap(&mut buf, pcap_path, cap_path, "x", 0, None, Some("not-a-chip")).is_err());
    }

    #[test]
    fn nexmon_chips_listing_includes_pi5() {
        let human = run(|o| nexmon_chips_cmd(o, false));
        assert!(human.contains("bcm43455c0"), "{human}");
        assert!(human.contains("pi5"), "{human}");
        assert!(human.to_lowercase().contains("raspberry pi"), "{human}");
        let j = run(|o| nexmon_chips_cmd(o, true));
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        let chips = v["chips"].as_array().unwrap();
        assert!(chips.iter().any(|c| c["slug"] == "bcm43455c0"));
        let pis = v["raspberry_pi_models"].as_array().unwrap();
        let pi5 = pis.iter().find(|m| m["slug"] == "pi5").expect("pi5 in listing");
        assert_eq!(pi5["chip"], "bcm43455c0");
        assert_eq!(pi5["csi_supported"], true);
    }

    #[test]
    fn decode_chanspec_command() {
        let out = run(|o| decode_chanspec_cmd(o, "0xe024", false)); // 5G | BW80(0x2000) | ch36 ... 0xe024 = 0xc000|0x2000|0x24
        assert!(out.contains("channel 36"), "{out}");
        assert!(out.contains("80 MHz"));
        assert!(out.contains("5 GHz"));
        let out = run(|o| decode_chanspec_cmd(o, "4102", false)); // 0x1006 = BW20(0x1000)|ch6
        assert!(out.contains("channel 6"));
        assert!(out.contains("2.4 GHz"));
        let j = run(|o| decode_chanspec_cmd(o, "0x1006", true));
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["channel"], 6);
        // bad input errors cleanly
        let mut buf = Vec::new();
        assert!(decode_chanspec_cmd(&mut buf, "0xZZZZ", false).is_err());
        assert!(decode_chanspec_cmd(&mut buf, "not-a-number", false).is_err());
    }

    #[test]
    fn errors_on_missing_capture() {
        let mut buf = Vec::new();
        assert!(inspect(&mut buf, "/no/such/file.rvcsi", false).is_err());
        assert!(replay(&mut buf, "/no/such/file.rvcsi", false, None).is_err());
        assert!(events(&mut buf, "/no/such/file.rvcsi", false).is_err());
        assert!(calibrate(&mut buf, "/no/such/file.rvcsi", None).is_err());
        assert!(record_from_nexmon(&mut buf, "/no/x.bin", "/tmp/y.rvcsi", "s", 0).is_err());
        assert!(record_from_nexmon_pcap(&mut buf, "/no/x.pcap", "/tmp/y.rvcsi", "s", 0, None, None).is_err());
        assert!(inspect_nexmon(&mut buf, "/no/such/file.pcap", None, false).is_err());
    }
}
