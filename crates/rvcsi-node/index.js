'use strict';

// rvCSI Node.js SDK — curated public surface over the napi-rs addon.
//
// The compiled addon (and its loader `binding.js`) are produced by
// `napi build --platform --release --js binding.js --dts binding.d.ts`
// in this directory (see package.json `build` script). Until that's run,
// `require('@ruv/rvcsi')` still succeeds — only the calls that touch the
// native code throw, with a message explaining how to build it.
//
// Everything the Rust side returns as JSON is parsed here so callers get
// plain objects (CsiFrame / CsiWindow / CsiEvent / SourceHealth /
// CaptureSummary — see index.d.ts).

let _binding = null;
let _bindingError = null;

function binding() {
  if (_binding) return _binding;
  if (_bindingError) throw _bindingError;
  try {
    // The @napi-rs/cli loader (resolves the right prebuilt .node for this platform).
    _binding = require('./binding.js');
  } catch (e1) {
    try {
      // Fallback: a sibling .node placed next to this file (e.g. a debug build).
      _binding = require('./rvcsi-node.node');
    } catch (e2) {
      _bindingError = new Error(
        'rvcsi: the native addon is not built. Build it with ' +
          '`npm run build` here, or `napi build --platform --release ' +
          '--js binding.js --dts binding.d.ts` in v2/crates/rvcsi-node ' +
          '(needs the Rust toolchain + @napi-rs/cli). ' +
          'Loader error: ' + e1.message + ' | fallback error: ' + e2.message,
      );
      throw _bindingError;
    }
  }
  return _binding;
}

const u32 = (n) => Number(n) >>> 0;

/** rvCSI runtime version string. @returns {string} */
function rvcsiVersion() {
  return binding().rvcsiVersion();
}

/** ABI version of the linked napi-c Nexmon shim (`major<<16 | minor`). @returns {number} */
function nexmonShimAbiVersion() {
  return binding().nexmonShimAbiVersion();
}

/**
 * Decode a Buffer of "rvCSI Nexmon records" (the napi-c shim format) into an
 * array of validated CsiFrame objects.
 * @param {Buffer|Uint8Array} buf
 * @param {string} sourceId
 * @param {number} sessionId
 * @returns {import('./index').CsiFrame[]}
 */
function nexmonDecodeRecords(buf, sourceId, sessionId) {
  return JSON.parse(binding().nexmonDecodeRecords(buf, String(sourceId), u32(sessionId)));
}

/**
 * Summarize a `.rvcsi` capture file.
 * @param {string} path
 * @returns {import('./index').CaptureSummary}
 */
function inspectCaptureFile(path) {
  return JSON.parse(binding().inspectCaptureFile(String(path)));
}

/**
 * Replay a `.rvcsi` capture through the DSP + event pipeline.
 * @param {string} path
 * @returns {import('./index').CsiEvent[]}
 */
function eventsFromCaptureFile(path) {
  return JSON.parse(binding().eventsFromCaptureFile(String(path)));
}

/**
 * Window a capture and store each window's embedding into a JSONL RF-memory file.
 * @param {string} capturePath
 * @param {string} outJsonlPath
 * @returns {number} windows stored
 */
function exportCaptureToRfMemory(capturePath, outJsonlPath) {
  return binding().exportCaptureToRfMemory(String(capturePath), String(outJsonlPath));
}

/**
 * Decode the *real* nexmon_csi UDP payloads inside a libpcap `.pcap` buffer
 * (`tcpdump -i wlan0 dst port 5500 -w csi.pcap`) into validated CsiFrame objects.
 * @param {Buffer|Uint8Array} pcap
 * @param {string} sourceId
 * @param {number} sessionId
 * @param {number} [port] CSI UDP port (default 5500)
 * @param {string} [chip] chip / Raspberry-Pi-model spec to validate against
 *   (e.g. `'pi5'`, `'bcm43455c0'`); non-conforming frames are dropped
 * @returns {import('./index').CsiFrame[]}
 */
function nexmonDecodePcap(pcap, sourceId, sessionId, port, chip) {
  return JSON.parse(
    binding().nexmonDecodePcap(
      pcap,
      String(sourceId),
      u32(sessionId),
      port == null ? undefined : Number(port),
      chip == null ? undefined : String(chip),
    ),
  );
}

/**
 * Summarize a nexmon_csi `.pcap` file (link type, CSI frame count, channels,
 * bandwidths, chip versions + resolved chip names, RSSI range, time span).
 * @param {string} path
 * @param {number} [port] CSI UDP port (default 5500)
 * @returns {import('./index').NexmonPcapSummary}
 */
function inspectNexmonPcap(path, port) {
  return JSON.parse(binding().inspectNexmonPcap(String(path), port == null ? undefined : Number(port)));
}

/**
 * Decode a Broadcom d11ac chanspec word.
 * @param {number} chanspec
 * @returns {import('./index').DecodedChanspec}
 */
function decodeChanspec(chanspec) {
  return JSON.parse(binding().decodeChanspec(u32(chanspec)));
}

/**
 * Resolve a `chip_ver` word from a nexmon_csi packet to a chip slug
 * (`'bcm43455c0'` for a Raspberry Pi 3B+/4/400/5; `'unknown:0xNNNN'` otherwise).
 * @param {number} chipVer
 * @returns {string}
 */
function nexmonChipName(chipVer) {
  return binding().nexmonChipName(u32(chipVer));
}

/**
 * The AdapterProfile (channels / bandwidths / expected subcarrier counts /
 * capability flags) for a chip / Raspberry-Pi-model spec (`'pi5'`,
 * `'bcm43455c0'`, ...). Throws on an unknown spec.
 * @param {string} spec
 * @returns {import('./index').AdapterProfile}
 */
function nexmonProfile(spec) {
  return JSON.parse(binding().nexmonProfile(String(spec)));
}

/**
 * Listing of the Nexmon-supported chips + the Raspberry Pi models that carry
 * them (incl. the Pi 5 → BCM43455c0).
 * @returns {import('./index').NexmonChipsListing}
 */
function nexmonChips() {
  return JSON.parse(binding().nexmonChips());
}

/** Streaming capture runtime: a source + the DSP stage + the event pipeline. */
class RvCsi {
  /** @param {*} rt the underlying napi RvcsiRuntime handle */
  constructor(rt) {
    /** @private */
    this._rt = rt;
  }

  /** Open a `.rvcsi` capture file. @param {string} path @returns {RvCsi} */
  static openCaptureFile(path) {
    return new RvCsi(binding().RvcsiRuntime.openCaptureFile(String(path)));
  }

  /**
   * Open a Nexmon capture file (concatenated rvCSI Nexmon records).
   * @param {string} path @param {string} sourceId @param {number} sessionId @returns {RvCsi}
   */
  static openNexmonFile(path, sourceId, sessionId) {
    return new RvCsi(binding().RvcsiRuntime.openNexmonFile(String(path), String(sourceId), u32(sessionId)));
  }

  /**
   * Open a real nexmon_csi `.pcap` capture.
   * @param {string} path @param {string} sourceId @param {number} sessionId
   * @param {number} [port] CSI UDP port (default 5500) @returns {RvCsi}
   */
  static openNexmonPcap(path, sourceId, sessionId, port) {
    return new RvCsi(
      binding().RvcsiRuntime.openNexmonPcap(
        String(path),
        String(sourceId),
        u32(sessionId),
        port == null ? undefined : Number(port),
      ),
    );
  }

  /** Next exposable, validated frame, or `null` at end-of-stream. @returns {import('./index').CsiFrame|null} */
  nextFrame() {
    const s = this._rt.nextFrameJson();
    return s == null ? null : JSON.parse(s);
  }

  /** Like {@link RvCsi#nextFrame} but with the DSP pipeline applied. @returns {import('./index').CsiFrame|null} */
  nextCleanFrame() {
    const s = this._rt.nextCleanFrameJson();
    return s == null ? null : JSON.parse(s);
  }

  /** Drain the rest of the stream through DSP + the event pipeline. @returns {import('./index').CsiEvent[]} */
  drainEvents() {
    return JSON.parse(this._rt.drainEventsJson());
  }

  /** Current health snapshot. @returns {import('./index').SourceHealth} */
  health() {
    return JSON.parse(this._rt.healthJson());
  }

  /** Frames pulled from the source so far. @returns {number} */
  get framesSeen() {
    return this._rt.framesSeen;
  }

  /** Frames dropped by validation so far. @returns {number} */
  get framesDropped() {
    return this._rt.framesDropped;
  }
}

module.exports = {
  rvcsiVersion,
  nexmonShimAbiVersion,
  nexmonDecodeRecords,
  nexmonDecodePcap,
  inspectNexmonPcap,
  decodeChanspec,
  nexmonChipName,
  nexmonProfile,
  nexmonChips,
  inspectCaptureFile,
  eventsFromCaptureFile,
  exportCaptureToRfMemory,
  RvCsi,
};
