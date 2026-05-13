/*
 * rvCSI — Nexmon CSI compatibility shim (napi-c layer, ADR-095 D2, ADR-096).
 *
 * This is the ONLY C in the rvCSI runtime. It is the seam against fragile
 * vendor/firmware byte formats; everything above this file is safe Rust.
 *
 * It exposes two record formats:
 *
 *  (1) the "rvCSI Nexmon record" — a compact, byte-defined, self-describing
 *      record (magic 'RVNX', RSSI, channel, timestamp, then interleaved int16
 *      I/Q in Q8.8 fixed point). Used by the recorder, replay, and tests.
 *
 *  (2) the *real* nexmon_csi UDP payload — what the patched Broadcom firmware
 *      (BCM43455c0 / 4358 / 4366c0, …) actually sends: an 18-byte header
 *      (magic 0x1111, RSSI, frame-control, source MAC, sequence, core/spatial
 *      stream, Broadcom chanspec, chip version) followed by `nsub` complex CSI
 *      samples. We implement the modern format (int16 LE I/Q interleaved — what
 *      CSIKit / csireader.py read for the 43455c0 et al.); the legacy packed-
 *      float export used by some 4339/4358 firmwares is a documented follow-up.
 *
 * Record (1) layout (all integers little-endian):
 *   off  size  field
 *     0     4  magic            = 0x52564E58  ('R','V','N','X')
 *     4     1  version          = RVCSI_NX_VERSION (1)
 *     5     1  flags            bit0: rssi present, bit1: noise floor present
 *     6     2  subcarrier_count N (1 .. RVCSI_NX_MAX_SUBCARRIERS)
 *     8     1  rssi_dbm         int8 (valid iff flags bit0)
 *     9     1  noise_dbm        int8 (valid iff flags bit1)
 *    10     2  channel          uint16
 *    12     2  bandwidth_mhz    uint16
 *    14     2  reserved         (0)
 *    16     8  timestamp_ns     uint64
 *    24   4*N  N pairs of int16 (i, q), interleaved, fixed-point Q8.8
 *   total = 24 + 4*N bytes;  stored int16 v maps to float v / 256.0
 *
 * Format (2) — nexmon_csi UDP payload header (all little-endian):
 *   off  size  field
 *     0     2  magic            = 0x1111
 *     2     1  rssi             int8 (dBm)
 *     3     1  fctl             uint8 (802.11 frame-control byte)
 *     4     6  src_mac          uint8[6]
 *    10     2  seq_cnt          uint16 (802.11 sequence-control)
 *    12     2  core_stream      uint16 (bits[2:0]=rx core, bits[5:3]=spatial stream)
 *    14     2  chanspec         uint16 (Broadcom d11ac chanspec)
 *    16     2  chip_ver         uint16 (e.g. 0x4345 = BCM43455c0)
 *    18   ...  CSI: nsub complex samples; for RVCSI_NX_CSI_FMT_INT16_IQ that is
 *               4*nsub bytes = nsub pairs of int16 LE (real, imag), raw counts.
 *   nsub is derived from the payload length: nsub = (len - 18) / 4.
 */
#ifndef RVCSI_NEXMON_SHIM_H
#define RVCSI_NEXMON_SHIM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RVCSI_NX_MAGIC 0x52564E58u /* 'R','V','N','X' little-endian */
#define RVCSI_NX_VERSION 1
#define RVCSI_NX_HEADER_BYTES 24
#define RVCSI_NX_MAX_SUBCARRIERS 2048
#define RVCSI_NX_FLAG_RSSI 0x01u
#define RVCSI_NX_FLAG_NOISE 0x02u

/* nexmon_csi UDP payload constants. */
#define RVCSI_NX_NEXMON_MAGIC 0x1111u
#define RVCSI_NX_NEXMON_HDR_BYTES 18

/* CSI body formats for rvcsi_nx_csi_udp_decode. */
#define RVCSI_NX_CSI_FMT_INT16_IQ 0   /* nsub pairs of int16 LE (real, imag) — the modern 43455c0/4358/4366c0 export */
/* (1 = legacy nexmon packed-float — not yet implemented; see header comment) */

/* Sentinel for "metadata field absent". */
#define RVCSI_NX_ABSENT_I16 ((int16_t)0x7FFF)

/* Error codes returned (positive; the negated value is used internally). */
typedef enum {
  RVCSI_NX_OK = 0,
  RVCSI_NX_ERR_TOO_SHORT = 1,      /* buffer shorter than the header */
  RVCSI_NX_ERR_BAD_MAGIC = 2,      /* rvCSI-record magic mismatch */
  RVCSI_NX_ERR_BAD_VERSION = 3,    /* unsupported rvCSI-record version */
  RVCSI_NX_ERR_CAPACITY = 4,       /* caller i/q buffer too small for N */
  RVCSI_NX_ERR_TRUNCATED = 5,      /* buffer shorter than the declared record */
  RVCSI_NX_ERR_ZERO_SUBCARRIERS = 6,
  RVCSI_NX_ERR_TOO_MANY_SUBCARRIERS = 7,
  RVCSI_NX_ERR_NULL_ARG = 8,
  RVCSI_NX_ERR_BAD_NEXMON_MAGIC = 9,  /* nexmon_csi UDP magic != 0x1111 */
  RVCSI_NX_ERR_BAD_CSI_LEN = 10,      /* (len - 18) not a positive multiple of 4 */
  RVCSI_NX_ERR_UNKNOWN_FORMAT = 11    /* csi_format not recognised */
} RvcsiNxError;

/* Decoded per-record metadata (the I/Q samples are written separately into
 * caller-provided float arrays). */
typedef struct RvcsiNxMeta {
  uint16_t subcarrier_count;
  uint16_t channel;
  uint16_t bandwidth_mhz;
  int16_t rssi_dbm;        /* RVCSI_NX_ABSENT_I16 if not present */
  int16_t noise_floor_dbm; /* RVCSI_NX_ABSENT_I16 if not present */
  uint64_t timestamp_ns;
} RvcsiNxMeta;

/* The parsed 18-byte nexmon_csi UDP header (raw vendor fields preserved). */
typedef struct RvcsiNxUdpHeader {
  int16_t rssi_dbm;       /* sign-extended from the int8 in the packet */
  uint8_t fctl;
  uint8_t src_mac[6];
  uint16_t seq_cnt;
  uint16_t core;          /* rx core index, core_stream bits [2:0] */
  uint16_t spatial_stream;/* spatial stream index, core_stream bits [5:3] */
  uint16_t chanspec;      /* raw Broadcom chanspec word */
  uint16_t chip_ver;
  uint16_t channel;       /* decoded from chanspec */
  uint16_t bandwidth_mhz; /* decoded from chanspec (0 = unknown) */
  uint8_t is_5ghz;        /* 1 if the chanspec band bits say 5 GHz, else 0 */
  uint16_t subcarrier_count; /* derived from the payload length: (len-18)/4 */
} RvcsiNxUdpHeader;

/* ----- rvCSI record (format 1) ---------------------------------------- */

/* Length, in bytes, of the rvCSI record at `buf` given `len` available, or 0 on
 * any problem (too short / bad magic / bad version / N out of range / truncated). */
size_t rvcsi_nx_record_len(const uint8_t *buf, size_t len);

/* Parse one rvCSI record at `buf`; fills `*meta` and writes `subcarrier_count`
 * floats into each of `i_out`/`q_out` (capacity `cap` each). Returns RVCSI_NX_OK
 * or a positive RvcsiNxError. No allocation, no globals. */
int rvcsi_nx_parse_record(const uint8_t *buf, size_t len, RvcsiNxMeta *meta,
                          float *i_out, float *q_out, size_t cap);

/* Serialize one rvCSI record into `buf` (capacity `cap`). Returns the byte count
 * (24 + 4*N) or 0 on error. */
size_t rvcsi_nx_write_record(uint8_t *buf, size_t cap, const RvcsiNxMeta *meta,
                             const float *i_in, const float *q_in);

/* ----- real nexmon_csi UDP payload (format 2) ------------------------- */

/* Decode a Broadcom d11ac chanspec word into channel / bandwidth (MHz) / band.
 * `out_channel` gets `chanspec & 0xff`; `out_bw_mhz` gets 20/40/80/160 (or 0 if
 * the bandwidth bits are unrecognised); `out_is_5ghz` gets 1 for the 5 GHz band
 * bits, 0 otherwise. Any out pointer may be NULL. Always succeeds. */
void rvcsi_nx_decode_chanspec(uint16_t chanspec, uint16_t *out_channel,
                              uint16_t *out_bw_mhz, uint8_t *out_is_5ghz);

/* Parse just the 18-byte nexmon_csi UDP header at `payload` (length `len`),
 * filling `*out` (including the chanspec-decoded channel/bandwidth and the
 * length-derived subcarrier count). Returns RVCSI_NX_OK or a positive error
 * (TOO_SHORT, BAD_NEXMON_MAGIC, BAD_CSI_LEN, NULL_ARG). */
int rvcsi_nx_csi_udp_header(const uint8_t *payload, size_t len,
                            RvcsiNxUdpHeader *out);

/* Full decode of a nexmon_csi UDP payload: parses the 18-byte header, then the
 * CSI body according to `csi_format` (currently only RVCSI_NX_CSI_FMT_INT16_IQ).
 * Fills `*meta` (channel/bandwidth from the chanspec, rssi from the header,
 * subcarrier_count from the length; `timestamp_ns` is left 0 — the caller stamps
 * it from the pcap packet time). Writes `subcarrier_count` floats into each of
 * `i_out`/`q_out` (capacity `cap`). If `hdr_out` is non-NULL it also receives the
 * full parsed header. Returns RVCSI_NX_OK or a positive RvcsiNxError. */
int rvcsi_nx_csi_udp_decode(const uint8_t *payload, size_t len, int csi_format,
                            RvcsiNxUdpHeader *hdr_out, RvcsiNxMeta *meta,
                            float *i_out, float *q_out, size_t cap);

/* Write a synthetic nexmon_csi UDP payload (the 18-byte header + int16 I/Q body)
 * into `buf` (capacity `cap`). Used by tests and the `nexmon` synthetic-source.
 * `i_in`/`q_in` hold `subcarrier_count` raw int16-valued samples each (clamped to
 * the int16 range on write). Returns the byte count (18 + 4*N) or 0 on error. */
size_t rvcsi_nx_csi_udp_write(uint8_t *buf, size_t cap, const RvcsiNxUdpHeader *hdr,
                              uint16_t subcarrier_count, const float *i_in,
                              const float *q_in);

/* ----- misc ----------------------------------------------------------- */

/* Static, human-readable string for an RvcsiNxError code. Never NULL. */
const char *rvcsi_nx_strerror(int code);

/* ABI version of this shim (`major << 16 | minor`); the Rust side asserts the
 * major matches. Bumped to 1.1 when the nexmon_csi UDP entry points were added. */
uint32_t rvcsi_nx_abi_version(void);

#ifdef __cplusplus
}
#endif

#endif /* RVCSI_NEXMON_SHIM_H */
