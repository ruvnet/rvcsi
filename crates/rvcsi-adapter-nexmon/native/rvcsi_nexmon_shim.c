/*
 * rvCSI — Nexmon CSI compatibility shim implementation (napi-c layer).
 * See rvcsi_nexmon_shim.h for the record/packet layouts and the contract.
 *
 * Deliberately tiny, allocation-free, and dependency-free (libc only). Every
 * read is bounds-checked against the caller-supplied length; nothing here can
 * scribble outside caller buffers, and nothing here panics or aborts.
 */
#include "rvcsi_nexmon_shim.h"

#include <string.h>

#define RVCSI_NX_ABI 0x00010001u /* major.minor = 1.1 (added the nexmon_csi UDP entry points) */

/* ---- little-endian load/store helpers (portable, no aliasing UB) ---- */

static uint16_t ld_u16(const uint8_t *p) {
  return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static uint32_t ld_u32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}
static uint64_t ld_u64(const uint8_t *p) {
  return (uint64_t)ld_u32(p) | ((uint64_t)ld_u32(p + 4) << 32);
}
static int16_t ld_i16(const uint8_t *p) { return (int16_t)ld_u16(p); }

static void st_u16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v & 0xFF);
  p[1] = (uint8_t)((v >> 8) & 0xFF);
}
static void st_u32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v & 0xFF);
  p[1] = (uint8_t)((v >> 8) & 0xFF);
  p[2] = (uint8_t)((v >> 16) & 0xFF);
  p[3] = (uint8_t)((v >> 24) & 0xFF);
}
static void st_u64(uint8_t *p, uint64_t v) {
  st_u32(p, (uint32_t)(v & 0xFFFFFFFFu));
  st_u32(p + 4, (uint32_t)((v >> 32) & 0xFFFFFFFFu));
}
static void st_i16(uint8_t *p, int16_t v) { st_u16(p, (uint16_t)v); }

/* Q8.8 fixed-point <-> float, with saturation on encode (rvCSI record format). */
static float q88_to_f(int16_t v) { return (float)v / 256.0f; }
static int16_t f_to_q88(float f) {
  float scaled = f * 256.0f;
  if (scaled >= 32767.0f) return (int16_t)32767;
  if (scaled <= -32768.0f) return (int16_t)-32768;
  if (scaled >= 0.0f) return (int16_t)(scaled + 0.5f);
  return (int16_t)(scaled - 0.5f);
}

/* Plain int16 <-> float for the raw nexmon_csi int16 I/Q export. */
static int16_t f_to_i16_sat(float f) {
  if (f >= 32767.0f) return (int16_t)32767;
  if (f <= -32768.0f) return (int16_t)-32768;
  if (f >= 0.0f) return (int16_t)(f + 0.5f);
  return (int16_t)(f - 0.5f);
}

uint32_t rvcsi_nx_abi_version(void) { return RVCSI_NX_ABI; }

const char *rvcsi_nx_strerror(int code) {
  switch (code) {
    case RVCSI_NX_OK: return "ok";
    case RVCSI_NX_ERR_TOO_SHORT: return "buffer too short for header";
    case RVCSI_NX_ERR_BAD_MAGIC: return "bad magic (not an rvCSI Nexmon record)";
    case RVCSI_NX_ERR_BAD_VERSION: return "unsupported record version";
    case RVCSI_NX_ERR_CAPACITY: return "output buffer too small for subcarrier count";
    case RVCSI_NX_ERR_TRUNCATED: return "buffer shorter than the declared record";
    case RVCSI_NX_ERR_ZERO_SUBCARRIERS: return "record declares zero subcarriers";
    case RVCSI_NX_ERR_TOO_MANY_SUBCARRIERS: return "record declares too many subcarriers";
    case RVCSI_NX_ERR_NULL_ARG: return "null argument";
    case RVCSI_NX_ERR_BAD_NEXMON_MAGIC: return "nexmon_csi UDP magic mismatch (expected 0x1111)";
    case RVCSI_NX_ERR_BAD_CSI_LEN: return "nexmon_csi CSI body length is not a positive multiple of 4";
    case RVCSI_NX_ERR_UNKNOWN_FORMAT: return "unknown CSI body format";
    default: return "unknown error";
  }
}

/* ===== rvCSI record (format 1) ======================================== */

static int validate_header(const uint8_t *buf, size_t len, uint16_t *out_n,
                           size_t *out_total) {
  if (len < (size_t)RVCSI_NX_HEADER_BYTES) return -RVCSI_NX_ERR_TOO_SHORT;
  if (ld_u32(buf) != RVCSI_NX_MAGIC) return -RVCSI_NX_ERR_BAD_MAGIC;
  if (buf[4] != (uint8_t)RVCSI_NX_VERSION) return -RVCSI_NX_ERR_BAD_VERSION;
  uint16_t n = ld_u16(buf + 6);
  if (n == 0) return -RVCSI_NX_ERR_ZERO_SUBCARRIERS;
  if (n > RVCSI_NX_MAX_SUBCARRIERS) return -RVCSI_NX_ERR_TOO_MANY_SUBCARRIERS;
  size_t total = (size_t)RVCSI_NX_HEADER_BYTES + (size_t)n * 4u;
  if (len < total) return -RVCSI_NX_ERR_TRUNCATED;
  *out_n = n;
  *out_total = total;
  return 0;
}

size_t rvcsi_nx_record_len(const uint8_t *buf, size_t len) {
  if (buf == NULL) return 0;
  uint16_t n;
  size_t total;
  if (validate_header(buf, len, &n, &total) < 0) return 0;
  return total;
}

int rvcsi_nx_parse_record(const uint8_t *buf, size_t len, RvcsiNxMeta *meta,
                          float *i_out, float *q_out, size_t cap) {
  if (buf == NULL || meta == NULL || i_out == NULL || q_out == NULL)
    return RVCSI_NX_ERR_NULL_ARG;

  uint16_t n;
  size_t total;
  int rc = validate_header(buf, len, &n, &total);
  if (rc < 0) return -rc;
  if ((size_t)n > cap) return RVCSI_NX_ERR_CAPACITY;

  uint8_t flags = buf[5];
  meta->subcarrier_count = n;
  meta->channel = ld_u16(buf + 10);
  meta->bandwidth_mhz = ld_u16(buf + 12);
  meta->rssi_dbm =
      (flags & RVCSI_NX_FLAG_RSSI) ? (int16_t)(int8_t)buf[8] : RVCSI_NX_ABSENT_I16;
  meta->noise_floor_dbm =
      (flags & RVCSI_NX_FLAG_NOISE) ? (int16_t)(int8_t)buf[9] : RVCSI_NX_ABSENT_I16;
  meta->timestamp_ns = ld_u64(buf + 16);

  const uint8_t *p = buf + RVCSI_NX_HEADER_BYTES;
  for (uint16_t k = 0; k < n; ++k) {
    i_out[k] = q88_to_f(ld_i16(p));
    q_out[k] = q88_to_f(ld_i16(p + 2));
    p += 4;
  }
  return RVCSI_NX_OK;
}

size_t rvcsi_nx_write_record(uint8_t *buf, size_t cap, const RvcsiNxMeta *meta,
                             const float *i_in, const float *q_in) {
  if (buf == NULL || meta == NULL || i_in == NULL || q_in == NULL) return 0;
  uint16_t n = meta->subcarrier_count;
  if (n == 0 || n > RVCSI_NX_MAX_SUBCARRIERS) return 0;
  size_t total = (size_t)RVCSI_NX_HEADER_BYTES + (size_t)n * 4u;
  if (cap < total) return 0;

  memset(buf, 0, RVCSI_NX_HEADER_BYTES);
  st_u32(buf, RVCSI_NX_MAGIC);
  buf[4] = (uint8_t)RVCSI_NX_VERSION;
  uint8_t flags = 0;
  if (meta->rssi_dbm != RVCSI_NX_ABSENT_I16) flags |= RVCSI_NX_FLAG_RSSI;
  if (meta->noise_floor_dbm != RVCSI_NX_ABSENT_I16) flags |= RVCSI_NX_FLAG_NOISE;
  buf[5] = flags;
  st_u16(buf + 6, n);
  buf[8] = (uint8_t)(int8_t)((flags & RVCSI_NX_FLAG_RSSI) ? meta->rssi_dbm : 0);
  buf[9] = (uint8_t)(int8_t)((flags & RVCSI_NX_FLAG_NOISE) ? meta->noise_floor_dbm : 0);
  st_u16(buf + 10, meta->channel);
  st_u16(buf + 12, meta->bandwidth_mhz);
  st_u16(buf + 14, 0);
  st_u64(buf + 16, meta->timestamp_ns);

  uint8_t *p = buf + RVCSI_NX_HEADER_BYTES;
  for (uint16_t k = 0; k < n; ++k) {
    st_i16(p, f_to_q88(i_in[k]));
    st_i16(p + 2, f_to_q88(q_in[k]));
    p += 4;
  }
  return total;
}

/* ===== real nexmon_csi UDP payload (format 2) ========================= */

/* Map a subcarrier (FFT) count to a bandwidth in MHz, per the standard nexmon
 * exports: 64->20, 128->40, 256->80, 512->160 (and the half-bands 32->10,
 * 16->5). Returns 0 if `nsub` doesn't look like one of those. */
static uint16_t bw_from_nsub(uint16_t nsub) {
  switch (nsub) {
    case 16:  return 5;
    case 32:  return 10;
    case 64:  return 20;
    case 128: return 40;
    case 256: return 80;
    case 512: return 160;
    default:  return 0;
  }
}

/* Broadcom d11ac chanspec bandwidth field (bits [13:11]) -> MHz. */
static uint16_t bw_from_chanspec(uint16_t chanspec) {
  switch ((chanspec >> 11) & 0x7u) {
    case 2: return 20;
    case 3: return 40;
    case 4: return 80;
    case 5: return 160;
    case 6: return 80; /* 80+80: report the per-segment width */
    default: return 0;
  }
}

void rvcsi_nx_decode_chanspec(uint16_t chanspec, uint16_t *out_channel,
                              uint16_t *out_bw_mhz, uint8_t *out_is_5ghz) {
  uint16_t channel = (uint16_t)(chanspec & 0x00FFu);
  uint16_t bw = bw_from_chanspec(chanspec);
  /* Band bits [15:14]: d11ac 5 GHz == 0b11. Cross-check with the channel number
   * for robustness against older chanspec encodings. */
  uint8_t band_is_5ghz = (((chanspec >> 14) & 0x3u) == 0x3u) ? 1u : 0u;
  if (!band_is_5ghz && channel > 14u) band_is_5ghz = 1u;
  if (band_is_5ghz && channel >= 1u && channel <= 13u && bw == 20u) {
    /* almost certainly a 2.4 GHz control channel mislabeled by an old encoding */
    band_is_5ghz = 0u;
  }
  if (out_channel) *out_channel = channel;
  if (out_bw_mhz) *out_bw_mhz = bw;
  if (out_is_5ghz) *out_is_5ghz = band_is_5ghz;
}

/* Validate + parse the 18-byte header; on success returns N (subcarrier count)
 * and fills *out. On failure returns a negative RvcsiNxError. */
static int parse_nexmon_header(const uint8_t *payload, size_t len,
                               RvcsiNxUdpHeader *out, uint16_t *out_n) {
  if (payload == NULL || out == NULL) return -RVCSI_NX_ERR_NULL_ARG;
  if (len < (size_t)RVCSI_NX_NEXMON_HDR_BYTES) return -RVCSI_NX_ERR_TOO_SHORT;
  if (ld_u16(payload) != RVCSI_NX_NEXMON_MAGIC) return -RVCSI_NX_ERR_BAD_NEXMON_MAGIC;

  size_t csi_bytes = len - (size_t)RVCSI_NX_NEXMON_HDR_BYTES;
  if (csi_bytes == 0u || (csi_bytes % 4u) != 0u) return -RVCSI_NX_ERR_BAD_CSI_LEN;
  size_t nsub = csi_bytes / 4u;
  if (nsub > RVCSI_NX_MAX_SUBCARRIERS) return -RVCSI_NX_ERR_TOO_MANY_SUBCARRIERS;

  uint16_t core_stream = ld_u16(payload + 12);
  uint16_t chanspec = ld_u16(payload + 14);

  memset(out, 0, sizeof(*out));
  out->rssi_dbm = (int16_t)(int8_t)payload[2];
  out->fctl = payload[3];
  memcpy(out->src_mac, payload + 4, 6);
  out->seq_cnt = ld_u16(payload + 10);
  out->core = (uint16_t)(core_stream & 0x7u);
  out->spatial_stream = (uint16_t)((core_stream >> 3) & 0x7u);
  out->chanspec = chanspec;
  out->chip_ver = ld_u16(payload + 16);
  rvcsi_nx_decode_chanspec(chanspec, &out->channel, &out->bandwidth_mhz, &out->is_5ghz);
  out->subcarrier_count = (uint16_t)nsub;
  /* Prefer the FFT-derived bandwidth when the chanspec bits are missing/odd. */
  {
    uint16_t bw_n = bw_from_nsub((uint16_t)nsub);
    if (bw_n != 0u) out->bandwidth_mhz = bw_n;
  }
  *out_n = (uint16_t)nsub;
  return 0;
}

int rvcsi_nx_csi_udp_header(const uint8_t *payload, size_t len,
                            RvcsiNxUdpHeader *out) {
  uint16_t n;
  int rc = parse_nexmon_header(payload, len, out, &n);
  return (rc < 0) ? -rc : RVCSI_NX_OK;
}

int rvcsi_nx_csi_udp_decode(const uint8_t *payload, size_t len, int csi_format,
                            RvcsiNxUdpHeader *hdr_out, RvcsiNxMeta *meta,
                            float *i_out, float *q_out, size_t cap) {
  if (meta == NULL || i_out == NULL || q_out == NULL) return RVCSI_NX_ERR_NULL_ARG;
  if (csi_format != RVCSI_NX_CSI_FMT_INT16_IQ) return RVCSI_NX_ERR_UNKNOWN_FORMAT;

  RvcsiNxUdpHeader hdr;
  uint16_t n;
  int rc = parse_nexmon_header(payload, len, &hdr, &n);
  if (rc < 0) return -rc;
  if ((size_t)n > cap) return RVCSI_NX_ERR_CAPACITY;

  meta->subcarrier_count = n;
  meta->channel = hdr.channel;
  meta->bandwidth_mhz = hdr.bandwidth_mhz;
  meta->rssi_dbm = hdr.rssi_dbm; /* always present in the nexmon header */
  meta->noise_floor_dbm = RVCSI_NX_ABSENT_I16; /* not carried by nexmon_csi */
  meta->timestamp_ns = 0u; /* the caller stamps this from the pcap packet time */

  const uint8_t *p = payload + RVCSI_NX_NEXMON_HDR_BYTES;
  for (uint16_t k = 0; k < n; ++k) {
    i_out[k] = (float)ld_i16(p);     /* real, raw int16 count */
    q_out[k] = (float)ld_i16(p + 2); /* imag, raw int16 count */
    p += 4;
  }
  if (hdr_out) *hdr_out = hdr;
  return RVCSI_NX_OK;
}

size_t rvcsi_nx_csi_udp_write(uint8_t *buf, size_t cap, const RvcsiNxUdpHeader *hdr,
                              uint16_t subcarrier_count, const float *i_in,
                              const float *q_in) {
  if (buf == NULL || hdr == NULL || i_in == NULL || q_in == NULL) return 0;
  if (subcarrier_count == 0u || subcarrier_count > RVCSI_NX_MAX_SUBCARRIERS) return 0;
  size_t total = (size_t)RVCSI_NX_NEXMON_HDR_BYTES + (size_t)subcarrier_count * 4u;
  if (cap < total) return 0;

  memset(buf, 0, RVCSI_NX_NEXMON_HDR_BYTES);
  st_u16(buf, RVCSI_NX_NEXMON_MAGIC);
  buf[2] = (uint8_t)(int8_t)hdr->rssi_dbm;
  buf[3] = hdr->fctl;
  memcpy(buf + 4, hdr->src_mac, 6);
  st_u16(buf + 10, hdr->seq_cnt);
  st_u16(buf + 12, (uint16_t)((hdr->core & 0x7u) | ((hdr->spatial_stream & 0x7u) << 3)));
  st_u16(buf + 14, hdr->chanspec);
  st_u16(buf + 16, hdr->chip_ver);

  uint8_t *p = buf + RVCSI_NX_NEXMON_HDR_BYTES;
  for (uint16_t k = 0; k < subcarrier_count; ++k) {
    st_i16(p, f_to_i16_sat(i_in[k]));
    st_i16(p + 2, f_to_i16_sat(q_in[k]));
    p += 4;
  }
  return total;
}
