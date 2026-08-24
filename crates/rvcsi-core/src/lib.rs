//! # rvCSI core
//!
//! Foundation types for the rvCSI edge RF sensing runtime (ADR-095, ADR-096).
//!
//! Every CSI source is normalized into a [`CsiFrame`]; bounded sequences of
//! frames become a [`CsiWindow`]; semantic interpretations become a
//! [`CsiEvent`]. A [`CsiSource`] is the plugin trait every hardware/file/replay
//! adapter implements. Nothing crosses a language boundary (napi-rs / napi-c)
//! until [`validate_frame`] has run and the frame's [`ValidationStatus`] is
//! `Accepted` or `Degraded`.
//!
//! This crate is dependency-light (serde + thiserror only) and `no_std`-clean
//! in spirit so it can be reused from WASM later.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod adapter;
mod error;
mod event;
mod evidence;
mod frame;
mod ids;
mod simulation;
mod validation;
mod window;

pub use adapter::{AdapterKind, AdapterProfile, CsiSource, SourceConfig, SourceHealth};
pub use error::RvcsiError;
pub use event::{CsiEvent, CsiEventKind, EventError, MAX_EVENT_TTL_NS};
pub use evidence::{
    ChannelSoundingRole, ChannelSoundingStep, EventDisposition, EvidenceError, EvidenceExportScope,
    EvidenceQuality, GatewayEnvelopeContract, PrivacyClass, PseudonymousToken, QualityReason,
    SensingEvidence, SensingEvidencePayload, SourceCapability, SyntheticLabel, TokenAuthentication,
    TokenStatus, TrackAssociation, VerifiedGatewayEnvelope, MAX_ASSOCIATION_TTL_NS,
    MAX_CHANNEL_SOUNDING_CHANNEL_INDEX, MAX_CHANNEL_SOUNDING_RTT_NS, MAX_CHANNEL_SOUNDING_STEPS,
    MAX_EVIDENCE_TTL_NS, MAX_GATEWAY_TIMING_UNCERTAINTY_US, MAX_RVCS_PHASE_MILLIRADIANS,
    MAX_RVCS_RTT_PICOSECONDS, MAX_TOKEN_TTL_NS, MIN_ASSOCIATION_CONFIDENCE,
    MIN_CHANNEL_SOUNDING_STEPS,
};
pub use frame::{CsiFrame, ValidationStatus};
pub use ids::{EventId, FrameId, IdGenerator, SessionId, SourceId, WindowId};
pub use simulation::{
    run_ble_csi_crossing_simulation, FusionSimulationConfig, FusionSimulationError,
    FusionSimulationReport, FusionSimulationSummary,
};
pub use validation::{validate_frame, QualityScore, ValidationError, ValidationPolicy};
pub use window::CsiWindow;

/// Re-exported result type for the runtime.
pub type Result<T> = core::result::Result<T, RvcsiError>;
