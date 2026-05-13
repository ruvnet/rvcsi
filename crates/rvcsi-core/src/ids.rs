//! Identifier value objects.
//!
//! `FrameId`, `WindowId` and `EventId` are monotonic `u64` newtypes minted by
//! an [`IdGenerator`]. `SessionId` is also a `u64` (one per capture session).
//! `SourceId` wraps a human-readable string (`"esp32-com7"`, `"pcap:lab.pcap"`)
//! so logs and RuVector records stay legible.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

macro_rules! u64_newtype {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub struct $name(pub u64);

        impl $name {
            /// The raw integer value.
            #[inline]
            pub const fn value(self) -> u64 {
                self.0
            }
        }

        impl From<u64> for $name {
            #[inline]
            fn from(v: u64) -> Self {
                $name(v)
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}#{}", stringify!($name), self.0)
            }
        }
    };
}

u64_newtype!(
    /// Identifies one CSI observation within a capture session.
    FrameId
);
u64_newtype!(
    /// Identifies a capture session (one source + one runtime config).
    SessionId
);
u64_newtype!(
    /// Identifies a bounded window of frames.
    WindowId
);
u64_newtype!(
    /// Identifies a semantic event.
    EventId
);

/// Human-readable identifier for a CSI source.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SourceId(pub String);

impl SourceId {
    /// Construct from anything string-like.
    pub fn new(s: impl Into<String>) -> Self {
        SourceId(s.into())
    }

    /// Borrow the underlying string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for SourceId {
    fn from(s: &str) -> Self {
        SourceId(s.to_string())
    }
}

impl From<String> for SourceId {
    fn from(s: String) -> Self {
        SourceId(s)
    }
}

impl core::fmt::Display for SourceId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Monotonic id minter shared by a runtime instance.
///
/// Frame, window and event id spaces are independent. The generator is
/// `Send + Sync` (atomic counters) so it can be shared across the capture,
/// signal and event tasks.
#[derive(Debug, Default)]
pub struct IdGenerator {
    frame: AtomicU64,
    window: AtomicU64,
    event: AtomicU64,
    session: AtomicU64,
}

impl IdGenerator {
    /// A fresh generator with all counters at zero.
    pub const fn new() -> Self {
        IdGenerator {
            frame: AtomicU64::new(0),
            window: AtomicU64::new(0),
            event: AtomicU64::new(0),
            session: AtomicU64::new(0),
        }
    }

    /// Next frame id.
    pub fn next_frame(&self) -> FrameId {
        FrameId(self.frame.fetch_add(1, Ordering::Relaxed))
    }

    /// Next window id.
    pub fn next_window(&self) -> WindowId {
        WindowId(self.window.fetch_add(1, Ordering::Relaxed))
    }

    /// Next event id.
    pub fn next_event(&self) -> EventId {
        EventId(self.event.fetch_add(1, Ordering::Relaxed))
    }

    /// Next session id.
    pub fn next_session(&self) -> SessionId {
        SessionId(self.session.fetch_add(1, Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_generator_is_monotonic_and_independent() {
        let g = IdGenerator::new();
        assert_eq!(g.next_frame(), FrameId(0));
        assert_eq!(g.next_frame(), FrameId(1));
        assert_eq!(g.next_window(), WindowId(0));
        assert_eq!(g.next_event(), EventId(0));
        assert_eq!(g.next_frame(), FrameId(2));
        assert_eq!(g.next_session(), SessionId(0));
    }

    #[test]
    fn source_id_roundtrips_and_displays() {
        let s = SourceId::from("esp32-com7");
        assert_eq!(s.as_str(), "esp32-com7");
        assert_eq!(s.to_string(), "esp32-com7");
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<SourceId>(&json).unwrap(), s);
    }

    #[test]
    fn u64_newtype_display_and_serde() {
        let f = FrameId(42);
        assert_eq!(f.value(), 42);
        assert_eq!(f.to_string(), "FrameId#42");
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(json, "42");
        assert_eq!(serde_json::from_str::<FrameId>(&json).unwrap(), f);
    }
}
