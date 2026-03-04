//! No-op congestion controller for VPN tunneling.
//!
//! Inner TCP already handles congestion control; the outer QUIC CC
//! would double-penalize loss. This controller maintains a constant
//! window and ignores all congestion signals.

use std::any::Any;
use std::sync::Arc;
use std::time::Instant;

use quinn::congestion::{Controller, ControllerFactory};

/// Configuration for the no-op congestion controller.
#[derive(Debug, Clone)]
pub struct NoopCcConfig {
    window: u64,
}

impl NoopCcConfig {
    pub fn new(window: u64) -> Self {
        Self { window }
    }
}

impl ControllerFactory for NoopCcConfig {
    fn build(self: Arc<Self>, _now: Instant, _current_mtu: u16) -> Box<dyn Controller> {
        Box::new(NoopCc {
            window: self.window,
        })
    }
}

/// No-op congestion controller: constant window, ignores loss.
#[derive(Debug, Clone)]
struct NoopCc {
    window: u64,
}

impl Controller for NoopCc {
    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
        // Intentionally empty - never reduce window
    }

    fn on_mtu_update(&mut self, _new_mtu: u16) {}

    fn window(&self) -> u64 {
        self.window
    }

    fn initial_window(&self) -> u64 {
        self.window
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}
