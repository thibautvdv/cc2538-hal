use core::time::Duration;

use crate::sys_ctrl::ClockConfig;
use cortex_m::peripheral::{DCB, DWT};

/// A monotonic non-decreasing timer
///
/// This uses the timer in the debug watch trace peripheral. This means, that if the
/// core is stopped, the timer does not count up.
#[derive(Clone, Copy)]
pub struct MonoTimer {
    freq: u32,
}

impl MonoTimer {
    /// Creates a new `Monotonic` timer
    pub fn new(mut dwt: DWT, mut dcb: DCB, clocks: ClockConfig) -> Self {
        dcb.enable_trace();
        dwt.enable_cycle_counter();

        // now the CYCCNT counter can't be stopped or reset
        drop(dwt);

        Self {
            freq: clocks.sys_freq(),
        }
    }

    /// Returns the frequency at which the monotonic timer is operating at
    pub const fn frequency(self) -> u32 {
        self.freq
    }

    /// Returns an `Instant` corresponding to "now"
    pub fn now(self) -> Instant {
        Instant {
            now: DWT::cycle_count(),
        }
    }
}

/// A measurement of a monotonically non-decreasing clock
#[derive(Clone, Copy)]
pub struct Instant {
    now: u32,
}

impl Instant {
    /// Ticks elapsed since the `Instant` was created
    pub fn elapsed(self) -> u32 {
        DWT::cycle_count().wrapping_sub(self.now)
    }
}
