//! Delays

use core::convert::Infallible;

pub use crate::hal::delay::DelayNs;
use crate::sys_ctrl::ClockConfig;
use cortex_m::peripheral::syst::SystClkSource;
use cortex_m::peripheral::SYST;

pub struct Delay {
    clocks: ClockConfig,
    syst: SYST,
}

impl Delay {
    pub fn new(mut syst: SYST, clocks: ClockConfig) -> Self {
        syst.set_clock_source(SystClkSource::Core);
        Self { clocks, syst }
    }

    pub fn free(self) -> SYST {
        self.syst
    }
}

impl DelayNs for Delay {
    fn delay_ns(&mut self, ns: u32) {
        let rvr = ns / 1000 * (self.clocks.sys_freq() / 1_000_000);

        debug_assert!(rvr < (1 << 24));

        self.syst.set_reload(rvr);
        self.syst.clear_current();
        self.syst.enable_counter();

        while !self.syst.has_wrapped() {}

        self.syst.disable_counter();
    }
}
