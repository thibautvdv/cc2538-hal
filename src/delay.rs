//! Delays

use core::convert::Infallible;

pub use crate::hal::delay::blocking::{DelayMs, DelayUs};
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
        Self { clocks, syst  }
    }

    pub fn free(self) -> SYST {
        self.syst
    }
}

impl DelayMs<u32> for Delay {
    type Error = Infallible;

    fn delay_ms(&mut self, ms: u32) -> Result<(), Self::Error> {
        self.delay_us(ms * 1_000)?;
        Ok(())
    }
}

impl DelayMs<u16> for Delay {
    type Error = Infallible;

    fn delay_ms(&mut self, ms: u16) -> Result<(), Self::Error> {
        self.delay_ms(ms as u32)?;
        Ok(())
    }
}

impl DelayMs<u8> for Delay {
    type Error = Infallible;

    fn delay_ms(&mut self, ms: u8) -> Result<(), Self::Error> {
        self.delay_ms(ms as u32)?;
        Ok(())
    }
}

impl DelayUs<u32> for Delay {
    type Error = Infallible;

    fn delay_us(&mut self, us: u32) -> Result<(), Self::Error> {
        let rvr = us * (self.clocks.sys_freq() / 1_000_000);

        debug_assert!(rvr < (1 << 24));

        self.syst.set_reload(rvr);
        self.syst.clear_current();
        self.syst.enable_counter();

        while !self.syst.has_wrapped() {}

        self.syst.disable_counter();
        Ok(())
    }
}

impl DelayUs<u16> for Delay {
    type Error = Infallible;

    fn delay_us(&mut self, us: u16) -> Result<(), Self::Error> {
        self.delay_us(us as u32)?;
        Ok(())
    }
}

impl DelayUs<u8> for Delay {
    type Error = Infallible;

    fn delay_us(&mut self, us: u8) -> Result<(), Self::Error> {
        self.delay_us(us as u32)?;
        Ok(())
    }
}
