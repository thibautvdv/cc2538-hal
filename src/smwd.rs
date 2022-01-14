use core::cell::RefCell;

use cc2538_pac::NVIC;

use crate::sys_ctrl::ClockConfig;
use crate::{pac::SMWDTHROSC, sys_ctrl::ClockDiv};

pub trait SleepTimerExt {
    type Parts;

    fn split(self) -> Self::Parts;
}

#[derive(Debug)]
pub struct SleepTimer {
    smwdthrosc: SMWDTHROSC,
}

impl SleepTimerExt for SMWDTHROSC {
    type Parts = SleepTimer;

    fn split(self) -> Self::Parts {
        SleepTimer { smwdthrosc: self }
    }
}

impl SleepTimer {
    const PERIOD_NS: u32 = 31250;

    /// Get the current value of the sleep timer.
    #[inline]
    pub fn now(&self) -> u32 {
        //cortex_m::interrupt::free(|_| {
        let mut val = self.smwdthrosc.st0.read().st0().bits() as u32;
        val |= (self.smwdthrosc.st1.read().st1().bits() as u32) << 8;
        val |= (self.smwdthrosc.st2.read().st2().bits() as u32) << 16;
        val |= (self.smwdthrosc.st3.read().st3().bits() as u32) << 24;
        val
        //})
    }

    #[inline]
    fn set_ticks(&self, t: u32) {
        debug_assert!(t > self.now());

        while self.smwdthrosc.stload.read().stload().bit_is_clear() {}

        cortex_m::interrupt::free(|_| unsafe {
            self.smwdthrosc
                .st3
                .write(|w| w.st3().bits(((t >> 24) & 0xff) as u8));
            self.smwdthrosc
                .st2
                .write(|w| w.st2().bits(((t >> 16) & 0xff) as u8));
            self.smwdthrosc
                .st1
                .write(|w| w.st1().bits(((t >> 8) & 0xff) as u8));
            self.smwdthrosc
                .st0
                .write(|w| w.st0().bits((t & 0xff) as u8));
        });

        unsafe {
            NVIC::unmask(cc2538_pac::Interrupt::SM_TIMER);
        }
    }

    #[inline]
    pub fn wait_relative(&self, ticks: u32) {
        let ticks = self.now() + ticks;
        self.set_ticks(ticks);
    }

    #[inline]
    pub fn wait_absolute(&self, ticks: u32) {
        self.set_ticks(ticks);
    }
}
