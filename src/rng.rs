//! Random Number Generator

use core::marker::PhantomData;

use cc2538_pac::{soc_adc, SocAdc};

use crate::radio::{Radio, RadioDriver, RadioOff, RadioOn, RxMode};

pub struct NotSeeded;
pub struct Seeded;

pub enum Operation {
    Normal,
    ClockOnce,
    Stop,
}

pub struct RngDriver<'p, STATE> {
    _rng: PhantomData<&'p mut SocAdc>,
    _state: PhantomData<STATE>,
}

impl<'p, STATE> RngDriver<'p, STATE> {
    fn regs() -> &'static soc_adc::RegisterBlock {
        unsafe { &*SocAdc::ptr() }
    }

    /// Enable the random number generator.
    fn on(&self) {
        unsafe { Self::regs().adccon1().modify(|_, w| w.rctrl().bits(0)) };
    }

    /// Disabl the random number generator.
    fn off(&self) {
        unsafe { Self::regs().adccon1().modify(|_, w| w.rctrl().bits(1)) };
    }

    fn enable_in_low_power_mode() {
        todo!()
    }
}

impl<'p, STATE> Drop for RngDriver<'p, STATE> {
    fn drop(&mut self) {
        // Disable the random number generator.
        self.off();
    }
}

impl<'p> RngDriver<'p, Seeded> {
    pub fn get_random(&self) -> u32 {
        unsafe {
            Self::regs()
                .adccon1()
                .write(|w| w.rctrl().bits(Operation::ClockOnce as u8))
        };
        Self::regs().rndl().read().bits() | (Self::regs().rndh().read().bits() << 8)
    }
}

impl<'p> RngDriver<'p, NotSeeded> {
    pub fn new_with_seed(_rng: &'p mut SocAdc, seed: u16) -> RngDriver<'p, Seeded> {
        let this = Self {
            _rng: PhantomData,
            _state: PhantomData,
        };

        this.on();

        unsafe {
            Self::regs()
                .rndl()
                .write(|w| w.rndl().bits(((seed >> 8) & 0xff) as u8));

            Self::regs()
                .rndl()
                .write(|w| w.rndl().bits((seed & 0xff) as u8));
        }

        RngDriver {
            _rng: PhantomData,
            _state: PhantomData,
        }
    }

    pub fn new_with_radio_seed(_rng: &'p mut SocAdc, radio: &mut Radio) -> RngDriver<'p, Seeded> {
        // Make sure the RNG is on.
        let this = Self {
            _rng: PhantomData,
            _state: PhantomData,
        };

        this.on();

        // Temporarely take the radio.
        let mut r = Radio::Undefined;
        core::mem::swap(&mut r, radio);

        let (mut r, enabled) = match r {
            Radio::Off(r) => (r.enable(None), false),
            Radio::On(r) => (r, true),
            Radio::Undefined => unreachable!(),
        };

        r.set_rx_mode(RxMode::InfiniteReception);

        // Wait untill transients of RX are gone.
        while !r.is_rssi_valid() {}

        let mut seed: u16 = 0;

        while seed == 0x0000 || seed == 0x8003 {
            for _ in 0..16 {
                seed |= r.random_data() as u16;
                seed <<= 1;
            }
        }

        // Writing twice to NRDL will seed the RNG.
        unsafe {
            Self::regs()
                .rndl()
                .write(|w| w.rndl().bits(((seed >> 8) & 0xff) as u8));

            Self::regs()
                .rndl()
                .write(|w| w.rndl().bits((seed & 0xff) as u8));
        }

        r.set_rx_mode(RxMode::Normal);

        let mut r = if !enabled {
            Radio::Off(r.disable())
        } else {
            Radio::On(r)
        };

        // Move back the radio.
        core::mem::swap(&mut r, radio);

        RngDriver {
            _rng: PhantomData,
            _state: PhantomData,
        }
    }
}
