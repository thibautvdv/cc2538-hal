//! Reset and Clock Control

use paste::paste;

use core::{marker::PhantomData, time::Duration};

use cortex_m::asm;

use crate::pac::{sys_ctrl, SysCtrl as SysCtrlPac};
use crate::time::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Osc {
    Osc32Mhz,
    Osc16Mhz,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockDiv {
    Clock32Mhz = 0b000,
    Clock16Mhz = 0b001,
    Clock8Mhz = 0b010,
    Clock4Mhz = 0b011,
    Clock2Mhz = 0b100,
    Clock1Mhz = 0b101,
    Clock05Mhz = 0b110,
    Clock025Mhz = 0b111,
}

impl ClockDiv {
    pub const fn as_freq(&self) -> u32 {
        match self {
            ClockDiv::Clock32Mhz => 32_000_000,
            ClockDiv::Clock16Mhz => 16_000_000,
            ClockDiv::Clock8Mhz => 8_000_000,
            ClockDiv::Clock4Mhz => 4_000_000,
            ClockDiv::Clock2Mhz => 2_000_000,
            ClockDiv::Clock1Mhz => 1_000_000,
            ClockDiv::Clock05Mhz => 50_000,
            ClockDiv::Clock025Mhz => 25_000,
        }
    }
}

pub struct Unconfigured;
pub struct Frozen;

pub struct SysCtrl<STATE> {
    sys_ctrl: SysCtrlPac,
    config: ClockConfig,
    _state: PhantomData<STATE>,
}

impl ClockConfig {
    pub const fn sys_freq(&self) -> u32 {
        self.sys_div.as_freq()
    }

    pub const fn io_freq(&self) -> u32 {
        self.io_div.as_freq()
    }

    pub const fn smwd_freq(&self) -> u32 {
        32_768
    }
}

macro_rules! impl_sys_ctrl {
    (
        [
            $(($name:ident = $new_name:ident
                    -> $active_reg:ident, $sleep_reg:ident, $deep_sleep_reg:ident)),+ $(,)?
        ],
        [
            $(($reset_name:ident = $new_reset_name:ident
                    -> $reset_reg:ident)),+ $(,)?
        ]
    ) => {
        paste! {
        pub trait SysCtrlExt {
            type Parts;
            fn constrain(self) -> Self::Parts;
        }

        impl SysCtrlExt for SysCtrlPac {
            type Parts = SysCtrl<Unconfigured>;
            fn constrain(self) -> Self::Parts {
                SysCtrl {
                    sys_ctrl: self,
                    config: Default::default(),
                    _state: PhantomData,
                }
            }
        }

        #[derive(Debug, Copy, Clone, Default)]
        pub struct Gated {
            active_mode: bool,
            sleep_mode: bool,
            deep_sleep_mode: bool,
        }

        #[derive(Debug, Copy, Clone)]
        pub struct ClockConfig {
            pub use_crystal_osc32k: bool,
            pub osc: Osc,
            pub io_div: ClockDiv,
            pub sys_div: ClockDiv,
            $(
                pub $new_name: Gated,
            )+
        }

        impl Default for ClockConfig {
            fn default() -> Self {
                Self {
                    use_crystal_osc32k: false,
                    osc: Osc::Osc16Mhz,
                    io_div: ClockDiv::Clock16Mhz,
                    sys_div: ClockDiv::Clock16Mhz,
                    $(
                        $new_name: Default::default(),
                    )+
                }
            }
        }

        impl<STATE> SysCtrl<STATE> {
            $(
            pub fn [<enable_ $new_name _in_active_mode>](&mut self) {
                self.config.$new_name.active_mode = true;
                self.sys_ctrl.$active_reg().modify(|_, w| w.$name().set_bit());
            }

            pub fn [<disable_ $new_name _in_active_mode>](&mut self) {
                self.config.$new_name.active_mode = false;
                self.sys_ctrl.$active_reg().modify(|_, w| w.$name().clear_bit());
            }

            pub fn [<enable_ $new_name _in_sleep_mode>](&mut self) {
                self.config.$new_name.sleep_mode = true;
                self.sys_ctrl.$sleep_reg().modify(|_, w| w.$name().set_bit());
            }

            pub fn [<disable_ $new_name _in_sleep_mode>](&mut self) {
                self.config.$new_name.sleep_mode = false;
                self.sys_ctrl.$sleep_reg().modify(|_, w| w.$name().clear_bit());
            }

            pub fn [<enable_ $new_name _in_deep_sleep_mode>](&mut self) {
                self.config.$new_name.deep_sleep_mode = true;
                self.sys_ctrl.$deep_sleep_reg().modify(|_, w| w.$name().set_bit());
            }

            pub fn [<disable_ $new_name _in_deep_sleep_mode>](&mut self) {
                self.config.$new_name.deep_sleep_mode = false;
                self.sys_ctrl.$deep_sleep_reg().modify(|_, w| w.$name().clear_bit());
            }
            )+

            $(
            pub fn [<reset_ $new_reset_name>](&mut self) {
                self.sys_ctrl.$reset_reg().modify(|_, w| w.$reset_name().set_bit());
            }
            pub fn [<clear_reset_ $new_reset_name>](&mut self) {
                self.sys_ctrl.$reset_reg().modify(|_, w| w.$reset_name().clear_bit());
            }
            )+
        }

        impl SysCtrl<Unconfigured> {
            pub fn disable_crystal_osc32k(&mut self) {
                self.config.use_crystal_osc32k = false;
            }

            pub fn set_osc(&mut self, osc: Osc) {
                self.config.osc = osc;
            }

            pub fn set_io_div(&mut self, div: ClockDiv) {
                self.config.io_div = div;
            }

            pub fn set_sys_div(&mut self, div: ClockDiv) {
                self.config.sys_div = div;
            }

            pub fn freeze(self) -> SysCtrl<Frozen> {
                if self.config.use_crystal_osc32k {
                    self.sys_ctrl
                        .clock_ctrl()
                        .modify(|_, w| w.osc32k().clear_bit());
                }

                self.sys_ctrl.clock_ctrl().modify(|_, w| unsafe {
                    w.amp_det()
                        .set_bit()
                        .osc()
                        .clear_bit()
                        .sys_div()
                        .bits(self.config.sys_div as u8)
                });

                self.sys_ctrl
                    .clock_ctrl()
                    .modify(|_, w| unsafe { w.io_div().bits(self.config.io_div as u8) });

                // Wait until the 32Mhz is stable.
                while self.sys_ctrl.clock_sta().read().osc().bit_is_set() {}

                // Return all frequencies
                SysCtrl {
                    sys_ctrl: self.sys_ctrl,
                    config: self.config,
                    _state: PhantomData,
                }
            }
        }

        impl SysCtrl<Frozen> {
            pub const fn config(&self) -> ClockConfig {
                self.config
            }
        }
        }
    };
}

impl_sys_ctrl!(
    [
        (gpt0 = gpt0 -> rcgcgpt, scgcgpt, dcgcgpt),
        (gpt1 = gpt1 -> rcgcgpt, scgcgpt, dcgcgpt),
        (gpt2 = gpt2 -> rcgcgpt, scgcgpt, dcgcgpt),
        (gpt3 = gpt3 -> rcgcgpt, scgcgpt, dcgcgpt),
        (ssi0 = ssi0 -> rcgcssi, scgcssi, dcgcssi),
        (ssi1 = ssi1 -> rcgcssi, scgcssi, dcgcssi),
        (uart0 = uart0 -> rcgcuart, scgcuart, dcgcuart),
        (uart1 = uart1 -> rcgcuart, scgcuart, dcgcuart),
        (i2c0 = i2c -> rcgci2c, scgci2c, dcgci2c),
        (pka = pka -> rcgcsec, scgcsec, dcgcsec),
        (aes = aes -> rcgcsec, scgcsec, dcgcsec),
        (rfc0 = radio -> rcgcrfc, scgcrfc, dcgcrfc),
    ],
    [
        (gpt0 = gpt0 -> srgpt),
        (gpt1 = gpt1 -> srgpt),
        (gpt2 = gpt2 -> srgpt),
        (gpt3 = gpt3 -> srgpt),
        (ssi0 = ssi0 -> srssi),
        (ssi1 = ssi1 -> srssi),
        (uart0 = uart0 -> sruart),
        (uart1 = uart1 -> sruart),
        (i2c0 = i2c -> sri2c),
        (pka = pka -> srsec),
        (aes = aes -> srsec),
    ]
);
