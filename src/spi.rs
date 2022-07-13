use core::marker::PhantomData;

use cc2538_pac::{SSI0, SSI1};

use crate::sys_ctrl::ClockConfig;

pub enum ClockSource {
    /// The baud clock is determined by the SYS Div setting.
    /// The SSI system clock is determined by the SYS Div setting.
    SysDivSysDivClock = 0b000,
    /// The baud clock is determined by the SYS Div setting.
    /// The SSI system clock is on the same clock as the baud clock.
    SysDivBaudClock = 0b001,
    /// The baud clock is determined by the IO Div setting.
    /// The SSI system clock is determined by the SYS Div setting.
    IoDivSysDivClock = 0b100,
    /// The baud clock is determined by the IO Div setting.
    /// The SSI system clock is on the same clock as the baud clock.
    IoDivBaudClock = 0b101,
}

pub enum FrameFormat {
    Spi,
    TexasInstrumentSyncSerial,
    Microwave,
}

macro_rules! spi {
    (
        $spi:ident
    ) => {
        impl Spi<$spi, Disabled> {
            pub fn as_master(self) -> Self {
                unsafe { self.ssi.cr1.write_with_zero(|w| w) };
                self
            }

            pub fn as_slave(self) -> Self {
                self.ssi.cr1.modify(|_, w| w.ms().set_bit());
                self
            }

            /// Don't drive the output.
            /// This is only relevant in slave mode.
            pub fn disable_output(self) -> Self {
                self.ssi.cr1.modify(|_, w| w.sod().set_bit());
                self
            }

            pub fn set_clock_source(self, clock_source: ClockSource) -> Self {
                unsafe { self.ssi.cc.modify(|_, w| w.cs().bits(clock_source as u8)) };
                self
            }

            pub fn set_bit_rate(self, bit_rate: u32, clock_config: ClockConfig) -> Self {
                let div = 2 * bit_rate;
                let scr = (clock_config.sys_freq() + div - 1) / div;
                let scr = core::cmp::min(core::cmp::max(scr, 1), 256) - 1;

                unsafe {
                    self.ssi.cpsr.modify(|_, w| w.cpsdvsr().bits(2));
                }
                unsafe {
                    self.ssi.cr0.modify(|_, w| w.scr().bits(scr as u8));
                }

                self
            }

            pub fn enable(self) -> Spi<$spi, Enabled> {
                // 8-bit data transfer
                unsafe { self.ssi.cr0.modify(|_, w| w.dss().bits(0b0111)) };
                self.ssi.cr1.modify(|_, w| w.sse().set_bit());
                Spi {
                    ssi: self.ssi,
                    _state: PhantomData,
                }
            }
        }

        impl Spi<$spi, Enabled> {
            pub fn is_busy(&self) -> bool {
                self.ssi.sr.read().bsy().bit_is_set()
            }

            pub fn is_receive_fifo_full(&self) -> bool {
                self.ssi.sr.read().rff().bit_is_set()
            }

            pub fn is_receive_fifo_empty(&self) -> bool {
                !self.ssi.sr.read().rne().bit_is_set()
            }

            pub fn is_send_fifo_full(&self) -> bool {
                !self.ssi.sr.read().tnf().bit_is_set()
            }

            pub fn is_send_fifo_empty(&self) -> bool {
                self.ssi.sr.read().tfe().bit_is_set()
            }

            pub fn read_data(&self) -> u16 {
                (self.ssi.dr.read().bits() & 0x00ff) as u16
            }

            pub fn write(&self, data: &[u8]) {
                for b in data.iter() {
                    while self.is_send_fifo_full() {}
                    unsafe {
                        self.ssi.dr.write(|w| w.data().bits(*b as u16));
                    }
                }
            }
        }
    };
}

pub struct Disabled;
pub struct Enabled;

pub trait SpiSsi0Ext {
    type Parts;
    fn take(self) -> Self::Parts;
}

pub trait SpiSsi1Ext {
    type Parts;
    fn take(self) -> Self::Parts;
}

pub struct Spi<SSI, STATE> {
    ssi: SSI,
    _state: PhantomData<STATE>,
}

impl SpiSsi0Ext for SSI0 {
    type Parts = Spi<Self, Disabled>;

    fn take(self) -> Self::Parts {
        // Disble the SSI
        self.cr1.modify(|_, w| w.sse().clear_bit());

        Spi {
            ssi: self,
            _state: PhantomData,
        }
    }
}

impl SpiSsi1Ext for SSI1 {
    type Parts = Spi<Self, Disabled>;

    fn take(self) -> Self::Parts {
        // Disble the SSI
        self.cr1.modify(|_, w| w.sse().clear_bit());

        Spi {
            ssi: self,
            _state: PhantomData,
        }
    }
}

spi!(SSI0);
spi!(SSI1);
