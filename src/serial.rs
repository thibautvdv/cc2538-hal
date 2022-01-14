use crate::pac::UART0;
use crate::pac::UART1;

use core::convert::Infallible;
use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;
use core::task::{Context, Poll};

use crate::gpio::{AltFunc, PXx};
use crate::sys_ctrl::ClockConfig;
use crate::time::*;

use crate::hal::serial;

pub trait TxPin<UART> {}
pub trait RxPin<UART> {}

impl TxPin<UART0> for PXx<AltFunc> {}
impl TxPin<UART1> for PXx<AltFunc> {}

impl RxPin<UART0> for PXx<AltFunc> {}
impl RxPin<UART1> for PXx<AltFunc> {}

use core::fmt::Write;

pub enum Event {
    Rxne,
    Txe,
}

#[derive(Debug)]
pub enum Error {
    Framing,
    Noise,
    Overrun,
    Parity,
}

pub struct Rx<UART> {
    _uart: PhantomData<UART>,
}

pub struct Tx<UART> {
    _uart: PhantomData<UART>,
}

pub struct Serial<UART, PINS> {
    uart: UART,
    pins: PINS,
}

macro_rules! uart {
    ($(
        $UARTX:ident: ($uartX:ident),
    )+) => {
        $(
            impl<TX, RX> Serial<$UARTX, (TX, RX)> {
                /// Configures a UART peripheral to provide serial communication.
                pub fn $uartX(uart: $UARTX, pins: (TX, RX), baud_rate: u32, clocks: ClockConfig)
                    -> Self
                where
                    TX: TxPin<$UARTX>,
                    RX: RxPin<$UARTX>,
                {
                    let clk = clocks.io_freq();
                    let baud_rate = baud_rate;
                    let mut b_rate = baud_rate;

                    uart.cc.modify(|_,w| unsafe { w.cs().bits(0x1) });

                    if baud_rate*16 > clk {
                        // Enable high speed mode.
                        uart.ctl.modify(|_,w| w.hse().set_bit());
                        b_rate /= 2;
                    } else {
                        // Disable high speed mode
                        uart.ctl.modify(|_, w| w.hse().clear_bit());
                    }

                    let div = (((clk * 8)/b_rate)+1)/2;

                    // Set the baud rate
                    uart.ibrd.modify(|_, w| unsafe { w.divint().bits((div/64) as u16) });
                    uart.fbrd.modify(|_, w| unsafe { w.divfrac().bits((div%64) as u8) });

                    // Set parity, data length and number of stop bits
                    uart.lcrh.modify(|_, w| unsafe { w.wlen().bits(0x3).pen().clear_bit() });

                    // Enable the FIFO
                    uart.lcrh.modify(|_, w| w.fen().set_bit());

                    uart.ctl.modify(|_, w| w.uarten().set_bit().txe().set_bit().rxe().set_bit());

                    Self {
                        uart,
                        pins,
                    }
                }

                /// Start listening for an interrupt event.
                pub fn listen(&mut self, event: Event) {
                    match event {
                        Event::Rxne => self.uart.im.modify(|_, w| w.rxim().set_bit()),
                        Event::Txe => self.uart.im.modify(|_, w| w.txim().set_bit()),
                    }
                }

                /// Stop listening for an interrupt event.
                pub fn unlisten(&mut self, event: Event) {
                    match event {
                        Event::Rxne => self.uart.im.modify(|_, w| w.rxim().clear_bit()),
                        Event::Txe => self.uart.im.modify(|_, w| w.txim().clear_bit()),
                    }
                }

                /// Splits the `Serial` abstraction into a transmitter and a receiver half.
                pub fn split(self) -> (Tx<$UARTX>, Rx<$UARTX>) {
                    (
                        Tx {
                            _uart: PhantomData,
                        },
                        Rx {
                            _uart: PhantomData,
                        }
                    )
                }

                /// Release the UART peripheral and associated pins.
                pub fn free(self) -> ($UARTX, (TX, RX)) {
                    (self.uart, self.pins)
                }
            }

            impl serial::nb::Read<u8> for Rx<$UARTX> {
                type Error = nb::Error<Error>;

                fn read(&mut self) -> nb::Result<u8, Self::Error> {
                    todo!();
                }
            }

            impl serial::blocking::Write<u8> for Tx<$UARTX> {
                type Error = Error;


                fn flush(&mut self) -> Result<(), Self::Error> {
                    todo!();
                }

                fn write(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
                    let uart = unsafe { &(*$UARTX::ptr()) };
                    // Spin untill there is place in the FIFO
                    while uart.fr.read().txff().bit_is_set() {}

                    for b in buffer {
                        uart.dr.write(|w| unsafe { w.data().bits(*b) });
                    }

                    Ok(())
                }
            }

            impl Write for Tx<$UARTX> {
                fn write_str(&mut self, s: &str) -> Result<(), core::fmt::Error> {
                    for c in s.chars() {
                        self.write_char(c)?;
                    }
                    Ok(())
                }

                fn write_char(&mut self, c: char) -> Result<(), core::fmt::Error> {
                    use serial::blocking::Write;
                    self.write(&[c as u8]).unwrap();
                    Ok(())
                }
            }
        )+
    };
}

uart! {
    UART0: (uart0),
    UART1: (uart1),
}
