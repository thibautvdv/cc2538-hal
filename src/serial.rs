use crate::pac::Uart0;
use crate::pac::Uart1;

use core::convert::Infallible;
use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;
use core::task::{Context, Poll};

use crate::gpio::{AltFunc, PXx};
use crate::sys_ctrl::ClockConfig;
use crate::time::*;

use embedded_io::ErrorType;
use embedded_io::Read as SerialRead;
use embedded_io::Write as SerialWrite;

pub trait TxPin<UART> {}
pub trait RxPin<UART> {}

impl TxPin<Uart0> for PXx<AltFunc> {}
impl TxPin<Uart1> for PXx<AltFunc> {}

impl RxPin<Uart0> for PXx<AltFunc> {}
impl RxPin<Uart1> for PXx<AltFunc> {}

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

                    uart.cc().modify(|_,w| unsafe { w.cs().bits(0x1) });

                    if baud_rate*16 > clk {
                        // Enable high speed mode.
                        uart.ctl().modify(|_,w| w.hse().set_bit());
                        b_rate /= 2;
                    } else {
                        // Disable high speed mode
                        uart.ctl().modify(|_, w| w.hse().clear_bit());
                    }

                    let div = (((clk * 8)/b_rate)+1)/2;

                    // Set the baud rate
                    uart.ibrd().modify(|_, w| unsafe { w.divint().bits((div/64) as u16) });
                    uart.fbrd().modify(|_, w| unsafe { w.divfrac().bits((div%64) as u8) });

                    // Set parity, data length and number of stop bits
                    uart.lcrh().modify(|_, w| unsafe { w.wlen().bits(0x3).pen().clear_bit() });

                    // Enable the FIFO
                    uart.lcrh().modify(|_, w| w.fen().set_bit());

                    uart.ctl().modify(|_, w| w.uarten().set_bit().txe().set_bit().rxe().set_bit());

                    Self {
                        uart,
                        pins,
                    }
                }

                /// Start listening for an interrupt event.
                pub fn listen(&mut self, event: Event) {
                    match event {
                        Event::Rxne => self.uart.im().modify(|_, w| w.rxim().set_bit()),
                        Event::Txe => self.uart.im().modify(|_, w| w.txim().set_bit()),
                    };
                }

                /// Stop listening for an interrupt event.
                pub fn unlisten(&mut self, event: Event) {
                    match event {
                        Event::Rxne => self.uart.im().modify(|_, w| w.rxim().clear_bit()),
                        Event::Txe => self.uart.im().modify(|_, w| w.txim().clear_bit()),
                    };
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

            impl ErrorType for Rx<$UARTX> {
                type Error = core::convert::Infallible;
            }

            impl SerialRead for Rx<$UARTX> {
                fn read(&mut self, _buffer: &mut [u8]) -> Result<usize, Self::Error> {
                    let _uart = unsafe { &(*$UARTX::ptr()) };

                    todo!();
                }
            }

            impl ErrorType for Tx<$UARTX> {
                type Error = core::convert::Infallible;
            }

            impl SerialWrite for Tx<$UARTX> {
                fn write(&mut self, _buffer: &[u8]) -> Result<usize, Self::Error> {
                    let _uart = unsafe { &(*$UARTX::ptr()) };

                    todo!();
                }

                fn flush(&mut self) -> Result<(), Self::Error> {
                    let _uart = unsafe { &(*$UARTX::ptr()) };

                    todo!();
                }
            }
        )+
    };
}

uart! {
    Uart0: (uart0),
    Uart1: (uart1),
}
