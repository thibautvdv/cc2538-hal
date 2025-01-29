//! General Purpose Input / Output

use core::marker::PhantomData;

pub use crate::hal::digital::*;
use crate::ioc::*;

use paste::paste;

/// Extension trait to split a GPIO peripheral in independent pins and registers
pub trait GpioExt {
    /// The to split the GPIO into
    type Parts;

    /// Splits the GPIO block into independent pins and registers
    fn split(self) -> Self::Parts;
}

/// Enum to select a direction for the pin
#[repr(u8)]
pub enum Direction {
    Input = 0,
    Output = 1,
}

/// Enum to select the pad override
#[repr(u8)]
pub enum PadOveride {
    Output = 0x8,
    PullUp = 0x4,
    PullDown = 0x2,
    Analog = 0x1,
    Disabled = 0x0,
}

/// Output type state
#[derive(Debug, Clone, Copy)]
pub struct Output<MODE> {
    _mode: PhantomData<MODE>,
}

/// Output enable mode type state
#[derive(Debug, Clone, Copy)]
pub struct OutputEnable;

/// Input type state
#[derive(Debug, Clone, Copy)]
pub struct Input<MODE> {
    _mode: PhantomData<MODE>,
}

/// Input pull up mode type state
#[derive(Debug, Clone, Copy)]
pub struct PullUpEnable;
/// Input pull down mode type state
#[derive(Debug, Clone, Copy)]
pub struct PullDownEnable;
/// Input analog mode type state
#[derive(Debug, Clone, Copy)]
pub struct AnalogEnable;

/// Pin type state
#[derive(Debug, Clone, Copy)]
pub struct AltFunc;

#[repr(u8)]
pub enum OutputFunction {
    Uart0Txd = 0x0,
    Uart1Rts = 0x1,
    Uart1Txd = 0x2,
    Ssi0Tx = 0x3,
    Ssi0ClkOut = 0x4,
    Ssi0FssOut = 0x5,
    Ssi0TxSerOut = 0x6,
    Ssi1Txd = 0x7,
    Ssi1ClkOut = 0x8,
    Ssi1FssOut = 0x9,
    Ssi1TxSerOut = 0xa,
    I2cSda = 0xb,
    I2cScl = 0xc,
    Gpt0Cp1 = 0xd,
    Gpt0Cp2 = 0xe,
    Gpt1Cp1 = 0xf,
    Gpt1Cp2 = 0x10,
    Gpt2Cp1 = 0x11,
    Gpt2Cp2 = 0x12,
    Gpt3Cp1 = 0x13,
    Gpt3Cp2 = 0x14,
}

macro_rules! gpio {
    (
        [
            $({
                GPIO: $GPIOX:ident,
                gpio_enum: $gpio_enum:ident,
                gpio: $gpiox:ident,
                gpio_mapped: $gpioy:ident,
                partially_erased_pin: $PXx:ident,
                pins: [
                    $(
                        $PXi:ident:
                            ($pxi:ident, $pin:expr, $MODE:ty, $padover:ident, $afsel:ident),
                    )+
                ],
            },)+
        ],
        [
            $({$alt_out_fun:ident: $alt_out_reg:ident },)+
        ]
    ) => {
        use crate::hal::digital::InputPin as InputPinTrait;
        use crate::hal::digital::OutputPin as OutputPinTrait;

        $(
            use crate::pac::$GPIOX;
        )+

        #[derive(Debug, Clone, Copy)]
        pub enum Gpio {
            $(
                $gpio_enum,
            )+
        }

        /// Fully erased pin
        #[derive(Debug, Clone, Copy)]
        pub struct PXx<MODE> {
            pin: u8,
            gpio: Gpio,
            _mode: PhantomData<MODE>,
        }

        impl<MODE> PXx<MODE> {
            fn set_afsel(&mut self, set: bool) {
                match &self.gpio {
                    $(
                        Gpio::$gpio_enum => {
                            unsafe { (*$GPIOX::ptr()).afsel().modify(|r,w| {
                                w.afsel().bits(
                                    (r.afsel().bits() & !(1 << self.pin)) | ((set as u8) << self.pin))
                            }); }
                        },
                    )*
                }
            }

            $(
                /// Set the pin to the specified function.
                pub fn $alt_out_fun(&mut self, alt_reg: &mut $alt_out_reg) -> PXx<AltFunc> {
                    self.set_afsel(true);

                    paste! {
                    alt_reg.[<$alt_out_reg:snake>]().write(
                        |w| unsafe { w.bits( (self.gpio as u32 * 8) + (self.pin as u32)) }
                    );
                    }
                    PXx { pin: self.pin, gpio: self.gpio, _mode: PhantomData }
                }
            )+
        }

        impl<MODE> ErrorType for PXx<Output<MODE>> {
            type Error = core::convert::Infallible;
        }

        impl<MODE> OutputPin for PXx<Output<MODE>> {
            fn set_high(&mut self) -> Result<(), Self::Error> {
                match &self.gpio {
                    $(
                    Gpio::$gpio_enum => {
                        let addr = $GPIOX::ptr() as *mut u32;
                        let offset = 1 << self.pin;
                        unsafe { *addr.offset(offset) = offset as u32; }
                    }
                    )+
                }
                Ok(())
            }

            fn set_low(&mut self) -> Result<(), Self::Error> {
                match &self.gpio {
                    $(
                    Gpio::$gpio_enum => {
                        let addr = $GPIOX::ptr() as *mut u32;
                        let offset = 1 << self.pin;
                        unsafe { *addr.offset(offset) = 0u32; }
                    }
                    )+
                }
                Ok(())
            }
        }

        impl<MODE> ErrorType for PXx<Input<MODE>> {
            type Error = core::convert::Infallible;
        }

        impl<MODE> InputPinTrait for PXx<Input<MODE>> {
            fn is_high(&mut self) -> Result<bool, Self::Error> {
                Ok(!self.is_low()?)
            }

            fn is_low(&mut self) -> Result<bool, Self::Error> {
                match &self.gpio {
                    $(
                    Gpio::$gpio_enum => {
                        let addr = $GPIOX::ptr() as *mut u32;
                        let offset = 1 << self.pin;
                        Ok(unsafe { *addr.offset(offset) == 0 })
                    }
                    )+
                }
            }
        }


        $(
            pub mod $gpiox {
                use paste::paste;
                use core::marker::PhantomData;

                use crate::pac::{$gpioy, $GPIOX};

                use crate::hal::digital::OutputPin as OutputPinTrait;
                use crate::hal::digital::InputPin as InputPinTrait;
                use crate::hal::digital::ErrorType;

                use super::{
                    Input, Output, OutputEnable, PullUpEnable, PullDownEnable,
                    AnalogEnable, GpioExt, PXx, Gpio, Direction, PadOveride,
                    OutputFunction, AltFunc,
                };

                /// GPIO parts
                #[derive(Debug)]
                pub struct Parts {
                    /// Opaque DATA part
                    pub data: DATA,
                    /// Opaque DIR part
                    pub dir: DIR,
                    /// Opaque AFSEL part
                    pub afsel: AFSEL,

                    $(
                        pub $pxi: $PXi<$MODE>,
                    )+
                }

                impl GpioExt for $GPIOX {
                    type Parts = Parts;

                    fn split(self) -> Parts {
                        Parts {
                            data: DATA {},
                            dir: DIR {},
                            afsel: AFSEL {},
                            $(
                                $pxi: $PXi { _mode: PhantomData },
                            )+
                        }
                    }
                }

                #[derive(Debug, Clone, Copy)]
                pub struct $PXx<MODE> {
                    pin: u8,
                    _mode: PhantomData<MODE>,
                }

                impl<MODE> $PXx<MODE> {
                    pub fn downgrade(self) -> PXx<MODE> {
                        PXx {
                            pin: self.pin,
                            gpio: Gpio::$gpio_enum,
                            _mode: self._mode,
                        }
                    }
                }

                impl<MODE> ErrorType for $PXx<Output<MODE>> {
                    type Error = core::convert::Infallible;
                }

                impl<MODE> OutputPinTrait for $PXx<Output<MODE>> {
                    fn set_high(&mut self) -> Result<(), Self::Error> {
                        let addr = $GPIOX::ptr() as *mut u32;
                        let offset = 1 << self.pin;
                        unsafe { *addr.offset(offset) = offset as u32; }
                        Ok(())
                    }

                    fn set_low(&mut self) -> Result<(), Self::Error> {
                        let addr = $GPIOX::ptr() as *mut u32;
                        let offset = 1 << self.pin;
                        unsafe { *addr.offset(offset) = 0u32; }
                        Ok(())
                    }
                }

                impl<MODE> ErrorType for $PXx<Input<MODE>> {
                    type Error = core::convert::Infallible;
                }

                impl<MODE> InputPinTrait for $PXx<Input<MODE>> {
                    fn is_high(&mut self) -> Result<bool, Self::Error> {
                        Ok(!self.is_low()?)
                    }

                    fn is_low(&mut self) -> Result<bool, Self::Error> {
                        let addr = $GPIOX::ptr() as *mut u32;
                        let offset = 1 << self.pin;
                        Ok(unsafe { *addr.offset(offset) == 0u32 })
                    }

                }

                /// Opaque DATA register
                #[derive(Debug)]
                pub struct DATA;

                /// Opaque DIR register
                #[derive(Debug)]
                pub struct DIR;

                impl DIR {
                    pub(crate) fn dir(&mut self) -> &$gpioy::Dir {
                        unsafe { &(*$GPIOX::ptr()).dir() }
                    }
                }

                /// Opaque AFSEL register
                #[derive(Debug)]
                pub struct AFSEL;

                impl AFSEL {
                    pub(crate) fn afsel(&mut self) -> &$gpioy::Afsel {
                        unsafe { &(*$GPIOX::ptr()).afsel() }
                    }
                }

                $(
                    use crate::ioc::$padover;
                    use crate::ioc::$afsel;

                    #[derive(Debug, Clone, Copy)]
                    pub struct $PXi<MODE> {
                        _mode: PhantomData<MODE>,
                    }

                    impl<MODE> $PXi<MODE> {
                        pub fn downgrade(self) -> PXx<MODE> {
                            PXx {
                                pin: $pin,
                                gpio: Gpio::$gpio_enum,
                                _mode: self._mode,
                            }
                        }

                        /// Configure the pin to operate as an output pin
                        pub fn into_output_enable_output(
                            self,
                            dir: &mut DIR,
                            pad_over: &mut $padover
                        ) -> $PXi<Output<OutputEnable>> {
                            self.set_direction(dir, Direction::Output);
                            Self::set_overide_configuretion_register(
                                pad_over,
                                PadOveride::Output,
                            );
                            $PXi { _mode: PhantomData }
                        }

                        /// Configure the pin to operate as a pull up input pin
                        pub fn into_pull_up_enable_input(
                            self,
                            dir: &mut DIR,
                            pad_over: &mut $padover
                        ) -> $PXi<Input<PullUpEnable>> {
                            self.set_direction(dir, Direction::Input);
                            Self::set_overide_configuretion_register(
                                pad_over,
                                PadOveride::PullUp,
                            );
                            $PXi { _mode: PhantomData }
                        }

                        /// Configure the pin to operate as a pull down input pin
                        pub fn into_pull_down_enable_input(
                            self,
                            dir: &mut DIR,
                            pad_over: &mut $padover
                        ) -> $PXi<Input<PullDownEnable>> {
                            self.set_direction(dir, Direction::Input);
                            Self::set_overide_configuretion_register(
                                pad_over,
                                PadOveride::PullDown,
                            );
                            $PXi { _mode: PhantomData }
                        }

                        /// Configure the pin to operate as an analog input pin
                        pub fn into_analog_input(self, dir: &mut DIR, pad_over: &mut $padover)
                            -> $PXi<Input<AnalogEnable>> {
                            self.set_direction(dir, Direction::Input);
                            Self::set_overide_configuretion_register(
                                pad_over,
                                PadOveride::Analog
                            );
                            $PXi { _mode: PhantomData }
                        }

                        fn set_overide_configuretion_register(
                            pad_over: &mut $padover, over: PadOveride)
                        {
                            paste! {
                            pad_over.[<$padover:snake>]().write(|w| unsafe { w.bits(over as u32) });
                            }
                        }

                        pub fn set_direction(&self, dir: &mut DIR, direction: Direction) {
                            dir.dir().modify(|r, w| unsafe {
                                w.dir().bits(
                                    (r.dir().bits() & !(1 << $pin)) | ((direction as u8) << $pin))
                            });

                        }

                        pub(crate) const fn as_pin_selector(&self) -> u32 {
                            (Gpio::$gpio_enum as u32 * 8) + $pin as u32
                        }

                        /// Set the pin as an alternative function output pin.
                        ///
                        /// Arguments:
                        ///
                        /// * `afsel`: The port register to enable hardware alternate function for this pin.
                        /// * `afsel_reg`: The IOC SEL register for this pin.
                        /// * `func`: The selected alternate function.
                        pub fn into_alt_output_function(self, dir: &mut DIR, afsel: &mut AFSEL, afsel_reg: &mut $afsel, pad_over: &mut $padover, func: OutputFunction) -> $PXi<AltFunc> {
                            self.set_direction(dir, Direction::Output);

                            Self::set_overide_configuretion_register(
                                pad_over,
                                PadOveride::Output,
                            );

                            // Set the specific pin to an alternate function
                            afsel.afsel().modify(|r, w| unsafe {
                                w.afsel().bits(
                                    (r.afsel().bits() & !(1 << $pin)) | (1 << $pin))
                            });

                            // Select the alternate function
                            paste! {
                            afsel_reg.[<$afsel:snake>]().write(|w| unsafe { w.bits(func as u32 ) });
                            }

                            $PXi { _mode: PhantomData }
                        }

                        pub fn set_pad_overide(&mut self, pad_over: &mut $padover, overide: PadOveride) {
                            Self::set_overide_configuretion_register(
                                pad_over,
                                overide,
                            )
                        }
                    }

                    impl ErrorType for $PXi<Output<OutputEnable>> {
                        type Error = core::convert::Infallible;
                    }

                    impl OutputPinTrait for $PXi<Output<OutputEnable>> {
                        fn set_high(&mut self) -> Result<(), Self::Error> {
                            let addr = $GPIOX::ptr() as *mut u32;
                            let offset = 1 << $pin;
                            unsafe { *addr.offset(offset) = offset as u32; }
                            Ok(())
                        }

                        fn set_low(&mut self) -> Result<(), Self::Error> {
                            let addr = $GPIOX::ptr() as *mut u32;
                            let offset = 1 << $pin;
                            unsafe { *addr.offset(offset) = 0u32; }
                            Ok(())
                        }
                    }

                    impl<MODE> ErrorType for $PXi<Input<MODE>> {
                        type Error = core::convert::Infallible;
                    }

                    impl<MODE> InputPinTrait for $PXi<Input<MODE>> {
                        fn is_high(&mut self) -> Result<bool, Self::Error> {
                            Ok(!self.is_low()?)
                        }

                        fn is_low(&mut self) -> Result<bool, Self::Error> {
                            let addr = $GPIOX::ptr() as *mut u32;
                            let offset = 1 << $pin;
                            Ok(unsafe { *addr.offset(offset) == 0  })
                        }
                    }
                )+
            }
        )+
    };
}

gpio!(
[
    {
        GPIO: GpioA,
        gpio_enum: GpioA,
        gpio: gpioa,
        gpio_mapped: gpio_a,
        partially_erased_pin: PAx,
        pins: [
            PA0: (pa0, 0, Input<PullUpEnable>, Pa0Over, Pa0Sel),
            PA1: (pa1, 1, Input<PullUpEnable>, Pa1Over, Pa1Sel),
            PA2: (pa2, 2, Input<PullUpEnable>, Pa2Over, Pa2Sel),
            PA3: (pa3, 3, Input<PullUpEnable>, Pa3Over, Pa3Sel),
            PA4: (pa4, 4, Input<PullUpEnable>, Pa4Over, Pa4Sel),
            PA5: (pa5, 5, Input<PullUpEnable>, Pa5Over, Pa5Sel),
            PA6: (pa6, 6, Input<PullUpEnable>, Pa6Over, Pa6Sel),
            PA7: (pa7, 7, Input<PullUpEnable>, Pa7Over, Pa7Sel),
        ],
    },
    {
        GPIO: GpioB,
        gpio_enum: GpioB,
        gpio: gpiob,
        gpio_mapped: gpio_b,
        partially_erased_pin: PBx,
        pins: [
            PB0: (pb0, 0, Input<PullUpEnable>, Pb0Over, Pb0Sel),
            PB1: (pb1, 1, Input<PullUpEnable>, Pb1Over, Pb1Sel),
            PB2: (pb2, 2, Input<PullUpEnable>, Pb2Over, Pb2Sel),
            PB3: (pb3, 3, Input<PullUpEnable>, Pb3Over, Pb3Sel),
            PB4: (pb4, 4, Input<PullUpEnable>, Pb4Over, Pb4Sel),
            PB5: (pb5, 5, Input<PullUpEnable>, Pb5Over, Pb5Sel),
            PB6: (pb6, 6, Input<PullUpEnable>, Pb6Over, Pb6Sel),
            PB7: (pb7, 7, Input<PullUpEnable>, Pb7Over, Pb7Sel),
        ],
    },
    {
        GPIO: GpioC,
        gpio_enum: GpioC,
        gpio: gpioc,
        gpio_mapped: gpio_c,
        partially_erased_pin: PCx,
        pins: [
            PC0: (pc0, 0, Input<PullUpEnable>, Pc0Over, Pc0Sel),
            PC1: (pc1, 1, Input<PullUpEnable>, Pc1Over, Pc1Sel),
            PC2: (pc2, 2, Input<PullUpEnable>, Pc2Over, Pc2Sel),
            PC3: (pc3, 3, Input<PullUpEnable>, Pc3Over, Pc3Sel),
            PC4: (pc4, 4, Input<PullUpEnable>, Pc4Over, Pc4Sel),
            PC5: (pc5, 5, Input<PullUpEnable>, Pc5Over, Pc5Sel),
            PC6: (pc6, 6, Input<PullUpEnable>, Pc6Over, Pc6Sel),
            PC7: (pc7, 7, Input<PullUpEnable>, Pc7Over, Pc7Sel),
        ],
    },
    {
        GPIO: GpioD,
        gpio_enum: GpioD,
        gpio: gpiod,
        gpio_mapped: gpio_d,
        partially_erased_pin: PDx,
        pins: [
            PD0: (pd0, 0, Input<PullUpEnable>, Pd0Over, Pd0Sel),
            PD1: (pd1, 1, Input<PullUpEnable>, Pd1Over, Pd1Sel),
            PD2: (pd2, 2, Input<PullUpEnable>, Pd2Over, Pd2Sel),
            PD3: (pd3, 3, Input<PullUpEnable>, Pd3Over, Pd3Sel),
            PD4: (pd4, 4, Input<PullUpEnable>, Pd4Over, Pd4Sel),
            PD5: (pd5, 5, Input<PullUpEnable>, Pd5Over, Pd5Sel),
            PD6: (pd6, 6, Input<PullUpEnable>, Pd6Over, Pd6Sel),
            PD7: (pd7, 7, Input<PullUpEnable>, Pd7Over, Pd7Sel),
        ],
    },
],
[
    { as_uart0_rxd: UartrxdUart0 },
    { as_uart1_cts: UartctsUart1 },
    { as_uart1_rxd: UartrxdUart1 },
    { as_ssi0_clk: ClkSsiSsi0 },
    { as_ssi0_rxd: SsirxdSsi0 },
    { as_ssi0_fss_in: SsifssinSsi0 },
    { as_ssi0_clk_in: ClkSsiinSsi0 },
    { as_ssi1_clk: ClkSsiSsi1 },
    { as_ssi1_rxd: SsirxdSsi1 },
    { as_ssi1_fss_in: SsifssinSsi1 },
    { as_ssi1_clk_in: ClkSsiinSsi1 },
    { as_i2c_ms_sda: I2cmssda },
    { as_i2c_ms_scl: I2cmsscl },
    { as_gpt0_ocp1: Gpt0ocp1 },
    { as_gpt0_ocp2: Gpt0ocp2 },
    { as_gpt1_ocp1: Gpt1ocp1 },
    { as_gpt1_ocp2: Gpt1ocp2 },
    { as_gpt2_ocp1: Gpt2ocp1 },
    { as_gpt2_ocp2: Gpt2ocp2 },
    { as_gpt3_ocp1: Gpt3ocp1 },
    { as_gpt3_ocp2: Gpt3ocp2 },
]
);
