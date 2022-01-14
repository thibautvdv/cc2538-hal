use core::marker::PhantomData;

use cc2538_pac::{soc_adc, CCTEST, RFCORE_XREG, SOC_ADC};

/// The channel the ADC is using when calling [`Adc::get`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdcChannel {
    Ain0 = 0b0000,
    Ain1 = 0b0001,
    Ain2 = 0b0010,
    Ain3 = 0b0011,
    Ain4 = 0b0100,
    Ain5 = 0b0101,
    Ain6 = 0b0110,
    Ain7 = 0b0111,
    Ain0Ain1 = 0b1000,
    Ain2Ain3 = 0b1001,
    Ain4Ain5 = 0b1010,
    Ain6Ain7 = 0b1011,
    Gnd = 0b1100,
    TemperatureSensor = 0b1110,
    VddDiv3 = 0b1111,
}

/// The reference voltage used for the conversion in the ADC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefVoltage {
    Internal = 0x00,
    ExternalAin7 = 0x01,
    Avdd5 = 0x10,
    ExternalAin6Ain7 = 0x11,
}

/// The decimation rate of the ADC.
/// The decimation rate also determines the resolution and time required to complete a conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecimationRate {
    Dec64 = 0b00,
    Dec128 = 0b01,
    Dec256 = 0b10,
    Dec512 = 0b11,
}

pub struct AdcDriver<'p> {
    _adc: PhantomData<&'p mut SOC_ADC>,
}

impl<'p> AdcDriver<'p> {
    fn regs() -> &'static soc_adc::RegisterBlock {
        unsafe { &*SOC_ADC::ptr() }
    }

    pub fn new(_adc: &mut SOC_ADC) -> Self {
        Self {
            _adc: PhantomData,
        }
    }    

    pub fn get(&self, channel: AdcChannel, reference: RefVoltage, div: DecimationRate) -> u16 {
        unsafe { Self::regs().adccon1.modify(|_, w| w.stsel().bits(0b11)) };

        let mut cctest_tr0 = 0;
        let mut rfcore_xreg_atest = 0;
        if channel == AdcChannel::TemperatureSensor {
            unsafe {
                cctest_tr0 = (*CCTEST::ptr()).tr0.read().bits();
                (*CCTEST::ptr()).tr0.modify(|_, w| w.adctm().set_bit());

                rfcore_xreg_atest = (*RFCORE_XREG::ptr()).atest.read().bits();
                (*RFCORE_XREG::ptr())
                    .atest
                    .modify(|_, w| w.atest_ctrl().bits(0x1));
            }
        }
        unsafe {
            Self::regs().adccon3.write(|w| {
                w.ech()
                    .bits(channel as u8)
                    .ediv()
                    .bits(div as u8)
                    .eref()
                    .bits(reference as u8)
            });
        }

        // Poll until end of conversion
        while !self.end_of_conversion() {}

        // Read conversion
        let mut res = Self::regs().adcl.read().bits() & 0xfc;
        res |= Self::regs().adch.read().bits() << 8;

        // Restore radio and temperature sensor.
        if channel == AdcChannel::TemperatureSensor {
            unsafe {
                (*CCTEST::ptr()).tr0.write(|w| w.bits(cctest_tr0));
                (*RFCORE_XREG::ptr())
                    .atest
                    .write(|w| w.bits(rfcore_xreg_atest));
            }
        }
        res as u16
    }

    pub fn get_converted_temperature(&self) -> u32 {
        let val = self.get(
            AdcChannel::TemperatureSensor,
            RefVoltage::Internal,
            DecimationRate::Dec512,
        );

        25_000 + ((val as u32 >> 4) - 1_422) * 10_000 / 42
    }

    fn end_of_conversion(&self) -> bool {
        Self::regs().adccon1.read().eoc().bit_is_set()
    }
}