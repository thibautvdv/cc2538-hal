use core::marker::PhantomData;

use cc2538_pac::{soc_adc, Cctest, RfcoreXreg, SocAdc};

use core::marker::ConstParamTy;

/// The channel the ADC is using when calling [`Adc::get`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, ConstParamTy)]
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

impl Default for RefVoltage {
    fn default() -> Self {
        Self::Internal
    }
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

impl Default for DecimationRate {
    fn default() -> Self {
        Self::Dec512
    }
}

pub struct Adc<'p, const CHANNEL: AdcChannel> {
    channel: AdcChannel,
    reference: RefVoltage,
    rate: DecimationRate,
    _adc: PhantomData<&'p mut SocAdc>,
}

impl<'p, const CHANNEL: AdcChannel> Adc<'p, CHANNEL> {
    /// Return the register block of the ADC.
    fn regs() -> &'static soc_adc::RegisterBlock {
        unsafe { &*SocAdc::ptr() }
    }

    /// Create a new ADC.
    pub fn new(_adc: &mut SocAdc) -> Self {
        Self {
            channel: CHANNEL,
            reference: Default::default(),
            rate: Default::default(),
            _adc: PhantomData,
        }
    }

    /// Set the voltage reference.
    pub fn set_reference(&mut self, reference: RefVoltage) {
        self.reference = reference;
    }

    /// Set the decimation rate.
    pub fn set_decimation_rate(&mut self, rate: DecimationRate) {
        self.rate = rate;
    }

    /// Get the ADC value.
    pub fn read(&self) -> u16 {
        unsafe { Self::regs().adccon1().modify(|_, w| w.stsel().bits(0b11)) };

        let mut cctest_tr0 = 0;
        let mut rfcore_xreg_atest = 0;
        if self.channel == AdcChannel::TemperatureSensor {
            unsafe {
                cctest_tr0 = (*Cctest::ptr()).tr0().read().bits();
                (*Cctest::ptr()).tr0().modify(|_, w| w.adctm().set_bit());

                rfcore_xreg_atest = (*RfcoreXreg::ptr()).atest().read().bits();
                (*RfcoreXreg::ptr())
                    .atest()
                    .modify(|_, w| w.atest_ctrl().bits(0x1));
            }
        }
        unsafe {
            Self::regs().adccon3().write(|w| {
                w.ech()
                    .bits(self.channel as u8)
                    .ediv()
                    .bits(self.rate as u8)
                    .eref()
                    .bits(self.reference as u8)
            });
        }

        // Poll until end of conversion
        // TODO(thvdveld): can we make this asynchronous?
        while !self.end_of_conversion() {}

        // Read conversion
        let mut res = Self::regs().adcl().read().bits() & 0xfc;
        res |= Self::regs().adch().read().bits() << 8;

        // Restore radio and temperature sensor.
        if self.channel == AdcChannel::TemperatureSensor {
            unsafe {
                (*Cctest::ptr()).tr0().write(|w| w.bits(cctest_tr0));
                (*RfcoreXreg::ptr())
                    .atest()
                    .write(|w| w.bits(rfcore_xreg_atest));
            }
        }
        res as u16
    }

    // Check if the conversion is finished.
    fn end_of_conversion(&self) -> bool {
        Self::regs().adccon1().read().eoc().bit_is_set()
    }
}

impl<'p> Adc<'p, { AdcChannel::TemperatureSensor }> {
    /// Return a temperature value.
    pub fn get_converted_temperature(&self) -> u32 {
        let val = self.read();
        25_000 + ((val as u32 >> 4) - 1_422) * 10_000 / 42
    }
}
