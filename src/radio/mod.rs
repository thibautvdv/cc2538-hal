//! Radio module HAL

use core::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use cc2538_pac as pac;
use pac::{
    ana_regs, rfcore_ffsm, rfcore_sfr, rfcore_xreg, CorePeripherals, Interrupt, ANA_REGS, NVIC,
    RFCORE_FFSM, RFCORE_SFR, RFCORE_XREG,
};

use crate::dma::{self, Dma, Enabled, TransferMode};

use crate::time::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorEvent {
    NoLock,
    RxAbo,
    RxOverf,
    RxUnderf,
    TxOverf,
    TxUnderf,
    StrobeErr,
    All,
}

impl ErrorEvent {
    pub(crate) const fn mask(&self) -> u32 {
        match self {
            ErrorEvent::NoLock => 1 << 0,
            ErrorEvent::RxAbo => 1 << 1,
            ErrorEvent::RxOverf => 1 << 2,
            ErrorEvent::RxUnderf => 1 << 3,
            ErrorEvent::TxOverf => 1 << 4,
            ErrorEvent::TxUnderf => 1 << 5,
            ErrorEvent::StrobeErr => 1 << 6,
            ErrorEvent::All => !0u32,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    TxAckDone,
    TxDone,
    RfIdle,
    CspManInt,
    CspStop,
    CspWait,
    Sfd,
    Fifop,
    SrcMatchDone,
    SrcMatchFound,
    FrameAccepted,
    RxPktDone,
    RxMaskZero,
    All,
}

impl Event {
    #[inline]
    pub(crate) const fn mask(&self) -> u32 {
        match self {
            Event::TxAckDone => 0b1,
            Event::TxDone => 0b10,
            Event::RfIdle => 0b100,
            Event::CspManInt => 0b1000,
            Event::CspStop => 0b10000,
            Event::CspWait => 0b100000,
            Event::Sfd => 0b10,
            Event::Fifop => 0b100,
            Event::SrcMatchDone => 0b1000,
            Event::SrcMatchFound => 0b10000,
            Event::FrameAccepted => 0b100000,
            Event::RxPktDone => 0b1000000,
            Event::RxMaskZero => 0b10000000,
            Event::All => !0u32,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadioError {
    PayloadTooBig,
    ChannelNotClear,
    UnableToStartTx,
    Collision,
    FailedTransmission,
    IncorrectFrame,
}

pub enum Radio<'p> {
    Off(RadioDriver<'p, RadioOff>),
    On(RadioDriver<'p, RadioOn>),
    Undefined,
}

const CHECKSUM_LEN: usize = 2;
const MAX_PACKET_LEN: usize = 127;
const MAX_PAYLOAD_LEN: usize = MAX_PACKET_LEN - CHECKSUM_LEN;
const CCA_THRES: usize = 0xF8;

/// Radio configuration
#[derive(Debug, Copy, Clone)]
pub struct RadioConfig {
    pub channel: Channel,
    pub src_pan_id: u32,
    pub dst_pan_id: u32,
    pub short_addr: u16,
    pub ext_addr: [u8; 8],
}

impl Default for RadioConfig {
    fn default() -> Self {
        Self {
            channel: Channel::Channel26,
            src_pan_id: 0xabcd,
            dst_pan_id: 0xabcd,
            short_addr: 0,
            ext_addr: [0; 8],
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum RxMode {
    Normal = 0x0,
    InfiniteRx = 0x1,
    InfiniteReception = 0x10,
    SymbolSearchDisabled = 0x11,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Channel11 = 11,
    Channel12,
    Channel13,
    Channel14,
    Channel15,
    Channel16,
    Channel17,
    Channel18,
    Channel19,
    Channel20,
    Channel21,
    Channel22,
    Channel23,
    Channel24,
    Channel25,
    Channel26,
}

#[inline]
pub(crate) const fn channel_frequency(channel: Channel) -> u32 {
    (2405 + 5 * (channel as u32 - 11)) * 1_000_000
}

#[inline]
pub(crate) const fn channel_freq_reg_val(channel: Channel) -> u32 {
    11 + 5 * (channel as u32 - 11)
}

/// Op Codes for the Command Strobe/CSMA-CA Processor
#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum CspOpCode {
    /// Decrement Z register
    DecZ = 0xC5,
    /// Decrement Y register
    DecY = 0xC4,
    /// Decrement X register
    DecX = 0xC3,
    /// Increment Z register
    IncZ = 0xC2,
    /// Increment Y register
    IncY = 0xC1,
    /// Increment X register
    IncX = 0xC0,
    /// Increment Y not greater than M
    IncMaxY = 0xC8,
    /// Load random value into X register
    RandXY = 0xBD,
    /// Interrupt
    Int = 0xBA,
    /// Wait for X MAC timer overflows
    WaitX = 0xBC,
    /// Set the compare value of the MAC timer to the current timer value
    SetCmp1 = 0xBE,
    /// Wait for W MAC timer overflows
    WaitW = 0x80,
    /// Wait until MAC timer event 1
    WEvent1 = 0xB8,
    /// Wait until MAC timer event 2
    WEvent2 = 0xB9,
    /// Set loop label
    Label = 0xBB,
    /// Conditional repeat
    RptC = 0xA0,
    /// Conditional skip instruction
    SkipSC = 0x00,
    /// Stop program execution
    Stop = 0xD2,
    /// No operation
    SNop = 0xD0,
    /// Enable and calibrate frequency synthesizer for RX
    SRXOn = 0xD3,
    /// Enable TX after calibration
    STXOn = 0xD9,
    /// Enable calibration and TX if CCA indicates a clear channel
    STXOnCca = 0xDA,
    /// Sample the current CCA value to SAMPLED_CCA
    SSampleCca = 0xDB,
    /// Disable RX or TX and frequency synthesizer
    SRFOff = 0xDF,
    /// Flush RX FIFO buffer and reset demodulator
    SFlushRX = 0xDD,
    /// Flush TX FIFO buffer
    SFlushTX = 0xDE,
    /// Send acknowledge frame with pending field cleared
    SAck = 0xD6,
    /// Send acknowledge frame with the pending field set
    SAckPend = 0xD7,
    /// Abort sending of acknowledge frame
    SNack = 0xD8,
    /// Set bit in RXENABLE register
    SRXMaskBitSet = 0xD4,
    /// Clear bit in RXENABLE register
    SRXMaskBitClr = 0xD5,
    /// Immediate stop program execution
    IsStop = 0xE2,
    /// Immediate start program executation
    IsStart = 0xE1,
    /// Immediate enable and calibrate frequency synthesizer for RX
    IsRXon = 0xE3,
    /// Immediate set bit in RXENABLE
    IsRXMaskBitSet = 0xE4,
    /// Immediate clear bit in RXENABLE
    IsRXMaskBitClr = 0xE5,
    /// Immediate enable TX after callibration
    IsTXOn = 0xE9,
    /// Immediate enable calibration and TX if CCA indicates a clear channel
    IsTXOnCca = 0xEA,
    /// Immediate sample the current CCA value to SAMPLED_CCA
    IsSampleCca = 0xEB,
    /// Immediate disable RX or TX and the frequency synthesizer
    IsRFOff = 0xEF,
    /// Immediate flush RX FIFO buffer and reset demodulator
    IsFlushRx = 0xED,
    /// Immediate flush TX FIFO
    IsFlushTX = 0xEE,
    /// Immediate send acknowledge frame with the pending field cleared
    IsAck = 0xE6,
    /// Immediate send acknowledge frame with the pending field set
    IsAckPend = 0xE7,
    /// Immediate abort sending of acknowledge frame
    IsNack = 0xE8,
    /// Immediate clear CSP program memory, reset program counter
    IsClear = 0xFF,
}

pub struct RadioOn;
pub struct RadioOff;

pub struct RadioDriver<'p, State> {
    _ffsm: PhantomData<&'p mut RFCORE_FFSM>,
    _xreg: PhantomData<&'p mut RFCORE_XREG>,
    _sfr: PhantomData<&'p mut RFCORE_SFR>,
    _ana: PhantomData<&'p mut ANA_REGS>,
    tx_channel: dma::Channel,
    rx_channel: dma::Channel,
    _state: PhantomData<State>,
}

impl<'p, State> RadioDriver<'p, State> {
    #[inline]
    fn ffsm_regs() -> &'static rfcore_ffsm::RegisterBlock {
        unsafe { &*RFCORE_FFSM::ptr() }
    }

    #[inline]
    fn xreg_regs() -> &'static rfcore_xreg::RegisterBlock {
        unsafe { &*RFCORE_XREG::ptr() }
    }

    #[inline]
    fn sfr_regs() -> &'static rfcore_sfr::RegisterBlock {
        unsafe { &*RFCORE_SFR::ptr() }
    }

    #[inline]
    fn ana_regs() -> &'static ana_regs::RegisterBlock {
        unsafe { &*ANA_REGS::ptr() }
    }

    /// Set the PAN ID to use by the radio
    #[inline]
    pub fn set_pan_id(&self, id: u32) {
        Self::ffsm_regs()
            .pan_id0
            .modify(|_, w| unsafe { w.bits(id & 0xFF) });
        Self::ffsm_regs()
            .pan_id1
            .modify(|_, w| unsafe { w.bits(id >> 8) });
    }

    /// Return the PAN ID that is currently used
    #[inline]
    pub fn get_pan_id(&mut self) -> u16 {
        (Self::ffsm_regs().pan_id1.read().bits() << 8) as u16
            | (Self::ffsm_regs().pan_id0.read().bits() & 0xFF) as u16
    }

    /// Set the short address
    #[inline]
    pub fn set_short_address(&mut self, addr: u16) {
        Self::ffsm_regs()
            .short_addr0
            .modify(|_, w| unsafe { w.bits(addr as u32 & 0xFF) });
        Self::ffsm_regs()
            .short_addr1
            .modify(|_, w| unsafe { w.bits(addr as u32 >> 8) });
    }

    /// Return the short address
    #[inline]
    pub fn get_short_address(&mut self) -> u16 {
        (Self::ffsm_regs().short_addr1.read().bits() << 8) as u16
            | (Self::ffsm_regs().short_addr0.read().bits() & 0xFF) as u16
    }

    /// Set the extended address
    #[inline]
    pub fn set_extended_address(&mut self, addr: &[u8]) {
        let ffsm = Self::ffsm_regs();
        ffsm.ext_addr0
            .write(|w| unsafe { w.ext_addr0().bits(addr[7]) });
        ffsm.ext_addr1
            .write(|w| unsafe { w.ext_addr1().bits(addr[6]) });
        ffsm.ext_addr2
            .write(|w| unsafe { w.ext_addr2().bits(addr[5]) });
        ffsm.ext_addr3
            .write(|w| unsafe { w.ext_addr3().bits(addr[4]) });
        ffsm.ext_addr4
            .write(|w| unsafe { w.ext_addr4().bits(addr[3]) });
        ffsm.ext_addr5
            .write(|w| unsafe { w.ext_addr5().bits(addr[2]) });
        ffsm.ext_addr6
            .write(|w| unsafe { w.ext_addr6().bits(addr[1]) });
        ffsm.ext_addr7
            .write(|w| unsafe { w.ext_addr7().bits(addr[0]) });
    }

    /// Return the CCA threshold in dB
    #[inline]
    pub fn get_cca_threshold(&mut self) -> i32 {
        let cca_thr = Self::xreg_regs().ccactrl0.read().cca_thr().bits() as i32;
        cca_thr - 73
    }

    /// Set the CCA threshold in dB
    #[inline]
    pub fn set_cca_threshold(&mut self, threshold: i32) {
        Self::xreg_regs()
            .ccactrl0
            .modify(|_, w| unsafe { w.bits((threshold + 73) as u32) });
    }

    /// Return the TX power in dB
    pub fn get_tx_power(&mut self) -> i32 {
        todo!();
    }

    /// Set the TX power in dB
    pub fn set_tx_power(&mut self, _power: i32) {
        todo!();
    }

    /// Enable frame filtering
    #[inline]
    pub fn enable_frame_filtering(&mut self) {
        Self::xreg_regs()
            .frmfilt0
            .modify(|_, w| w.frame_filter_en().set_bit());
    }

    /// Disable frame filtering
    #[inline]
    pub fn disable_frame_filtering(&mut self) {
        Self::xreg_regs()
            .frmfilt0
            .modify(|_, w| w.frame_filter_en().clear_bit());
    }

    /// Enable SHR search
    #[inline]
    pub fn enable_shr_search(&mut self) {
        Self::xreg_regs()
            .frmctrl0
            .modify(|_, w| unsafe { w.rx_mode().bits(0b00) });
    }

    /// Disable SHR search
    #[inline]
    pub fn disable_shr_search(&mut self) {
        Self::xreg_regs()
            .frmctrl0
            .modify(|_, w| unsafe { w.rx_mode().bits(0b11) });
    }

    /// Enable auto CRC
    #[inline]
    fn enable_autocrc(&mut self) {
        Self::xreg_regs()
            .frmctrl0
            .modify(|_, w| w.autocrc().set_bit());
    }

    /// Disable auto CRC
    #[inline]
    fn disable_autocrc(&mut self) {
        Self::xreg_regs()
            .frmctrl0
            .modify(|_, w| w.autocrc().clear_bit());
    }

    /// Enable auto ACK
    #[inline]
    fn enable_autoack(&mut self) {
        Self::xreg_regs()
            .frmctrl0
            .modify(|_, w| w.autoack().set_bit());
    }

    /// Disable auto ACK
    #[inline]
    fn disable_autoack(&mut self) {
        Self::xreg_regs()
            .frmctrl0
            .modify(|_, w| w.autoack().clear_bit());
    }

    pub fn get_sfd_timestamp(&mut self) -> u32 {
        todo!();
    }

    /// Set the RX mode
    #[inline]
    pub fn set_rx_mode(&mut self, rx_mode: RxMode) {
        Self::xreg_regs()
            .frmctrl0
            .modify(|_, w| unsafe { w.rx_mode().bits(rx_mode as u8) });
    }

    /// Send an OP code to the CSP
    #[inline]
    pub fn send_csp_op_code(&self, op_code: CspOpCode) {
        Self::sfr_regs()
            .rfst
            .modify(|_, w| unsafe { w.instr().bits(op_code as u8) });
    }

    /// Listen to an interrupt
    #[inline]
    pub fn listen(&mut self, event: Event) {
        match event {
            Event::Sfd
            | Event::Fifop
            | Event::SrcMatchDone
            | Event::SrcMatchFound
            | Event::FrameAccepted
            | Event::RxPktDone
            | Event::RxMaskZero => Self::xreg_regs()
                .rfirqm0
                .modify(|r, w| unsafe { w.bits(r.bits() | event.mask()) }),
            Event::TxAckDone
            | Event::TxDone
            | Event::RfIdle
            | Event::CspManInt
            | Event::CspStop
            | Event::CspWait => Self::xreg_regs()
                .rfirqm1
                .modify(|r, w| unsafe { w.bits(r.bits() | event.mask()) }),
            Event::All => {
                Self::xreg_regs()
                    .rfirqm0
                    .write(|w| unsafe { w.bits(event.mask()) });
                Self::xreg_regs()
                    .rfirqm1
                    .write(|w| unsafe { w.bits(event.mask()) });
            }
        }
    }

    /// Unlisten to an interrupt
    #[inline]
    pub fn unlisten(&mut self, event: Event) {
        match event {
            Event::Sfd
            | Event::Fifop
            | Event::SrcMatchDone
            | Event::SrcMatchFound
            | Event::FrameAccepted
            | Event::RxPktDone
            | Event::RxMaskZero => Self::xreg_regs()
                .rfirqm0
                .modify(|r, w| unsafe { w.bits(r.bits() & !event.mask()) }),
            Event::TxAckDone
            | Event::TxDone
            | Event::RfIdle
            | Event::CspManInt
            | Event::CspStop
            | Event::CspWait => Self::xreg_regs()
                .rfirqm1
                .modify(|r, w| unsafe { w.bits(r.bits() & !event.mask()) }),
            Event::All => {
                Self::xreg_regs().rfirqm0.write(|w| unsafe { w.bits(0) });
                Self::xreg_regs().rfirqm1.write(|w| unsafe { w.bits(0) });
            }
        }
    }

    /// Clear an interrupt
    #[inline]
    pub fn clear_event(&mut self, event: Event) {
        match event {
            Event::Sfd
            | Event::Fifop
            | Event::SrcMatchDone
            | Event::SrcMatchFound
            | Event::FrameAccepted
            | Event::RxPktDone
            | Event::RxMaskZero => Self::sfr_regs()
                .rfirqf0
                .modify(|r, w| unsafe { w.bits(r.bits() & !event.mask()) }),
            Event::TxAckDone
            | Event::TxDone
            | Event::RfIdle
            | Event::CspManInt
            | Event::CspStop
            | Event::CspWait => Self::sfr_regs()
                .rfirqf1
                .modify(|r, w| unsafe { w.bits(r.bits() & !event.mask()) }),
            Event::All => {
                Self::sfr_regs().rfirqf0.write(|w| unsafe { w.bits(0) });
                Self::sfr_regs().rfirqf1.write(|w| unsafe { w.bits(0) });
            }
        }
    }

    /// Check if an interrupt is pending
    #[inline]
    pub fn is_interrupt_pending(&self, event: Event) -> bool {
        match event {
            Event::Sfd
            | Event::Fifop
            | Event::SrcMatchDone
            | Event::SrcMatchFound
            | Event::FrameAccepted
            | Event::RxPktDone
            | Event::RxMaskZero => (Self::sfr_regs().rfirqf0.read().bits() & event.mask()) != 0,
            Event::TxAckDone
            | Event::TxDone
            | Event::RfIdle
            | Event::CspManInt
            | Event::CspStop
            | Event::CspWait => (Self::sfr_regs().rfirqf1.read().bits() & event.mask()) != 0,
            Event::All => {
                (Self::sfr_regs().rfirqf0.read().bits() | Self::sfr_regs().rfirqf1.read().bits())
                    != 0
            }
        }
    }

    /// Listen to a specific error interrupt
    #[inline]
    pub fn listen_error(&mut self, event: ErrorEvent) {
        Self::xreg_regs()
            .rferrm
            .modify(|r, w| unsafe { w.bits(r.bits() | event.mask()) })
    }

    /// Unlisten to a specific error interrupt
    #[inline]
    pub fn unlisten_error(&mut self, event: ErrorEvent) {
        Self::xreg_regs()
            .rferrm
            .modify(|r, w| unsafe { w.bits(r.bits() & !event.mask()) })
    }

    /// Clear a specific error interrupt
    #[inline]
    pub fn clear_err(&mut self, event: ErrorEvent) {
        Self::sfr_regs()
            .rferrf
            .modify(|r, w| unsafe { w.bits(r.bits() & !event.mask()) });
    }

    /// Check for a specific error interrupt
    #[inline]
    pub fn is_error_interrupt(&self, event: ErrorEvent) -> bool {
        match event {
            ErrorEvent::NoLock => Self::sfr_regs().rferrf.read().nlock().bit_is_set(),
            ErrorEvent::RxAbo => Self::sfr_regs().rferrf.read().rxabo().bit_is_set(),
            ErrorEvent::RxOverf => Self::sfr_regs().rferrf.read().rxoverf().bit_is_set(),
            ErrorEvent::RxUnderf => Self::sfr_regs().rferrf.read().rxunderf().bit_is_set(),
            ErrorEvent::TxOverf => Self::sfr_regs().rferrf.read().txoverf().bit_is_set(),
            ErrorEvent::TxUnderf => Self::sfr_regs().rferrf.read().txunderf().bit_is_set(),
            ErrorEvent::StrobeErr => Self::sfr_regs().rferrf.read().strobeerr().bit_is_set(),
            ErrorEvent::All => Self::sfr_regs().rferrf.read().bits() != 0,
        }
    }
}

impl<'p> RadioDriver<'p, RadioOff> {
    pub fn new(
        #[allow(unused_variables)] rfcore_ffsm: &'p mut RFCORE_FFSM,
        #[allow(unused_variables)] rfcore_xreg: &'p mut RFCORE_XREG,
        #[allow(unused_variables)] rfcore_sfr: &'p mut RFCORE_SFR,
        #[allow(unused_variables)] ana_regs: &'p mut ANA_REGS,
        tx_channel: dma::Channel,
        rx_channel: dma::Channel,
    ) -> RadioDriver<'p, RadioOff> {
        RadioDriver {
            _ffsm: PhantomData,
            _xreg: PhantomData,
            _sfr: PhantomData,
            _ana: PhantomData,
            tx_channel,
            rx_channel,
            _state: PhantomData,
        }
    }

    /// Enable the radio module
    ///
    /// This actually flushes RX and enables RX.
    #[inline]
    pub fn enable(mut self, config: Option<RadioConfig>) -> RadioDriver<'p, RadioOn> {
        // NOTE Maybe we can check here if the clock for RF is enabled

        let xreg = Self::xreg_regs();
        let ana = Self::ana_regs();

        xreg.ccactrl0
            .modify(|_, w| unsafe { w.cca_thr().bits(CCA_THRES as u8) });

        if let Some(config) = config {
            self.set_pan_id(config.dst_pan_id);
            self.set_short_address(config.short_addr);
            self.set_extended_address(&config.ext_addr);
        }

        self.send_csp_op_code(CspOpCode::IsFlushRx);

        // These are changes from the default values (following contiki-ng)
        xreg.txfiltcfg.modify(|_, w| unsafe { w.bits(0x09) }); // TX anti-aliasing filter bandwidth
        xreg.agcctrl1.modify(|_, w| unsafe { w.bits(0x15) }); // AGC target value
        ana.ivctrl.modify(|_, w| unsafe { w.bits(0x0B) }); // ANA bias current
        xreg.fscal1.modify(|_, w| unsafe { w.bits(0x01) }); // Tune frequency calibration

        self.enable_autocrc();
        self.enable_autoack();

        xreg.srcmatch.modify(|_, w| unsafe { w.bits(0) }); // Disable source address matching and autopend

        xreg.fifopctrl
            .modify(|_, w| unsafe { w.fifop_thr().bits(MAX_PACKET_LEN as u8) });

        xreg.txpower.modify(|_, w| unsafe { w.bits(0xD5) }); // This is the recomended TX power

        self.set_channel(Channel::Channel26);

        self.enable_shr_search();

        // Enable TX DMA mode
        // Disable peripheral requests
        self.tx_channel.allow_periph_requests(false);
        self.tx_channel
            .set_destination_end_address(Self::sfr_regs().rfdata.as_ptr() as u32);

        self.tx_channel
            .set_arbitration_size(dma::Arbitration::Transfer128);
        self.tx_channel
            .set_transfer_mode(dma::TransferMode::AutoRequest);
        self.tx_channel.set_source_size(dma::DataSize::Data8bit);
        self.tx_channel
            .set_destination_size(dma::DataSize::Data8bit);
        self.tx_channel
            .set_source_increment(dma::AddressIncrement::Increment8bit);
        self.tx_channel
            .set_destination_increment(dma::AddressIncrement::None);

        // enable rx dma mode
        // disable peripheral requests
        self.rx_channel.allow_periph_requests(true);
        self.rx_channel
            .set_source_end_address(Self::sfr_regs().rfdata.as_ptr() as u32);

        self.rx_channel
            .set_arbitration_size(dma::Arbitration::Transfer128);
        self.rx_channel
            .set_transfer_mode(dma::TransferMode::AutoRequest);
        self.rx_channel.set_source_size(dma::DataSize::Data8bit);
        self.rx_channel
            .set_destination_size(dma::DataSize::Data8bit);
        self.rx_channel
            .set_source_increment(dma::AddressIncrement::None);
        self.rx_channel
            .set_destination_increment(dma::AddressIncrement::Increment8bit);

        self.clear_event(Event::All);
        self.clear_err(ErrorEvent::All);

        // Enable RX interrupts
        self.listen(Event::Fifop);
        self.listen(Event::TxDone);
        self.listen_error(ErrorEvent::All);

        unsafe { NVIC::unmask(Interrupt::RF_TXRX) };

        self.enable_rx()
    }

    /// Set the channel
    #[inline]
    pub fn set_channel(&mut self, channel: Channel) {
        Self::xreg_regs()
            .freqctrl
            .modify(|_, w| unsafe { w.bits(channel_freq_reg_val(channel)) });
    }

    /// Returns the RSSI value in dB
    ///
    /// # Important
    /// This value can only be valid after eight symbol periods after entering RX.
    #[inline]
    pub fn get_rssi(&mut self) -> i32 {
        let mut rssi;

        // Wait for a valid RSSI reading
        loop {
            rssi = Self::xreg_regs().rssi.read().rssi_val().bits();

            if rssi != 0x80 {
                break;
            }
        }

        rssi as i32 - 73
    }

    /// Enable RX
    #[inline]
    fn enable_rx(self) -> RadioDriver<'p, RadioOn> {
        self.send_csp_op_code(CspOpCode::IsRXon);
        RadioDriver {
            _ffsm: PhantomData,
            _xreg: PhantomData,
            _sfr: PhantomData,
            _ana: PhantomData,
            tx_channel: self.tx_channel,
            rx_channel: self.rx_channel,
            _state: PhantomData,
        }
    }

    /// Enable the MAC timer.
    #[inline]
    fn start_mac_timer(&mut self) {
        // sfr.mtctrl.write(|w| w.sync().set_bit().run().set_bit());
        Self::sfr_regs().mtctrl.write(|w| w.sync().set_bit());
        Self::sfr_regs().mtctrl.write(|w| w.run().set_bit());

        while Self::sfr_regs().mtctrl.read().state().bit_is_clear() {}

        // XXX: Contiki-ng does the following:
        // First, the timer is started, then ended and then started again.
        // I'm not sure why they do that.
    }

    #[inline]
    fn set_poll_mode(&mut self) {
        self.start_mac_timer();
    }
}

impl<'p> RadioDriver<'p, RadioOn> {
    pub fn disable(self) -> RadioDriver<'p, RadioOff> {
        // Wait for ongoing TX to complete
        while Self::xreg_regs().fsmstat1.read().tx_active().bit_is_set() {}

        if Self::xreg_regs().fsmstat1.read().fifop().bit_is_set() {
            self.send_csp_op_code(CspOpCode::IsFlushRx);
        }

        self.disable_rx()
    }

    #[inline]
    fn enable_tx(self) {
        // We can only enable TX when RX is on.
        // This is because we need to do a CCA before we can send.
        // TX will get disabled when it is done sending.
        // XXX: This should probably return Result to check if enabling was succesful.
        // XXX: If it was not able to enable TX, then the buffer should be flushed
        self.send_csp_op_code(CspOpCode::IsTXOn);
    }

    /// Disable RX
    fn disable_rx(self) -> RadioDriver<'p, RadioOff> {
        self.send_csp_op_code(CspOpCode::IsRFOff);
        RadioDriver {
            _ffsm: PhantomData,
            _xreg: PhantomData,
            _sfr: PhantomData,
            _ana: PhantomData,
            tx_channel: self.tx_channel,
            rx_channel: self.rx_channel,
            _state: PhantomData,
        }
    }

    /// Prepare the radio with a packet to be sent
    #[inline]
    pub fn prepare(&mut self, payload: &[u8]) -> Result<(), RadioError> {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(RadioError::PayloadTooBig);
        }

        // Wait until TX is ready
        while Self::xreg_regs().fsmstat1.read().tx_active().bit() {}

        // Flush the TX buffer
        self.send_csp_op_code(CspOpCode::IsFlushTX);

        // Write how much data is going to be send
        Self::sfr_regs()
            .rfdata
            .write(|w| unsafe { w.bits((payload.len() + CHECKSUM_LEN) as u32) });

        // self.tx_channel
        //     .set_source_end_address(payload.as_ptr() as u32);

        // self.tx_channel.use_burst(true);
        // self.tx_channel
        //     .set_transfer_mode(dma::TransferMode::AutoRequest);
        // self.tx_channel.set_transfer_size(payload.len() as u8 - 1);

        // self.tx_channel.enable();
        // self.tx_channel.request();

        // while self.tx_channel.get_mode() != dma::TransferMode::Stop {}

        // Write the data to the FIFO
        for b in payload.iter() {
            Self::sfr_regs()
                .rfdata
                .write(|w| unsafe { w.bits((*b) as u32) });
        }

        Ok(())
    }

    /// Send the packet that has previously been prepared
    #[inline]
    pub fn transmit(&mut self) -> Result<(), RadioError> {
        // We check if we received something and if the channel is clear to send.
        if !self.is_channel_clear() || self.receiving_packet() {
            return Err(RadioError::Collision);
        }

        // Enable TX
        // IMPORTANT: only enable after checking if the channel is clear or if we received a
        // packet. Otherwise TX wont be able to start.
        self.send_csp_op_code(CspOpCode::IsTXOn);

        let mut counter = 0;
        while Self::xreg_regs().fsmstat1.read().tx_active().bit_is_set() && counter < 3 {
            counter += 1;
            // XXX: delay of 6 µs
        }

        if Self::xreg_regs().fsmstat1.read().tx_active().bit_is_clear() {
            // TX was not able to start
            self.send_csp_op_code(CspOpCode::IsFlushTX);
            return Err(RadioError::UnableToStartTx);
        }

        Ok(())
    }

    /// Prepare and transmit a packet
    #[inline]
    pub fn send(&mut self, payload: &[u8]) -> Result<(), RadioError> {
        self.prepare(payload).expect("unable to prepare");
        self.transmit()
    }

    /// Return the status of TX
    #[inline]
    pub fn sending(&self) -> bool {
        Self::xreg_regs().fsmstat1.read().tx_active().bit_is_set()
    }

    /// Read a received packet into a buffer
    #[inline]
    pub fn read(&mut self, buffer: &mut [u8]) -> u32 {
        let len: u32 = Self::sfr_regs().rfdata.read().bits();

        if len > 127 {
            // If bigger than max packet len
            // bad sync error

            self.send_csp_op_code(CspOpCode::IsFlushRx);
            return 0;
        }

        if len <= 4 {
            // If smaller than min packet len

            self.send_csp_op_code(CspOpCode::IsFlushRx);
            return 0;
        }

        if len - 2 > buffer.len() as u32 {
            // Remove checksum length
            // message too long

            self.send_csp_op_code(CspOpCode::IsFlushRx);
            return 0;
        }

        //let len = len - 2;

        // Don't use DMA for short messages
        //if len > 5 {
        //self.rx_channel
        //.set_destination_end_address(buffer.as_ptr() as u32 + len - 1);
        //self.rx_channel.use_burst(true);
        //self.rx_channel
        //.set_transfer_mode(dma::TransferMode::AutoRequest);
        //self.rx_channel.set_transfer_size(len as u8 - 1);

        //self.rx_channel.enable();
        //self.rx_channel.request();

        //while self.rx_channel.get_mode() != dma::TransferMode::Stop {}
        //} else {
        for i in 0..len {
            buffer[i as usize] = Self::sfr_regs().rfdata.read().bits() as u8;
        }
        //}

        if Self::xreg_regs().fsmstat1.read().fifop().bit_is_set() {
            if Self::xreg_regs().fsmstat1.read().fifo().bit_is_set() {
                cortex_m::asm::sev();
            } else {
                self.send_csp_op_code(CspOpCode::IsFlushRx);
            }
        }

        // let rssi = buffer[len as usize - 2] - 73;
        // let crc_corr = buffer[len as usize - 1];

        // if ((crc_corr & 0x80) >> 7) & 0b1 == 1 {
        // packetbuf_set_attr(rssi, rssi);
        // packetbuf_set_attr(link_quality, crc_corr & 0x7f)
        // }

        // read the RSSI and CRC/Corr bytes
        // let rssi = self.sfr.rfdata.read().bits() - 73;
        // let crc_corr = self.sfr.rfdata.read().bits();

        // buffer[buffer.len() - 2] = rssi as u8;
        // buffer[buffer.len() - 1] = crc_corr as u8;

        len - 2
    }

    /// Check if thradio driver is currently receiving a packet
    #[inline]
    pub fn receiving_packet(&self) -> bool {
        // SFD is high when transmitting and receiving.
        // TX_ACTIVE is only high when transmittering.
        // Thus TX_ACTIVE must be low to know if we are receiving.
        Self::xreg_regs().fsmstat1.read().sfd().bit()
            & Self::xreg_regs().fsmstat1.read().tx_active().bit()
    }

    /// Check if the radio driver has just received a packet
    #[inline]
    pub fn received_packet(&self) -> bool {
        Self::xreg_regs().fsmstat1.read().fifop().bit()
    }

    #[inline]
    pub fn is_rssi_valid(&self) -> bool {
        Self::xreg_regs().rssistat.read().rssi_valid().bit_is_set()
    }

    /// Perform a clear channel assesment to find out if there is a packet in the air
    #[inline]
    pub fn is_channel_clear(&self) -> bool {
        // Wait until RSSI is valid
        while !self.is_rssi_valid() {}

        Self::xreg_regs().fsmstat1.read().cca().bit_is_set()
    }

    /// Return random data.
    ///
    /// **NOTE**: Use this function to seed the Random Number Generator
    #[inline]
    pub fn random_data(&self) -> u8 {
        Self::xreg_regs().rfrnd.read().irnd().bit() as u8
    }
}
