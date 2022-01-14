//! Direct memory access (DMA) controller

use core::marker::PhantomData;

use cc2538_pac::UDMA;
use cortex_m::interrupt::free;

pub struct Disabled;
pub struct Enabled;

#[derive(Copy, Clone)]
#[repr(align(16))]
struct DmaChannelConfig {
    src_end_ptr: u32,
    dest_end_ptr: u32,
    control_word: u32,
    _unused: u32,
}

#[repr(align(1024))]
struct DmaChannelConfigArray([DmaChannelConfig; 32]);

#[used]
#[link_section = ".dma_channel_config"]
static mut DMA_CHANNEL_CONFIG: DmaChannelConfigArray = DmaChannelConfigArray(
    [DmaChannelConfig {
        src_end_ptr: 0,
        dest_end_ptr: 0,
        control_word: 0,
        _unused: 0,
    }; 32],
);

/// Extension trait to split the uDMA controller in its channels
pub trait DmaExt {
    type Part;

    fn constrain(self) -> Self::Part;
}

pub struct Dma<STATE> {
    udma: UDMA,
    _state: PhantomData<STATE>,
}

impl DmaExt for UDMA {
    type Part = Dma<Disabled>;

    fn constrain(self) -> Self::Part {
        Dma {
            udma: self,
            _state: PhantomData,
        }
    }
}

impl<STATE> Dma<STATE> {
    #[inline]
    pub fn get_state(&self) -> DmaState {
        let state = unsafe { (*cc2538_pac::UDMA::ptr()).stat.read().state().bits() };
        state.into()
    }

    /// Return the resources
    #[inline]
    pub fn free(self) -> UDMA {
        self.udma
    }
}

impl Dma<Disabled> {
    /// Enable the uDMA module by setting MASTEREN bit in the configuration and writing the base
    /// address of the configuration table to UDMA_CTLBASE.
    #[inline]
    pub fn enable(self) -> Dma<Enabled> {
        // First enable MASTEREN
        self.udma.cfg.write(|w| w.masten().set_bit());

        let addr = { unsafe { DMA_CHANNEL_CONFIG.0.as_ptr() as u32 } };

        // Write the base address of the control table.
        self.udma.ctlbase.write(|w| unsafe { w.bits(addr) });

        Dma {
            udma: self.udma,
            _state: PhantomData,
        }
    }
}

impl Dma<Enabled> {
    /// Return a channel.
    // XXX: check here if the channel is already in use
    #[inline]
    pub fn get_channel(&self, channel: usize, alternate: bool) -> Channel {
        free(|_| Channel {
            control_word: ChannelControlWord(unsafe {
                DMA_CHANNEL_CONFIG.0[32 * alternate as usize + channel].control_word
            }),
            channel,
            alternate,
        })
    }
}

pub struct Channel {
    control_word: ChannelControlWord,
    channel: usize,
    alternate: bool,
}

impl Channel {
    /// Enable the channel
    #[inline]
    pub fn enable(&self) {
        free(|_| unsafe {
            (*cc2538_pac::UDMA::ptr())
                .enaset
                .modify(|r, w| w.bits(r.bits() | (1 << self.channel)));
        });
    }

    /// Do a software request to start the transfer
    ///
    /// XXX should return a future
    #[inline]
    pub fn request(&self) {
        free(|_| unsafe {
            (*cc2538_pac::UDMA::ptr())
                .swreq
                .write(|w| w.bits(1 << self.channel))
        });
    }

    /// Get the current mode of the channel
    #[inline]
    pub fn get_mode(&self) -> TransferMode {
        let mode = free(|_| unsafe {
            DMA_CHANNEL_CONFIG.0[32 * self.alternate as usize + self.channel].control_word & 0x07
        });
        mode.into()
    }

    /// Set the source end address for this channel
    #[inline]
    pub fn set_source_end_address(&self, address: u32) {
        free(|_| unsafe {
            DMA_CHANNEL_CONFIG.0[32 * self.alternate as usize + self.channel].src_end_ptr = address
        });
    }

    /// Set the destination end addresss for this channel
    #[inline]
    pub fn set_destination_end_address(&self, address: u32) {
        free(|_| unsafe {
            DMA_CHANNEL_CONFIG.0[32 * self.alternate as usize + self.channel].dest_end_ptr = address
        });
    }

    /// Allow or disallow peripheral requests to start a transfer
    #[inline]
    pub fn allow_periph_requests(&self, allow: bool) {
        if !allow {
            free(|_| unsafe {
                (*cc2538_pac::UDMA::ptr())
                    .reqmaskset
                    .modify(|r, w| w.bits(r.bits() | (1 << self.channel)));
            });
        } else {
            free(|_| unsafe {
                (*cc2538_pac::UDMA::ptr())
                    .reqmaskclr
                    .write(|w| w.bits(1 << self.channel));
            });
        }
    }

    /// Set the priority of this channel
    #[inline]
    pub fn set_priority(&self, priority: Priority) {
        match priority {
            Priority::Default => free(|_| unsafe {
                (*cc2538_pac::UDMA::ptr())
                    .prioclr
                    .write(|w| w.bits(1 << self.channel));
            }),
            Priority::High => free(|_| unsafe {
                (*cc2538_pac::UDMA::ptr())
                    .prioset
                    .modify(|r, w| w.bits(r.bits() | (1 << self.channel)));
            }),
        }
    }

    #[inline]
    pub fn use_alternate(&mut self, alternate: bool) {
        self.alternate = alternate;
        if self.alternate {
            free(|_| unsafe {
                (*cc2538_pac::UDMA::ptr())
                    .altset
                    .modify(|r, w| w.bits(r.bits() | (1 << self.channel)));
            });
        } else {
            free(|_| unsafe {
                (*cc2538_pac::UDMA::ptr())
                    .altclr
                    .write(|w| w.bits(1 << self.channel));
            });
        }
    }

    #[inline]
    pub fn set_assignment(&mut self, assignement: u8) {
        let shift = (self.channel * 4) % 32;
        free(|_| match self.channel {
            0..=7 => unsafe {
                (*cc2538_pac::UDMA::ptr()).chmap0.modify(|r, w| {
                    w.bits((r.bits() & !(0b1111 << shift)) | ((assignement as u32) << shift))
                });
            },
            8..=15 => unsafe {
                (*cc2538_pac::UDMA::ptr()).chmap1.modify(|r, w| {
                    w.bits((r.bits() & !(0b1111 << shift)) | ((assignement as u32) << shift))
                });
            },
            16..=23 => unsafe {
                (*cc2538_pac::UDMA::ptr()).chmap2.modify(|r, w| {
                    w.bits((r.bits() & !(0b1111 << shift)) | ((assignement as u32) << shift))
                })
            },
            24..=31 => unsafe {
                (*cc2538_pac::UDMA::ptr()).chmap3.modify(|r, w| {
                    w.bits((r.bits() & !(0b1111 << shift)) | ((assignement as u32) << shift))
                })
            },
            _ => unreachable!(),
        });
    }

    /// Set the destination address increment for this channel
    #[inline]
    pub fn set_destination_increment(&mut self, increment: AddressIncrement) {
        self.control_word.set_destination_increment(increment);
        self.set_config();
    }

    /// Set the destination data size for this channel
    #[inline]
    pub fn set_destination_size(&mut self, size: DataSize) {
        self.control_word.set_destination_size(size);
        self.set_config();
    }

    /// Set the source address increment for this channel
    #[inline]
    pub fn set_source_increment(&mut self, increment: AddressIncrement) {
        self.control_word.set_source_increment(increment);
        self.set_config();
    }

    /// Set the source data size for this channel
    #[inline]
    pub fn set_source_size(&mut self, size: DataSize) {
        self.control_word.set_source_size(size);
        self.set_config();
    }

    /// Set the arbitration size for this channel
    #[inline]
    pub fn set_arbitration_size(&mut self, size: Arbitration) {
        self.control_word.set_arbitration_size(size);
        self.set_config();
    }

    /// Set the transfer size (the amount of transfers, not in bytes/bits) for this channel
    #[inline]
    pub fn set_transfer_size(&mut self, size: u8) {
        self.control_word.set_transfer_size(size);
        self.set_config();
    }

    /// Use burst mode for this channel
    #[inline]
    pub fn use_burst(&mut self, use_burst: bool) {
        if use_burst {
            free(|_| unsafe {
                (*cc2538_pac::UDMA::ptr())
                    .useburstset
                    .modify(|r, w| w.bits(r.bits() | (1 << self.channel)));
            });
        } else {
            free(|_| unsafe {
                (*cc2538_pac::UDMA::ptr())
                    .useburstclr
                    .write(|w| w.bits(1 << self.channel));
            });
        }

        self.control_word.use_burst(use_burst);
        self.set_config();
    }

    /// Set the transfer mode for this channel
    #[inline]
    pub fn set_transfer_mode(&mut self, mode: TransferMode) {
        self.control_word.set_transfer_mode(mode);
        self.set_config();
    }

    /// Set the config word in the DMA_CHANNEL_CONFIG array
    #[inline]
    fn set_config(&self) {
        free(|_| unsafe {
            DMA_CHANNEL_CONFIG.0[32 * (self.alternate as usize) + self.channel].control_word =
                self.control_word.into()
        });
    }
}

impl ChannelControlWord {
    #[inline]
    fn set_transfer_mode(&mut self, mode: TransferMode) {
        self.0 = (self.0 & !0b111) | (mode as u32 & 0b111);
    }

    #[inline]
    fn use_burst(&mut self, use_burst: bool) {
        self.0 = (self.0 & !(0b1 << 3)) | ((use_burst as u32 & 0b1) << 3);
    }

    #[inline]
    fn set_transfer_size(&mut self, size: u8) {
        self.0 = (self.0 & !(0b11_1111_1111 << 4)) | ((size as u32 & 0b11_1111_1111) << 4);
    }

    #[inline]
    fn set_arbitration_size(&mut self, size: Arbitration) {
        self.0 = (self.0 & !(0b1111 << 14)) | ((size as u32 & 0b1111) << 14);
    }

    #[inline]
    fn set_source_size(&mut self, size: DataSize) {
        self.0 = (self.0 & !(0b11 << 24)) | ((size as u32 & 0b11) << 24);
    }

    #[inline]
    fn set_source_increment(&mut self, increment: AddressIncrement) {
        self.0 = (self.0 & !(0b11 << 26)) | ((increment as u32 & 0b11) << 26);
    }

    #[inline]
    fn set_destination_size(&mut self, size: DataSize) {
        self.0 = (self.0 & !(0b11 << 28)) | ((size as u32 & 0b11) << 28);
    }

    #[inline]
    fn set_destination_increment(&mut self, increment: AddressIncrement) {
        self.0 = (self.0 & !(0b11 << 30)) | ((increment as u32 & 0b11) << 30);
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Priority {
    Default,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TransferMode {
    Stop = 0x0,
    Basic = 0x1,
    AutoRequest = 0x2,
    PingPong = 0x3,
    MemoryScatterGather = 0x4,
    AlternateMemoryScatterGather = 0x5,
    PeripheralScatterGather = 0x6,
    AlternatePeripheralScatterGather = 0x7,
}

impl Default for TransferMode {
    fn default() -> Self {
        Self::Stop
    }
}

impl From<u32> for TransferMode {
    fn from(val: u32) -> Self {
        match val {
            0x0 => Self::Stop,
            0x1 => Self::Basic,
            0x2 => Self::AutoRequest,
            0x3 => Self::PingPong,
            0x4 => Self::MemoryScatterGather,
            0x5 => Self::AlternateMemoryScatterGather,
            0x6 => Self::PeripheralScatterGather,
            0x7 => Self::AlternatePeripheralScatterGather,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AddressIncrement {
    Increment8bit = 0x0,
    Increment16bit = 0x1,
    Increment32bit = 0x2,
    None = 0x3,
}

impl Default for AddressIncrement {
    fn default() -> Self {
        Self::Increment8bit
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DataSize {
    Data8bit = 0x0,
    Data16bit = 0x1,
    Data32bit = 0x2,
}

impl Default for DataSize {
    fn default() -> Self {
        Self::Data8bit
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Arbitration {
    Transfer1 = 0x0,
    Transfer2 = 0x1,
    Tranfser4 = 0x2,
    Transfer8 = 0x3,
    Transfer16 = 0x4,
    Transfer32 = 0x5,
    Transfer64 = 0x6,
    Transfer128 = 0x7,
    Transfer256 = 0x8,
    Transfer512 = 0x9,
    NoArbitration = 0xa,
}

impl Default for Arbitration {
    fn default() -> Self {
        Self::Transfer1
    }
}

#[derive(Default, Debug, Clone, Copy, PartialEq)]
struct ChannelControlWord(u32);

impl From<ChannelControlWord> for u32 {
    fn from(val: ChannelControlWord) -> Self {
        val.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DmaState {
    Idle = 0x0,
    ReadingControllerData = 0x1,
    ReadingSourceEndPointer = 0x2,
    ReadingDestinationEndPointer = 0x3,
    ReadingSourceData = 0x4,
    WritingDestinationData = 0x5,
    WaitingRequestClear = 0x6,
    WritingControllerData = 0x7,
    Stalled = 0x8,
    Done = 0x9,
}

impl From<u8> for DmaState {
    fn from(val: u8) -> Self {
        match val {
            0x0 => Self::Idle,
            0x1 => Self::ReadingControllerData,
            0x2 => Self::ReadingSourceEndPointer,
            0x3 => Self::ReadingDestinationEndPointer,
            0x4 => Self::ReadingSourceData,
            0x5 => Self::WritingDestinationData,
            0x6 => Self::WaitingRequestClear,
            0x7 => Self::WritingControllerData,
            0x8 => Self::Stalled,
            0x9 => Self::Done,
            _ => unreachable!(),
        }
    }
}
