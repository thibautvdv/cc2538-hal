use core::convert::TryInto;
use core::marker::PhantomData;

use cc2538_pac::aes;

use super::Crypto;
use super::CryptoMode;
use super::NotSpecified;

pub mod keys;
use keys::AesKeys;

pub mod ccm;
pub mod ctr;

use ccm::AesCcm;
use ctr::AesCtr;

pub struct AesEngine<Type> {
    _type: PhantomData<Type>,
}
pub struct AesCbc {}
pub struct AesCbcMac {}
pub struct AesEcb {}
pub struct AesGcm {}

impl<'p> Crypto<'p> {
    /// Workaround for AES registers not retained after PM2.
    #[inline]
    fn workaround(&mut self) {
        let aes = Self::aes();
        aes.ctrl_int_cfg.write(|w| w.level().set_bit());
        aes.ctrl_int_en
            .write(|w| w.dma_in_done().set_bit().result_av().set_bit());
    }

    #[inline]
    fn set_mode(&mut self, mode: CryptoMode) {
        let aes = Self::aes();
        match mode {
            CryptoMode::StoreKeys => {
                aes.ctrl_alg_sel.write(|w| w.keystore().set_bit());
            }
            CryptoMode::HashAndTag => {
                aes.ctrl_alg_sel
                    .write(|w| w.tag().set_bit().hash().set_bit());
            }
            CryptoMode::Tag => {
                aes.ctrl_alg_sel.write(|w| w.tag().set_bit());
            }
            CryptoMode::Hash => {
                aes.ctrl_alg_sel.write(|w| w.hash().set_bit());
            }
            CryptoMode::Aes => {
                aes.ctrl_alg_sel.write(|w| w.aes().set_bit());
            }
        }
    }

    #[inline]
    fn enable_dma_channel0(&mut self) {
        Self::aes().dmac_ch0_ctrl.write(|w| w.en().set_bit());
    }

    #[inline]
    fn set_dma_channel0_ext_addr(&mut self, addr: u32) {
        Self::aes()
            .dmac_ch0_extaddr
            .write(|w| unsafe { w.addr().bits(addr) });
    }

    #[inline]
    fn set_dma_channel0_dmalength(&mut self, length: u16) {
        Self::aes()
            .dmac_ch0_dmalength
            .write(|w| unsafe { w.dmalen().bits(length) });
    }

    #[inline]
    fn enable_dma_channel1(&mut self) {
        Self::aes().dmac_ch1_ctrl.write(|w| w.en().set_bit());
    }

    #[inline]
    fn set_dma_channel1_ext_addr(&mut self, addr: u32) {
        Self::aes()
            .dmac_ch1_extaddr
            .write(|w| unsafe { w.addr().bits(addr) });
    }

    #[inline]
    fn set_dma_channel1_dmalength(&mut self, length: u16) {
        Self::aes()
            .dmac_ch1_dmalength
            .write(|w| unsafe { w.dmalen().bits(length) });
    }

    /// Enable the DMA path to the AES engine.
    #[inline]
    fn enable_dma_path(&mut self) {
        Self::aes().ctrl_alg_sel.modify(|_, w| w.aes().set_bit());
    }

    /// Clear any outstanding events.
    #[inline]
    fn clear_events(&mut self) {
        Self::aes().ctrl_int_clr.write(|w| w.result_av().set_bit());
    }

    #[inline]
    fn is_completed(&mut self) -> bool {
        Self::aes().ctrl_int_stat.read().result_av().bit_is_set()
    }

    /// Preload a key from the key RAM.
    #[inline]
    fn set_key(&mut self, key_area: u32) {
        Self::aes()
            .key_store_read_area
            .modify(|_, w| unsafe { w.bits(key_area) });
    }

    /// Returns `true` when all keys are loaded into the AES engine.
    #[inline]
    fn key_is_set(&mut self) -> bool {
        Self::aes().key_store_read_area.read().busy().bit_is_clear()
    }

    /// Returns `true` when there was an error when loading the key to the AES engine.
    #[inline]
    fn key_load_error(&mut self) -> bool {
        Self::aes()
            .ctrl_int_stat
            .read()
            .key_st_rd_err()
            .bit_is_set()
    }

    /// Save the context of the AES operation (for example the IV or the TAG).
    #[inline]
    fn save_context(&mut self) {
        Self::aes()
            .aes_ctrl
            .modify(|_, w| w.save_context().set_bit());
    }

    #[inline]
    fn write_dma0(&mut self, data: &[u8]) {
        let aes = Self::aes();

        aes.dmac_ch0_ctrl.modify(|_, w| w.en().set_bit());
        aes.dmac_ch0_extaddr
            .modify(|_, w| unsafe { w.addr().bits(data.as_ptr() as u32) });
        aes.dmac_ch0_dmalength
            .modify(|_, w| unsafe { w.dmalen().bits(data.len() as u16) });

        while !aes.ctrl_int_stat.read().dma_in_done().bit_is_set() {}
    }

    #[inline]
    fn write_dma1(&mut self, data: &[u8]) {
        let aes = Self::aes();

        aes.dmac_ch1_ctrl.modify(|_, w| w.en().set_bit());
        aes.dmac_ch1_extaddr
            .modify(|_, w| unsafe { w.addr().bits(data.as_ptr() as u32) });
        aes.dmac_ch1_dmalength
            .modify(|_, w| unsafe { w.dmalen().bits(data.len() as u16) });

        while !aes.ctrl_int_stat.read().dma_in_done().bit_is_set() {}
    }

    /// Set the IV in the AES engine.
    fn write_iv(&mut self, iv: &[u8]) {
        assert!(iv.len() == 16);

        // Convert the IV to 4 u32 words.
        let mut iv_u32: [u32; 4] = [0; 4];
        for (i, c) in iv.chunks(4).enumerate() {
            iv_u32[i] = u32::from_le_bytes(c.try_into().unwrap());
        }

        let aes = Self::aes();
        unsafe {
            aes.aes_iv_0.write(|w| w.bits(iv_u32[0]));
            aes.aes_iv_1.write(|w| w.bits(iv_u32[1]));
            aes.aes_iv_2.write(|w| w.bits(iv_u32[2]));
            aes.aes_iv_3.write(|w| w.bits(iv_u32[3]));
        }
    }

    fn read_tag(&mut self, tag: &mut [u8]) {
        assert!(tag.len() == 16);

        let mut tag_u32 = [0u32; 4];

        let aes = Self::aes();
        tag_u32[0] = aes.aes_tag_out_0.read().bits();
        tag_u32[1] = aes.aes_tag_out_1.read().bits();
        tag_u32[2] = aes.aes_tag_out_2.read().bits();
        tag_u32[3] = aes.aes_tag_out_3.read().bits();

        for (i, c) in tag_u32.iter().enumerate() {
            let b = c.to_le_bytes();
            for j in 0..4 {
                tag[i * 4 + j] = b[j];
            }
        }
    }

    /// Load a key into AES key RAM.
    pub fn load_key(&mut self, aes_keys: &AesKeys) {
        if self.is_aes_in_use() {
            return; // FIXME
        }

        let aes = Self::aes();

        self.workaround();

        // Configure the master module.
        self.set_mode(CryptoMode::StoreKeys);

        self.clear_events();

        // Writing to key_store_size deletes all keys.
        if aes.key_store_size.read().key_size().bits() != aes_keys.sizes as u8 {
            unsafe {
                aes.key_store_size
                    .modify(|_, w| w.key_size().bits(aes_keys.sizes as u8));
            }
        }

        // Free possibly already occupied key areas.
        let areas = ((0x1 << aes_keys.count) - 1) << aes_keys.start_area;
        unsafe { aes.key_store_written_area.write(|w| w.bits(areas)) };
        // Enable key areas to write.
        unsafe { aes.key_store_write_area.write(|w| w.bits(areas)) };

        self.enable_dma_channel0();
        self.set_dma_channel0_ext_addr(aes_keys.keys.as_ptr() as u32);
        self.set_dma_channel0_dmalength((aes_keys.count << 4) as u16);

        while !self.is_completed() {}

        if aes.ctrl_int_stat.read().dma_bus_err().bit_is_set() {
            // Clear the error
            aes.ctrl_int_clr.write(|w| w.dma_bus_err().set_bit());
            //self.disable_master_control();
            return; // Err(CryptoError::DmaBusError);
        }

        if aes.ctrl_int_stat.read().key_st_wr_err().bit_is_set() {
            // Clear the error
            aes.ctrl_int_clr.write(|w| w.key_st_wr_err().set_bit());
            //self.disable_master_control();
            return;
        }

        //self.ack_interrupt();
        aes.ctrl_int_clr
            .write(|w| w.dma_in_done().set_bit().result_av().set_bit());
        aes.ctrl_alg_sel.write(|w| unsafe { w.bits(0) });

        //self.disable_master_control();

        if (aes.key_store_written_area.read().bits() & areas) != areas {
            return;
        }
    }

    fn auth_crypt(
        &mut self,
        ctrl: impl FnOnce(&aes::RegisterBlock),
        key_index: u32,
        iv: Option<&[u8]>,
        adata: Option<&[u8]>,
        data_in: &[u8],
        data_out: &[u8],
    ) {
        if self.is_aes_in_use() {
            return;
        }

        let aes = Self::aes();
        aes.ctrl_alg_sel.modify(|_, w| w.aes().set_bit());

        aes.ctrl_int_clr
            .write(|w| w.dma_in_done().set_bit().result_av().set_bit());

        self.set_key(key_index);
        while !self.key_is_set() {}

        if self.key_load_error() {
            return;
        }

        if let Some(iv) = iv {
            self.write_iv(iv);
        }

        ctrl(aes);

        aes.aes_c_length_0
            .write(|w| unsafe { w.bits(data_in.len() as u32) });
        aes.aes_c_length_1.write(|w| unsafe { w.bits(0) });

        if let Some(adata) = adata {
            aes.aes_auth_length
                .write(|w| unsafe { w.auth_length().bits(adata.len() as u32) });

            if !adata.is_empty() {
                self.write_dma0(adata);

                if aes.ctrl_int_stat.read().dma_bus_err().bit_is_set() {
                    return;
                }

                aes.ctrl_int_clr.write(|w| w.dma_in_done().set_bit());
            }
        }

        if !data_in.is_empty() {
            self.write_dma0(data_in);

            if !data_out.is_empty() {
                self.write_dma1(data_out);
            }
        }

        while !(aes.ctrl_int_stat.read().dma_bus_err().bit_is_set()
            || aes.ctrl_int_stat.read().key_st_rd_err().bit_is_set()
            || aes.ctrl_int_stat.read().key_st_wr_err().bit_is_set()
            || aes.ctrl_int_stat.read().result_av().bit_is_set())
        {}
    }
}
