use core::convert::TryInto;
use core::default;
use core::marker::PhantomData;

use cc2538_pac::{aes, pka, AES, PKA};
use rtt_target::rprintln;

pub struct NotSpecified {}

pub struct AesEngine<Type> {
    _type: PhantomData<Type>,
}
pub struct AesCtr {}
pub struct AesCbc {}
pub struct AesCbcMac {}
pub struct AesEcb {}
pub struct AesGcm {}
pub struct AesCcm {}

pub struct EccEngine {}
pub struct Sha256Engine {}

pub trait CryptoExt {
    type Parts;

    fn constrain(self) -> Self::Parts;
}

pub struct Crypto<'p, State> {
    _aes: PhantomData<&'p mut AES>,
    _pka: PhantomData<&'p mut PKA>,
    _state: PhantomData<State>,
}

impl<'p, State> Crypto<'p, State> {
    #[inline]
    /// Return a pointer to the AES registers.
    fn aes() -> &'static aes::RegisterBlock {
        unsafe { &*AES::ptr() }
    }

    #[inline]
    /// Return a pointer to the PKA registers.
    fn pka() -> &'static pka::RegisterBlock {
        unsafe { &*PKA::ptr() }
    }

    pub fn reset(&mut self) {
        // Resetting is performed using SysCtrl.
        // TODO: change the SysCtrl API.
    }

    /// Check if the AES resource is in use.
    pub fn is_aes_in_use(&self) -> bool {
        Self::aes().ctrl_alg_sel.read().bits() != 0
    }

    /// Check if the PKA resource is in use.
    pub fn is_pka_in_use(&self) -> bool {
        Self::pka().function.read().run().bit_is_set()
    }

    /// Check if the result of the AES operation is available.
    fn is_aes_completed(&self) -> bool {
        Self::aes().ctrl_int_stat.read().result_av().bit_is_set()
    }

    ///// Check if the result of the PKA operation is available.
    //fn is_pka_completed(&self) -> bool {
    //Self::pka().ctrl_int_stat.read().result_av().bit_is_set()
    //}
}

impl<'p> Crypto<'p, NotSpecified> {
    /// Create a new crypto instance.
    pub fn new(
        #[allow(unused_variables)] aes: &'p mut AES,
        #[allow(unused_variables)] pka: &'p mut PKA,
    ) -> Self {
        Self {
            _aes: PhantomData,
            _pka: PhantomData,
            _state: PhantomData,
        }
    }

    /// Use the crypto engine for AES operations.
    pub fn aes_engine(self) -> Crypto<'p, AesEngine<NotSpecified>> {
        Crypto {
            _aes: PhantomData,
            _pka: PhantomData,
            _state: PhantomData,
        }
    }

    /// Use the crypto engine for elliptic curve operations.
    pub fn ecc_engine(self) -> Crypto<'p, EccEngine> {
        Crypto {
            _aes: PhantomData,
            _pka: PhantomData,
            _state: PhantomData,
        }
    }

    /// Use the crypto engine for SHA256 operations.
    pub fn sha256_engine(self) -> Crypto<'p, Sha256Engine> {
        Crypto {
            _aes: PhantomData,
            _pka: PhantomData,
            _state: PhantomData,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AesKeys {
    pub keys: [u8; 128],   // 1024 bits of memory (8 128-bit keys)
    pub sizes: AesKeySize, // The type of keys stored
    pub count: u8,         // How many keys are stored
    pub start_area: u8,    // The start area in 128 bits
}

#[derive(Debug, Clone, Copy)]
pub enum AesKeySize {
    Key128 = 0b01,
    Key192 = 0b10,
    Key256 = 0b11,
}

#[derive(Debug, Clone, Copy)]
pub enum AesKey {
    Key128([u8; 16]),
    Key192([u8; 24]),
    Key256([u8; 32]),
}

impl AesKeys {
    // XXX Create a better key management system for AES
    /// Create a correctly aligned key buffer for the AES engine.
    pub fn create(keys: &[AesKey], sizes: AesKeySize, start_area: u8) -> Self {
        let mut aligned = AesKeys {
            keys: [0; 128],
            sizes,
            count: 0,
            start_area,
        };

        let mut offset = 0;
        for k in keys.iter() {
            match k {
                AesKey::Key128(k) => {
                    aligned.keys[offset..offset + k.len()].copy_from_slice(k);
                    offset += 128 / 8;
                    aligned.count += 1;
                }
                AesKey::Key192(k) => {
                    aligned.keys[offset..offset + k.len()].copy_from_slice(k);
                    offset += 128 / 8 * 2;
                    aligned.count += 2;
                }
                AesKey::Key256(k) => {
                    aligned.keys[offset..offset + k.len()].copy_from_slice(k);
                    offset += 128 / 8 * 2;
                    aligned.count += 2;
                }
            }
        }

        aligned
    }
}

impl<'p> Crypto<'p, AesEngine<NotSpecified>> {
    /// Use the AES engine in CTR mode.
    pub fn ctr_mode(self) -> Crypto<'p, AesEngine<AesCtr>> {
        Crypto {
            _aes: PhantomData,
            _pka: PhantomData,
            _state: PhantomData,
        }
    }

    /// Use the AES engine in CBC mode.
    pub fn cbc_mode(self) -> Crypto<'p, AesEngine<AesCbc>> {
        Crypto {
            _aes: PhantomData,
            _pka: PhantomData,
            _state: PhantomData,
        }
    }

    /// Use the AES engine in CBC-MAC mode.
    pub fn cbc_mac_mode(self) -> Crypto<'p, AesEngine<AesCbcMac>> {
        Crypto {
            _aes: PhantomData,
            _pka: PhantomData,
            _state: PhantomData,
        }
    }

    /// Use the AES engine in ECB mode.
    pub fn ecb_mode(self) -> Crypto<'p, AesEngine<AesEcb>> {
        Crypto {
            _aes: PhantomData,
            _pka: PhantomData,
            _state: PhantomData,
        }
    }

    /// Use the AES engine in GCM mode.
    pub fn gcm_mode(self) -> Crypto<'p, AesEngine<AesGcm>> {
        Crypto {
            _aes: PhantomData,
            _pka: PhantomData,
            _state: PhantomData,
        }
    }

    /// Use the AES engine in CCM mode.
    pub fn ccm_mode(self) -> Crypto<'p, AesEngine<AesCcm>> {
        Crypto {
            _aes: PhantomData,
            _pka: PhantomData,
            _state: PhantomData,
        }
    }
}

#[derive(Debug)]
pub enum CryptoMode {
    StoreKeys,
    HashAndTag,
    Tag,
    Hash,
    Aes,
}

impl<'p, Type> Crypto<'p, AesEngine<Type>> {
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

    /// Load a key into AES key RAM.
    pub fn load_key(&mut self, aes_keys: &AesKeys) {
        if self.is_aes_in_use() {
            rprintln!("aes is already in use.");
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

    pub fn auth_crypt(
        &mut self,
        ctrl: impl FnOnce(&aes::RegisterBlock),
        key_index: u32,
        iv: Option<&[u8]>,
        adata: &[u8],
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
            rprintln!("key load error");
            return;
        }

        if let Some(iv) = iv {
            self.write_iv(iv);
        }

        ctrl(aes);

        aes.aes_c_length_0
            .write(|w| unsafe { w.bits(data_in.len() as u32) });
        aes.aes_c_length_1.write(|w| unsafe { w.bits(0) });

        if aes.aes_ctrl.read().ccm().bit_is_set() || aes.aes_ctrl.read().gcm().bits() != 0 {
            aes.aes_auth_length
                .write(|w| unsafe { w.auth_length().bits(adata.len() as u32) });

            if !adata.is_empty() {
                aes.dmac_ch0_ctrl.modify(|_, w| w.en().set_bit());
                aes.dmac_ch0_extaddr
                    .modify(|_, w| unsafe { w.addr().bits(adata.as_ptr() as u32) });
                aes.dmac_ch0_dmalength
                    .modify(|_, w| unsafe { w.dmalen().bits(adata.len() as u16) });
                while !aes.ctrl_int_stat.read().dma_in_done().bit_is_set() {}

                if aes.ctrl_int_stat.read().dma_bus_err().bit_is_set() {
                    rprintln!("dma bus error");
                    return;
                }

                aes.ctrl_int_clr.write(|w| w.dma_in_done().set_bit());
            }
        }

        if !data_in.is_empty() {
            aes.dmac_ch0_ctrl.modify(|_, w| w.en().set_bit());
            aes.dmac_ch0_extaddr
                .modify(|_, w| unsafe { w.addr().bits(data_in.as_ptr() as u32) });
            aes.dmac_ch0_dmalength
                .modify(|_, w| unsafe { w.dmalen().bits(data_in.len() as u16) });

            if !data_out.is_empty() {
                aes.dmac_ch1_ctrl.modify(|_, w| w.en().set_bit());
                aes.dmac_ch1_extaddr
                    .modify(|_, w| unsafe { w.addr().bits(data_out.as_ptr() as u32) });
                aes.dmac_ch1_dmalength
                    .modify(|_, w| unsafe { w.dmalen().bits(data_out.len() as u16) });
            }
        }

        while !(aes.ctrl_int_stat.read().dma_bus_err().bit_is_set()
            || aes.ctrl_int_stat.read().key_st_rd_err().bit_is_set()
            || aes.ctrl_int_stat.read().key_st_wr_err().bit_is_set()
            || aes.ctrl_int_stat.read().result_av().bit_is_set())
        {}

        //cortex_m::asm::bkpt();
    }
}

#[derive(Debug, Default)]
pub enum CtrWidth {
    #[default]
    Width128,
    Width256,
}

impl<'p> Crypto<'p, AesEngine<AesCcm>> {
    const CCM_NONCE_LEN: usize = 15;
    pub fn ccm_encrypt(
        &mut self,
        key_index: u32,
        len: u8,
        nonce: &[u8],
        mic_len: u8,
        adata: &[u8],
        data_in: &[u8],
        data_out: &mut [u8],
    ) {
        if self.is_aes_in_use() {
            return;
        }

        let m = (mic_len.max(2) - 2) >> 1;
        let l = len - 1;

        let ctrl = |aes: &aes::RegisterBlock| unsafe {
            aes.aes_ctrl.modify(|_, w| {
                w.save_context()
                    .set_bit()
                    .ccm_m()
                    .bits(m)
                    .ccm_l()
                    .bits(l)
                    .ccm()
                    .set_bit()
                    .ctr_width()
                    .bits(CtrWidth::Width128 as u8)
                    .ctr()
                    .set_bit()
                    .direction()
                    .set_bit()
            });
        };

        // Prepare the IV
        // The first part is the length of the data minus 1.
        // The following part is the nonce.
        // And the rest is the counter.
        let mut iv = [0u8; 16];
        iv[0] = len - 1;
        iv[1..][..Self::CCM_NONCE_LEN - len as usize].copy_from_slice(nonce);
        iv[16-len as usize..].fill_with(|| 0);

        self.auth_crypt(ctrl, key_index, Some(&iv), adata, data_in, data_out);
    }

    pub fn ccm_decrypt(&mut self) {
        todo!();
    }
}

const BLOCK_SIZE: usize = 64;
const OUTPUT_LEN: usize = 32;

#[derive(Debug, Clone, Copy)]
pub struct Sha256State {
    length: u64,
    state: [u32; 8],
    curlen: u32,
    buf: [u8; BLOCK_SIZE],
    new_digest: bool,
    final_digest: bool,
}

impl<'p> Crypto<'p, Sha256Engine> {
    pub fn sha256(&mut self, data: impl AsRef<[u8]>, digest: &mut impl AsMut<[u8]>) {
        let mut state = Sha256State {
            length: 0,
            state: [0; 8],
            curlen: 0,
            buf: [0; BLOCK_SIZE],
            new_digest: true,
            final_digest: false,
        };

        let data = data.as_ref();
        let digest = digest.as_mut();

        assert!(!data.is_empty());
        assert!(digest.len() == 32);

        let mut offset = 0;
        let mut len = data.len();

        // Check if the resource is in use
        if self.is_aes_in_use() {
            return;
        }

        if len > 0 && state.new_digest {
            if state.curlen == 0 && len > BLOCK_SIZE {
                state
                    .buf
                    .copy_from_slice(&data[offset..offset + BLOCK_SIZE]);
                self.new_hash(&mut state);
                state.new_digest = false;
                state.length += (BLOCK_SIZE << 3) as u64;
                offset += BLOCK_SIZE;
                len -= BLOCK_SIZE;
            } else {
                let n = usize::min(len, BLOCK_SIZE - state.curlen as usize);
                state.buf[state.curlen as usize..n].copy_from_slice(&data[offset..offset + n]);
                state.curlen += n as u32;
                offset += n;
                len -= n;

                if state.curlen == BLOCK_SIZE as u32 && len > 0 {
                    self.new_hash(&mut state);
                    state.new_digest = false;
                    state.length += (BLOCK_SIZE << 3) as u64;
                    state.curlen = 0;
                }
            }
        }

        while len > 0 && !state.new_digest {
            if state.curlen == 0 && len > BLOCK_SIZE {
                state
                    .buf
                    .copy_from_slice(&data[offset..offset + BLOCK_SIZE]);
                self.resume_hash(&mut state);
                state.length += (BLOCK_SIZE << 3) as u64;
                offset += BLOCK_SIZE;
                len -= BLOCK_SIZE;
            } else {
                let n = usize::min(len, BLOCK_SIZE - state.curlen as usize);
                state.buf[state.curlen as usize..n].copy_from_slice(&data[offset..offset + n]);
                state.curlen += n as u32;
                offset += n;
                len -= n;

                if state.curlen == BLOCK_SIZE as u32 && len > 0 {
                    self.resume_hash(&mut state);
                    state.length += (BLOCK_SIZE << 3) as u64;
                    state.curlen = 0;
                }
            }
        }

        self.finalize(&mut state);

        digest.copy_from_slice(unsafe { &core::mem::transmute::<[u32; 8], [u8; 32]>(state.state) });
    }

    fn new_hash(&mut self, state: &mut Sha256State) {
        let aes = Self::aes();
        // Workaround for AES registers not retained after PM2
        aes.ctrl_int_cfg.write(|w| w.level().set_bit());
        aes.ctrl_int_en
            .write(|w| w.dma_in_done().set_bit().result_av().set_bit());

        // Configure master control module and enable DMA path to the SHA-256 engine.
        // Enable digest readout.
        aes.ctrl_alg_sel
            .write(|w| w.tag().set_bit().hash().set_bit());

        // Clear any outstanding events.
        aes.ctrl_int_clr.write(|w| w.result_av().set_bit());

        // Configure the hash engine.
        // Indicate start of a new hash session and SHA-256.
        aes.hash_mode_in
            .write(|w| w.sha256_mode().set_bit().new_hash().set_bit());

        // If the final digest is required (pad the input DMA data).
        if state.final_digest {
            unsafe {
                aes.hash_length_in_l
                    .write(|w| w.length_in().bits((state.length & 0xffff_ffff) as u32));

                aes.hash_length_in_h
                    .write(|w| w.length_in().bits((state.length >> 32) as u32));

                aes.hash_io_buf_ctrl
                    .write(|w| w.pad_dma_message().set_bit());
            }
        }

        // Enable DMA channel 0.
        aes.dmac_ch0_ctrl.write(|w| w.en().set_bit());

        // Base address of the data in external memory.
        unsafe {
            aes.dmac_ch0_extaddr
                .write(|w| w.addr().bits(state.buf.as_ptr() as u32))
        };

        if state.final_digest {
            unsafe {
                aes.dmac_ch0_dmalength
                    .write(|w| w.dmalen().bits(state.curlen as u16))
            };
        } else {
            unsafe {
                aes.dmac_ch0_dmalength
                    .write(|w| w.dmalen().bits(BLOCK_SIZE as u16))
            };
        }

        // Enable DMA channel 1.
        aes.dmac_ch1_ctrl.write(|w| w.en().set_bit());

        unsafe {
            // Base address of the digest buffer.
            aes.dmac_ch1_extaddr
                .write(|w| w.addr().bits(state.state.as_ptr() as u32));
            // Length of the result digest.
            aes.dmac_ch1_dmalength
                .write(|w| w.dmalen().bits(OUTPUT_LEN as u16));
        }

        // Wait for the completion of the operation.
        while !self.is_aes_completed() {}

        // Clear the interrupt.
        aes.ctrl_int_clr
            .write(|w| w.dma_in_done().set_bit().result_av().set_bit());

        unsafe {
            // Disable master control.
            aes.ctrl_alg_sel.write(|w| w.bits(0));
            // Clear mode
            aes.aes_ctrl.write(|w| w.bits(0));
        }
    }

    fn resume_hash(&mut self, state: &mut Sha256State) {
        let aes = Self::aes();
        // Workaround for AES registers not retained after PM2.
        aes.ctrl_int_cfg.write(|w| w.level().set_bit());
        aes.ctrl_int_en
            .write(|w| w.dma_in_done().set_bit().result_av().set_bit());

        // Configure master control module and enable the DMA path to the SHA2-256 engine.
        aes.ctrl_alg_sel.write(|w| w.hash().set_bit());

        // Clear any outstanding events.
        aes.ctrl_int_clr.write(|w| w.result_av().set_bit());

        // Configure hash engine.
        // Indicate the start of a resumed hash session and SHA-256.
        aes.hash_mode_in.write(|w| w.sha256_mode().set_bit());

        // If the final digest is required (pad the input DMA data).
        if state.final_digest {
            unsafe {
                aes.hash_length_in_l
                    .write(|w| w.length_in().bits((state.length & 0xffff_ffff) as u32));
                aes.hash_length_in_h
                    .write(|w| w.length_in().bits((state.length >> 32) as u32));
            }
        }

        // Write the initial digest.
        unsafe {
            aes.hash_digest_a
                .write(|w| w.hash_digest().bits(state.state[0]));
            aes.hash_digest_b
                .write(|w| w.hash_digest().bits(state.state[1]));
            aes.hash_digest_c
                .write(|w| w.hash_digest().bits(state.state[2]));
            aes.hash_digest_d
                .write(|w| w.hash_digest().bits(state.state[3]));
            aes.hash_digest_e
                .write(|w| w.hash_digest().bits(state.state[4]));
            aes.hash_digest_f
                .write(|w| w.hash_digest().bits(state.state[5]));
            aes.hash_digest_g
                .write(|w| w.hash_digest().bits(state.state[6]));
            aes.hash_digest_h
                .write(|w| w.hash_digest().bits(state.state[7]));
        }

        // If final digest, pad the DMA-ed data.
        if state.final_digest {
            aes.hash_io_buf_ctrl
                .write(|w| w.pad_dma_message().set_bit());
        }

        // Enable DMA channel 0.
        aes.dmac_ch0_ctrl.write(|w| w.en().set_bit());
        // Base address of the data in external memory.
        unsafe {
            aes.dmac_ch0_extaddr
                .write(|w| w.addr().bits(state.buf.as_ptr() as u32))
        };

        if state.final_digest {
            unsafe {
                aes.dmac_ch0_dmalength
                    .write(|w| w.dmalen().bits(state.curlen as u16))
            };
        } else {
            unsafe {
                aes.dmac_ch0_dmalength
                    .write(|w| w.dmalen().bits(BLOCK_SIZE as u16))
            };
        }

        // Wait for the completion of the operation.
        while !self.is_aes_completed() {}

        // Read the digest
        state.state[0] = aes.hash_digest_a.read().bits();
        state.state[1] = aes.hash_digest_b.read().bits();
        state.state[2] = aes.hash_digest_c.read().bits();
        state.state[3] = aes.hash_digest_d.read().bits();
        state.state[4] = aes.hash_digest_e.read().bits();
        state.state[5] = aes.hash_digest_f.read().bits();
        state.state[6] = aes.hash_digest_g.read().bits();
        state.state[7] = aes.hash_digest_h.read().bits();

        // Ack reading of the digest.
        aes.hash_io_buf_ctrl.write(|w| w.output_full().set_bit());

        // Clear the interrupt.
        aes.ctrl_int_clr
            .write(|w| w.dma_in_done().set_bit().result_av().set_bit());

        unsafe {
            // Disable master control.
            aes.ctrl_alg_sel.write(|w| w.bits(0));
            // Clear mode
            aes.aes_ctrl.write(|w| w.bits(0));
        }
    }

    fn finalize(&mut self, state: &mut Sha256State) {
        state.length += (state.curlen << 3) as u64;
        state.final_digest = true;

        if state.new_digest {
            self.new_hash(state);
        } else {
            self.resume_hash(state);
        }

        state.new_digest = false;
        state.final_digest = false;
    }
}

pub struct EccCurveInfo<'e, const SIZE: usize> {
    pub name: &'e str,
    pub prime: [u32; SIZE],
    pub order: [u32; SIZE],
    pub a_coef: [u32; SIZE],
    pub b_coef: [u32; SIZE],
    pub bp_x: [u32; SIZE],
    pub bp_y: [u32; SIZE],
}

impl<'e, const SIZE: usize> EccCurveInfo<'e, SIZE> {
    /// Create the curve information for the NIST P-256 curve.
    pub const fn nist_p_256() -> EccCurveInfo<'e, 8> {
        EccCurveInfo {
            name: "NIST P-256",
            prime: [
                0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001,
                0xFFFFFFFF,
            ],
            order: [
                0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
                0xFFFFFFFF,
            ],
            a_coef: [
                0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001,
                0xFFFFFFFF,
            ],
            b_coef: [
                0x27D2604B, 0x3BCE3C3E, 0xCC53B0F6, 0x651D06B0, 0x769886BC, 0xB3EBBD55, 0xAA3A93E7,
                0x5AC635D8,
            ],
            bp_x: [
                0xD898C296, 0xF4A13945, 0x2DEB33A0, 0x77037D81, 0x63A440F2, 0xF8BCE6E5, 0xE12C4247,
                0x6B17D1F2,
            ],
            bp_y: [
                0x37BF51F5, 0xCBB64068, 0x6B315ECE, 0x2BCE3357, 0x7C0F9E16, 0x8EE7EB4A, 0xFE1A7F9B,
                0x4FE342E2,
            ],
        }
    }

    /// Create the curve information for the NIST P-192 curve.
    pub const fn nist_p_192() -> EccCurveInfo<'e, 6> {
        EccCurveInfo {
            name: "NIST P-192",
            prime: [
                0xffffffff, 0xffffffff, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff,
            ],
            order: [
                0xfffffffc, 0xffffffff, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff,
            ],
            a_coef: [
                0xc146b9b1, 0xfeb8deec, 0x72243049, 0x0fa7e9ab, 0xe59c80e7, 0x64210519,
            ],
            b_coef: [
                0x82ff1012, 0xf4ff0afd, 0x43a18800, 0x7cbf20eb, 0xb03090f6, 0x188da80e,
            ],
            bp_x: [
                0x1e794811, 0x73f977a1, 0x6b24cdd5, 0x631011ed, 0xffc8da78, 0x07192b95,
            ],
            bp_y: [
                0xb4d22831, 0x146bc9b1, 0x99def836, 0xffffffff, 0xffffffff, 0xffffffff,
            ],
        }
    }
}

pub struct EcPoint<'p> {
    pub x: &'p [u32],
    pub y: &'p [u32],
}

pub struct PkaRam {}

impl PkaRam {
    const PKA_RAM_PTR: usize = 0x4400_6000;
    const PKA_RAM_SIZE: usize = 0x800;

    /// Write a slice into the memory the PKA RAM.
    fn write_slice(data: &[u32], offset: usize) -> usize {
        assert!(offset + data.len() * 4 < Self::PKA_RAM_SIZE);

        for (i, d) in data.iter().enumerate() {
            let addr = Self::PKA_RAM_PTR + offset + i * 4;
            unsafe {
                core::ptr::write_volatile(addr as *mut u32, *d);
            }
        }

        4 * data.len()
    }

    /// Write data form PKA RAM into a slice.
    fn read_slice(data: &mut [u32], offset: usize) {
        assert!(offset + data.len() * 4 < Self::PKA_RAM_SIZE);

        for (i, d) in data.iter_mut().enumerate() {
            let addr = Self::PKA_RAM_PTR + offset + i * 4;
            unsafe {
                *d = core::ptr::read_volatile(addr as *mut u32);
            }
        }
    }
}

impl<'p> Crypto<'p, EccEngine> {
    pub fn mul<const SIZE: usize>(
        &mut self,
        curve: &EccCurveInfo<SIZE>,
        scalar: &[u32],
        point: &EcPoint,
        result: &mut [u32],
    ) {
        if self.is_pka_in_use() {
            return;
        }

        let pka = Self::pka();

        let extra_buf: u8 = (2 + SIZE as u8 % 2) * 4;
        let mut offset: usize = 0;

        // Save the address of the A vector.
        pka.aptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        // Write the scalar to it.
        offset += PkaRam::write_slice(scalar, offset) + SIZE % 2;

        // Save the address of the B vector.
        pka.bptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        // First write the primes, followed by the a and b coef.
        offset += PkaRam::write_slice(&curve.prime[..], offset) + extra_buf as usize;
        offset += PkaRam::write_slice(&curve.a_coef[..], offset) + extra_buf as usize;
        offset += PkaRam::write_slice(&curve.b_coef[..], offset) + extra_buf as usize;

        // Save the address of the C vector.
        pka.cptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        // First write the x coordinate, followed by the y coordinate.
        offset += PkaRam::write_slice(&point.x[..SIZE], offset) + extra_buf as usize;
        offset += PkaRam::write_slice(&point.y[..SIZE], offset) + extra_buf as usize;

        // Save the address of the D vector.
        pka.dptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });

        // Set the size of the A vector.
        pka.alength.write(|w| unsafe { w.bits(SIZE as u32) });
        // Set the size of the B vector.
        pka.blength.write(|w| unsafe { w.bits(SIZE as u32) });

        // Start the multiplication operation.
        //pka.function.write(|w| unsafe { w.bits(0x0000d000) });
        pka.function
            .write(|w| unsafe { w.sequencer_operations().bits(0b101).run().set_bit() });
        while self.is_pka_in_use() {}

        if pka.shift.read().bits() != 0x0 && pka.shift.read().bits() != 0x7 {
            rprintln!("Something went wrong");

            return;
        }

        let msw_val = pka.msw.read().msw_address().bits() as usize;
        if msw_val == 0 || pka.msw.read().result_is_zero().bit_is_set() {
            rprintln!("Result is 0");
            return;
        }

        let len1 = msw_val + 1;
        let len2 = pka.dptr.read().bits() as usize;
        let len = len1 - len2;

        PkaRam::read_slice(&mut result[..len], offset);
        offset += 4 * (len + 2 + (len % 2));
        PkaRam::read_slice(&mut result[len..][..len], offset);
    }

    pub fn add<const SIZE: usize>(
        &mut self,
        curve: &EccCurveInfo<SIZE>,
        point_a: &EcPoint,
        point_b: &EcPoint,
        result: &mut [u32],
    ) {
        if self.is_pka_in_use() {
            return;
        }

        let pka = Self::pka();

        let extra_buf: u8 = 2 + (SIZE as u8 % 2);
        let mut offset: usize = 0;

        // Save the address of the A vector.
        pka.aptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        // Write the scalar to it.
        offset += PkaRam::write_slice(&point_a.x[..SIZE], offset) + 4 * extra_buf as usize;
        offset += PkaRam::write_slice(&point_a.y[..SIZE], offset) + 4 * extra_buf as usize;

        // Save the address of the B vector.
        pka.bptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        // First write the primes, followed by the a and b coef.
        offset += PkaRam::write_slice(&curve.prime[..], offset) + 4 * extra_buf as usize;
        offset += PkaRam::write_slice(&curve.a_coef[..], offset) + 4 * extra_buf as usize;

        // Save the address of the C vector.
        pka.cptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        // First write the x coordinate, followed by the y coordinate.
        offset += PkaRam::write_slice(&point_b.x[..SIZE], offset) + 4 * extra_buf as usize;
        offset += PkaRam::write_slice(&point_b.y[..SIZE], offset) + 4 * extra_buf as usize;

        // Save the address of the D vector.
        pka.dptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });

        // Set the size of the A vector.
        //pka.alength.write(|w| unsafe { w.bits(SIZE as u32) });
        // Set the size of the B vector.
        pka.blength.write(|w| unsafe { w.bits(SIZE as u32) });

        // Start the multiplication operation.
        //pka.function.write(|w| unsafe { w.bits(0x0000b000) });
        pka.function
            .write(|w| unsafe { w.sequencer_operations().bits(0b011).run().set_bit() });
        while self.is_pka_in_use() {}

        if pka.shift.read().bits() != 0x0 && pka.shift.read().bits() != 0x7 {
            rprintln!("Something went wrong");

            return;
        }

        let msw_val = pka.msw.read().msw_address().bits() as usize;
        if msw_val == 0 || pka.msw.read().result_is_zero().bit_is_set() {
            rprintln!("Result is 0");
            return;
        }

        let len1 = msw_val + 1;
        let len2 = pka.dptr.read().bits() as usize;
        let len = len1 - len2;

        PkaRam::read_slice(&mut result[..len], offset);
        offset += 4 * (len + 2 + (len % 2));
        PkaRam::read_slice(&mut result[len..][..len], offset);
    }
}
