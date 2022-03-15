use core::marker::PhantomData;

use cc2538_pac::{aes, pka, AES, PKA};
use rtt_target::rprintln;

pub struct NotSpecified;
pub struct Sha256Engine;
pub struct EccEngine;

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
    pub fn sha256(&mut self, data: &[u8], digest: &mut [u8]) {
        let mut state = Sha256State {
            length: 0,
            state: [0; 8],
            curlen: 0,
            buf: [0; BLOCK_SIZE],
            new_digest: true,
            final_digest: false,
        };

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
    pub x_coef: [u32; SIZE],
    pub y_coef: [u32; SIZE],
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
            x_coef: [
                0xD898C296, 0xF4A13945, 0x2DEB33A0, 0x77037D81, 0x63A440F2, 0xF8BCE6E5, 0xE12C4247,
                0x6B17D1F2,
            ],
            y_coef: [
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
            x_coef: [
                0x1e794811, 0x73f977a1, 0x6b24cdd5, 0x631011ed, 0xffc8da78, 0x07192b95,
            ],
            y_coef: [
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
            rprintln!("{:0x?}", d);
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

        let extra_buf: u8 = 2 + SIZE as u8 % 2;
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
        offset = PkaRam::write_slice(&point.x[..SIZE], offset) + extra_buf as usize;
        offset = PkaRam::write_slice(&point.y[..SIZE], offset) + extra_buf as usize;

        // Save the address of the D vector.
        pka.dptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });

        // Set the size of the A vector.
        pka.alength.write(|w| unsafe { w.bits(SIZE as u32) });
        // Set the size of the B vector.
        pka.blength.write(|w| unsafe { w.bits(SIZE as u32) });

        // Start the multiplication operation.
        pka.function.write(|w| unsafe { w.bits(0x0000d000) });
        //pka.function
            //.write(|w| unsafe { w.sequencer_operations().bits(0b101).run().set_bit() });
        while self.is_pka_in_use() {}

        PkaRam::read_slice(result, offset);
    }

    pub fn mul_result(&mut self) {
        todo!();
    }

    pub fn mul_gen_pt_start(&mut self) {
        todo!();
    }

    pub fn mul_gen_pt_result(&mut self) {
        todo!();
    }

    pub fn add_start(&mut self) {
        todo!();
    }

    pub fn add_result(&mut self) {
        todo!();
    }
}
