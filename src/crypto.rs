use core::marker::PhantomData;

use cc2538_pac::{aes, AES};

pub struct NotSpecified;
pub struct Sha256Engine;

pub trait CryptoExt {
    type Parts;

    fn constrain(self) -> Self::Parts;
}

pub struct Crypto<STATE> {
    aes: AES,
    _state: PhantomData<STATE>,
}

impl CryptoExt for AES {
    type Parts = Crypto<NotSpecified>;

    fn constrain(self) -> Self::Parts {
        Crypto {
            aes: self,
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

impl<STATE> Crypto<STATE> {
    pub fn reset(&mut self) {
        // Resetting is performed using SysCtrl.
        // TODO: change the SysCtrl API.
    }

    pub fn free(self) -> AES {
        self.aes
    }
}

impl Crypto<NotSpecified> {
    pub fn sha256_engine(self) -> Crypto<Sha256Engine> {
        Crypto {
            aes: self.aes,
            _state: PhantomData,
        }
    }
}

impl Crypto<Sha256Engine> {
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
        if self.is_in_use() {
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
        // Workaround for AES registers not retained after PM2
        self.aes.ctrl_int_cfg.write(|w| w.level().set_bit());
        self.aes
            .ctrl_int_en
            .write(|w| w.dma_in_done().set_bit().result_av().set_bit());

        // Configure master control module and enable DMA path to the SHA-256 engine.
        // Enable digest readout.
        self.aes
            .ctrl_alg_sel
            .write(|w| w.tag().set_bit().hash().set_bit());

        // Clear any outstanding events.
        self.aes.ctrl_int_clr.write(|w| w.result_av().set_bit());

        // Configure the hash engine.
        // Indicate start of a new hash session and SHA-256.
        self.aes
            .hash_mode_in
            .write(|w| w.sha256_mode().set_bit().new_hash().set_bit());

        // If the final digest is required (pad the input DMA data).
        if state.final_digest {
            unsafe {
                self.aes
                    .hash_length_in_l
                    .write(|w| w.length_in().bits((state.length & 0xffff_ffff) as u32));

                self.aes
                    .hash_length_in_h
                    .write(|w| w.length_in().bits((state.length >> 32) as u32));

                self.aes
                    .hash_io_buf_ctrl
                    .write(|w| w.pad_dma_message().set_bit());
            }
        }

        // Enable DMA channel 0.
        self.aes.dmac_ch0_ctrl.write(|w| w.en().set_bit());

        // Base address of the data in external memory.
        unsafe {
            self.aes
                .dmac_ch0_extaddr
                .write(|w| w.addr().bits(state.buf.as_ptr() as u32))
        };

        if state.final_digest {
            unsafe {
                self.aes
                    .dmac_ch0_dmalength
                    .write(|w| w.dmalen().bits(state.curlen as u16))
            };
        } else {
            unsafe {
                self.aes
                    .dmac_ch0_dmalength
                    .write(|w| w.dmalen().bits(BLOCK_SIZE as u16))
            };
        }

        // Enable DMA channel 1.
        self.aes.dmac_ch1_ctrl.write(|w| w.en().set_bit());

        unsafe {
            // Base address of the digest buffer.
            self.aes
                .dmac_ch1_extaddr
                .write(|w| w.addr().bits(state.state.as_ptr() as u32));
            // Length of the result digest.
            self.aes
                .dmac_ch1_dmalength
                .write(|w| w.dmalen().bits(OUTPUT_LEN as u16));
        }

        // Wait for the completion of the operation.
        while !self.is_completed() {}

        // Clear the interrupt.
        self.aes
            .ctrl_int_clr
            .write(|w| w.dma_in_done().set_bit().result_av().set_bit());

        unsafe {
            // Disable master control.
            self.aes.ctrl_alg_sel.write(|w| w.bits(0));
            // Clear mode
            self.aes.aes_ctrl.write(|w| w.bits(0));
        }
    }

    fn resume_hash(&mut self, state: &mut Sha256State) {
        // Workaround for AES registers not retained after PM2.
        self.aes.ctrl_int_cfg.write(|w| w.level().set_bit());
        self.aes
            .ctrl_int_en
            .write(|w| w.dma_in_done().set_bit().result_av().set_bit());

        // Configure master control module and enable the DMA path to the SHA2-256 engine.
        self.aes.ctrl_alg_sel.write(|w| w.hash().set_bit());

        // Clear any outstanding events.
        self.aes.ctrl_int_clr.write(|w| w.result_av().set_bit());

        // Configure hash engine.
        // Indicate the start of a resumed hash session and SHA-256.
        self.aes.hash_mode_in.write(|w| w.sha256_mode().set_bit());

        // If the final digest is required (pad the input DMA data).
        if state.final_digest {
            unsafe {
                self.aes
                    .hash_length_in_l
                    .write(|w| w.length_in().bits((state.length & 0xffff_ffff) as u32));
                self.aes
                    .hash_length_in_h
                    .write(|w| w.length_in().bits((state.length >> 32) as u32));
            }
        }

        // Write the initial digest.
        unsafe {
            self.aes
                .hash_digest_a
                .write(|w| w.hash_digest().bits(state.state[0]));
            self.aes
                .hash_digest_b
                .write(|w| w.hash_digest().bits(state.state[1]));
            self.aes
                .hash_digest_c
                .write(|w| w.hash_digest().bits(state.state[2]));
            self.aes
                .hash_digest_d
                .write(|w| w.hash_digest().bits(state.state[3]));
            self.aes
                .hash_digest_e
                .write(|w| w.hash_digest().bits(state.state[4]));
            self.aes
                .hash_digest_f
                .write(|w| w.hash_digest().bits(state.state[5]));
            self.aes
                .hash_digest_g
                .write(|w| w.hash_digest().bits(state.state[6]));
            self.aes
                .hash_digest_h
                .write(|w| w.hash_digest().bits(state.state[7]));
        }

        // If final digest, pad the DMA-ed data.
        if state.final_digest {
            self.aes
                .hash_io_buf_ctrl
                .write(|w| w.pad_dma_message().set_bit());
        }

        // Enable DMA channel 0.
        self.aes.dmac_ch0_ctrl.write(|w| w.en().set_bit());
        // Base address of the data in external memory.
        unsafe {
            self.aes
                .dmac_ch0_extaddr
                .write(|w| w.addr().bits(state.buf.as_ptr() as u32))
        };

        if state.final_digest {
            unsafe {
                self.aes
                    .dmac_ch0_dmalength
                    .write(|w| w.dmalen().bits(state.curlen as u16))
            };
        } else {
            unsafe {
                self.aes
                    .dmac_ch0_dmalength
                    .write(|w| w.dmalen().bits(BLOCK_SIZE as u16))
            };
        }

        // Wait for the completion of the operation.
        while !self.is_completed() {}

        // Read the digest
        state.state[0] = self.aes.hash_digest_a.read().bits();
        state.state[1] = self.aes.hash_digest_b.read().bits();
        state.state[2] = self.aes.hash_digest_c.read().bits();
        state.state[3] = self.aes.hash_digest_d.read().bits();
        state.state[4] = self.aes.hash_digest_e.read().bits();
        state.state[5] = self.aes.hash_digest_f.read().bits();
        state.state[6] = self.aes.hash_digest_g.read().bits();
        state.state[7] = self.aes.hash_digest_h.read().bits();

        // Ack reading of the digest.
        self.aes
            .hash_io_buf_ctrl
            .write(|w| w.output_full().set_bit());

        // Clear the interrupt.
        self.aes
            .ctrl_int_clr
            .write(|w| w.dma_in_done().set_bit().result_av().set_bit());

        unsafe {
            // Disable master control.
            self.aes.ctrl_alg_sel.write(|w| w.bits(0));
            // Clear mode
            self.aes.aes_ctrl.write(|w| w.bits(0));
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

    fn is_completed(&self) -> bool {
        self.aes.ctrl_int_stat.read().result_av().bit_is_set()
    }

    fn is_in_use(&self) -> bool {
        self.aes.ctrl_alg_sel.read().bits() != 0
    }
}
