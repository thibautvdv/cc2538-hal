
use cc2538_pac::aes;

use super::Crypto;
use super::AesEngine;
use super::super::CtrWidth;

pub struct AesCcm {}

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

    pub fn ccm_decrypt(
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
                    .clear_bit()
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
}
