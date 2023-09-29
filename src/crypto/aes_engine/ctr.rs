use cc2538_pac::aes;

//use super::super::CtrWidth;
use super::AesEngine;
use super::Crypto;

pub struct AesCtr {}

impl<'p> Crypto<'p> {
    pub fn ctr_encrypt(
        &mut self,
        key_index: u32,
        nonce: &[u8],
        ctr: &[u8],
        mdata_in: &[u8],
        mdata_out: &mut [u8],
    ) {
        if Self::is_aes_in_use() {
            return;
        }

        let ctrl = |aes: &aes::RegisterBlock| unsafe {
            aes.aes_ctrl.write(|w| {
                w.ctr_width()
                    .bits((ctr.len() >> 2) as u8 - 1)
                    .ctr()
                    .set_bit()
                    .direction()
                    .set_bit()
            });
        };

        let mut iv = [0u8; 16];
        let nonce_len = nonce.len();
        iv[..nonce_len].copy_from_slice(nonce);
        iv[nonce_len..].copy_from_slice(ctr);

        self.auth_crypt(ctrl, key_index, Some(&iv), None, mdata_in, mdata_out)
    }

    pub fn ctr_decrypt(
        &mut self,
        key_index: u32,
        nonce: &[u8],
        ctr: &[u8],
        mdata_in: &[u8],
        mdata_out: &mut [u8],
    ) {
        if Self::is_aes_in_use() {
            return;
        }

        let ctrl = |aes: &aes::RegisterBlock| unsafe {
            aes.aes_ctrl.write(|w| {
                w.ctr_width()
                    .bits((ctr.len() >> 2) as u8 - 1)
                    .ctr()
                    .set_bit()
                    .direction()
                    .clear_bit()
            });
        };

        let mut iv = [0u8; 16];
        let nonce_len = nonce.len();
        iv[..nonce_len].copy_from_slice(nonce);
        iv[nonce_len..].copy_from_slice(ctr);

        self.auth_crypt(ctrl, key_index, Some(&iv), None, mdata_in, mdata_out)
    }
}
