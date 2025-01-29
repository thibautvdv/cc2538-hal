use cc2538_pac::aes;

use super::super::CtrWidth;
use super::AesEngine;
use super::Crypto;

pub struct AesCcm {}

#[derive(Debug, Clone, Copy)]
pub struct AesCcmInfo<'a> {
    key_index: u32,
    len_field_size: u8,
    auth_field_size: u8,
    adata: Option<&'a [u8]>,
}

impl<'a> AesCcmInfo<'a> {
    pub fn new(key_index: u32, len_field_size: u8, auth_field_size: u8) -> Self {
        Self {
            key_index,
            len_field_size,
            auth_field_size,
            adata: None,
        }
    }

    pub fn with_added_auth_data(self, adata: &'a [u8]) -> Self {
        Self {
            adata: Some(adata),
            ..self
        }
    }
}

impl Crypto<'_> {
    const CCM_NONCE_LEN: usize = 15;

    fn ccm_crypt(
        &mut self,
        ctrl: impl FnOnce(&aes::RegisterBlock),
        ccm_info: &AesCcmInfo,
        nonce: &[u8],
        data_in: &[u8],
        data_out: &mut [u8],
    ) {
        if Self::is_aes_in_use() {
            return;
        }

        // Prepare the IV
        // The first part is the length of the data minus 1.
        // The following part is the nonce.
        // And the rest is the counter.
        let mut iv = [0u8; 16];
        iv[0] = ccm_info.len_field_size - 1;
        iv[1..][..Self::CCM_NONCE_LEN - ccm_info.len_field_size as usize].copy_from_slice(nonce);
        iv[16 - ccm_info.len_field_size as usize..].fill_with(|| 0);

        self.auth_crypt(
            ctrl,
            ccm_info.key_index,
            Some(&iv),
            ccm_info.adata,
            data_in,
            data_out,
        );
    }

    pub fn ccm_encrypt(
        &mut self,
        ccm_info: &AesCcmInfo,
        nonce: &[u8],
        data_in: &[u8],
        data_out: &mut [u8],
        tag: &mut [u8],
    ) {
        let m = (ccm_info.auth_field_size.max(2) - 2) >> 1;
        let l = ccm_info.len_field_size - 1;

        let ctrl = |aes: &aes::RegisterBlock| unsafe {
            aes.aes_ctrl().modify(|_, w| {
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

        self.ccm_crypt(ctrl, ccm_info, nonce, data_in, data_out);
        self.read_tag(tag);
    }

    pub fn ccm_decrypt(
        &mut self,
        ccm_info: &AesCcmInfo,
        nonce: &[u8],
        data_in: &[u8],
        data_out: &mut [u8],
    ) {
        let m = (ccm_info.auth_field_size.max(2) - 2) >> 1;
        let l = ccm_info.len_field_size - 1;

        let ctrl = |aes: &aes::RegisterBlock| unsafe {
            aes.aes_ctrl().modify(|_, w| {
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

        self.ccm_crypt(ctrl, ccm_info, nonce, data_in, data_out);
    }
}
