use core::convert::TryInto;
use core::default;
use core::marker::PhantomData;

use cc2538_pac::{aes, pka, AES, PKA};
use rtt_target::rprintln;

pub mod aes_engine;
use aes_engine::*;

pub mod ecc;
use ecc::*;

pub mod sha2;
use sha2::*;

pub struct NotSpecified {}

/// Modes of the crypto engine.
#[derive(Debug)]
pub enum CryptoMode {
    StoreKeys,
    HashAndTag,
    Tag,
    Hash,
    Aes,
}

#[derive(Debug, Default)]
pub enum CtrWidth {
    #[default]
    Width128,
    Width256,
}

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
        todo!();
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
    pub fn aes_engine(self) -> Crypto<'p, aes_engine::AesEngine<NotSpecified>> {
        Crypto {
            _aes: PhantomData,
            _pka: PhantomData,
            _state: PhantomData,
        }
    }

    /// Use the crypto engine for elliptic curve operations.
    pub fn ecc_engine(self) -> Crypto<'p, ecc::EccEngine> {
        Crypto {
            _aes: PhantomData,
            _pka: PhantomData,
            _state: PhantomData,
        }
    }

    /// Use the crypto engine for SHA256 operations.
    pub fn sha256_engine(self) -> Crypto<'p, sha2::Sha256Engine> {
        Crypto {
            _aes: PhantomData,
            _pka: PhantomData,
            _state: PhantomData,
        }
    }
}
