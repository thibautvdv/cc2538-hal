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

pub mod bignum;
use bignum::*;

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

#[derive(Debug)]
pub enum CryptoError {
    PkaBusy,
    AesBusy,
    ResultIsZero,
    PkaFailure,
    NoSolution,
}

pub struct Crypto<'p> {
    _aes: PhantomData<&'p mut AES>,
    _pka: PhantomData<&'p mut PKA>,
}

impl<'p> Crypto<'p> {
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
    pub fn is_aes_in_use() -> bool {
        Self::aes().ctrl_alg_sel.read().bits() != 0
    }

    /// Check if the PKA resource is in use.
    pub fn is_pka_in_use() -> bool {
        Self::pka().function.read().run().bit_is_set()
    }

    /// Check if the result of the AES operation is available.
    fn is_aes_completed() -> bool {
        Self::aes().ctrl_int_stat.read().result_av().bit_is_set()
    }

    ///// Check if the result of the PKA operation is available.
    //fn is_pka_completed(&self) -> bool {
    //Self::pka().ctrl_int_stat.read().result_av().bit_is_set()
    //}
}

impl<'p> Crypto<'p> {
    /// Create a new crypto instance.
    pub fn new(
        #[allow(unused_variables)] aes: &'p mut AES,
        #[allow(unused_variables)] pka: &'p mut PKA,
    ) -> Self {
        Self {
            _aes: PhantomData,
            _pka: PhantomData,
        }
    }
}

pub struct PkaRam {}

impl PkaRam {
    const PKA_RAM_PTR: usize = 0x4400_6000;
    const PKA_RAM_SIZE: usize = 0x800;

    /// Write a slice into the memory the PKA RAM and returns the next offset that is 8 byte
    /// aligned. We assume that the offset that is also aligned.
    fn write_slice(data: &[u32], offset: usize) -> usize {
        assert!(offset % 8 == 0);
        assert!(offset + data.len() * 4 < Self::PKA_RAM_SIZE);

        for (i, d) in data.iter().enumerate() {
            let addr = Self::PKA_RAM_PTR + offset + i * 4;
            unsafe {
                core::ptr::write_volatile(addr as *mut u32, *d);
            }
        }

        (((4 * data.len()) + 7)/8)*8
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
