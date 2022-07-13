use core::cmp::Ordering;

use rtt_target::rprintln;

use super::Crypto;
use super::CryptoError;
use super::PkaRam;

/// Represents a big number for the CC2538 crypto accelerator.
///
/// The maximum size of the big number is 64 (32-bit) words, however, the user can create it's own
/// big number type and change the maximum size of the big number.
#[derive(Debug, Eq, PartialEq)]
pub struct BigNum<const MAX_LEN: usize = 64> {
    buffer: [u32; MAX_LEN],
    size: usize,
}

impl<const MAX_LEN: usize> core::fmt::Display for BigNum<MAX_LEN> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:0x?}", self.inner())
    }
}

impl<const MAX_LEN: usize> BigNum<MAX_LEN> {
    /// Create a new big number, with `size` amount of words to use from the buffer.
    pub fn new(size: usize) -> Self {
        Self {
            buffer: [0u32; MAX_LEN],
            size,
        }
    }

    /// Set the amount of words to use from the buffer.
    pub fn set_size(&mut self, size: usize) {
        assert!(size <= MAX_LEN);
        self.size = size;
    }

    /// Return a slice to the buffer.
    pub fn inner(&self) -> &[u32] {
        &self.buffer[..self.size]
    }

    /// Return a mutable slice to the buffer.
    pub fn inner_mut(&mut self) -> &mut [u32] {
        &mut self.buffer[..self.size]
    }

    /// Addition of two big numbers.
    pub fn add<const L: usize>(&self, rhs: &BigNum<L>) -> Result<BigNum<MAX_LEN>, CryptoError> {
        let mut tmp = BigNum::new(self.size.max(rhs.size) + 1);
        let len = Crypto::add(self.inner(), rhs.inner(), tmp.inner_mut())?;
        tmp.set_size(len);
        Ok(tmp)
    }

    /// Subtraction of two big numbers.
    pub fn sub<const L: usize>(&self, rhs: &BigNum<L>) -> Result<BigNum<MAX_LEN>, CryptoError> {
        let mut tmp = BigNum::new(self.size.max(rhs.size));
        let len = Crypto::sub(self.inner(), rhs.inner(), tmp.inner_mut())?;
        tmp.set_size(len);
        Ok(tmp)
    }

    /// Addition and subtraction of three big numbers.
    /// A + C - B
    pub fn add_sub(&self, c: &BigNum<MAX_LEN>, b: &BigNum<MAX_LEN>) -> BigNum<MAX_LEN> {
        let mut tmp = BigNum::new(self.size);
        Crypto::add_sub(self.inner(), c.inner(), b.inner(), tmp.inner_mut());
        tmp
    }

    /// Multiplication of two big numbers.
    pub fn mul<const L: usize>(&self, rhs: &BigNum<L>) -> Result<BigNum<MAX_LEN>, CryptoError> {
        let mut tmp = BigNum::new(self.size + rhs.size + 6);
        let len = Crypto::mul(self.inner(), rhs.inner(), tmp.inner_mut())?;
        tmp.set_size(len);
        Ok(tmp)
    }

    /// Division of two big numbers.
    pub fn div<const L: usize>(&self, rhs: &BigNum<L>) -> BigNum<MAX_LEN> {
        let mut tmp = BigNum::new(self.size + rhs.size + 6);
        Crypto::div(self.inner(), rhs.inner(), tmp.inner_mut());
        tmp
    }

    /// Modulus of two big numbers.
    pub fn modulo<const L: usize>(&self, rhs: &BigNum<L>) -> Result<BigNum<MAX_LEN>, CryptoError> {
        let mut tmp = BigNum::new(rhs.size + 2);
        let len = Crypto::modulo(self.inner(), rhs.inner(), tmp.inner_mut())?;
        tmp.set_size(len);
        Ok(tmp)
    }

    /// Inverse modulus of two big numbers.
    pub fn inv_mod<const L: usize>(&self, rhs: &BigNum<L>) -> BigNum<MAX_LEN> {
        let mut tmp = BigNum::new(rhs.size + 1);
        Crypto::inv_modulo(self.inner(), rhs.inner(), tmp.inner_mut());
        tmp
    }

    /// Exponentiation with big numbers.
    ///
    /// C^A mod B -> D, where `self` is A.
    pub fn exp<const L: usize>(&self, modulus: &BigNum<L>, base: &BigNum<L>) -> BigNum<MAX_LEN> {
        // TODO: calculate the correct maximum length.
        let mut tmp = BigNum::new(MAX_LEN);
        Crypto::exp(self.inner(), modulus.inner(), base.inner(), tmp.inner_mut());
        tmp
    }

    /// Comparision of two big numbers.
    pub fn compare<const L: usize>(&self, rhs: &BigNum<L>) -> Option<Ordering> {
        Crypto::cmp(self.inner(), rhs.inner())
    }
}

impl<'p> Crypto<'p> {
    #[inline]
    fn set_a_ptr(&mut self, offset: u32) {
        Self::pka().aptr.write(|w| unsafe { w.bits(offset) });
    }

    #[inline]
    fn set_b_ptr(&mut self, offset: u32) {
        Self::pka().bptr.write(|w| unsafe { w.bits(offset) });
    }

    #[inline]
    fn set_c_ptr(&mut self, offset: u32) {
        Self::pka().cptr.write(|w| unsafe { w.bits(offset) });
    }

    #[inline]
    fn set_d_ptr(&mut self, offset: u32) {
        Self::pka().dptr.write(|w| unsafe { w.bits(offset) });
    }

    /// Addition of two bignums.
    ///
    /// The length of the `result` should be max(num1, num2) + 1.
    pub fn add(
        num1: impl AsRef<[u32]>,
        num2: impl AsRef<[u32]>,
        result: &mut (impl AsMut<[u32]> + ?Sized),
    ) -> Result<usize, CryptoError> {
        let num1 = num1.as_ref();
        let num2 = num2.as_ref();
        let result = result.as_mut();

        if Self::is_pka_in_use() {
            return Err(CryptoError::PkaBusy);
        }

        let pka = Self::pka();
        let mut offset: usize = 0;

        // Save the address of the A vector.
        pka.aptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        PkaRam::write_slice(num1, offset);
        offset += 4 * (num1.len() + num1.len() % 2);

        // Save the address of the B vector.
        pka.bptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        PkaRam::write_slice(num2, offset);
        offset += 4 * (num2.len() + num2.len() % 2 + 2);

        // Save the address of the C vector.
        pka.cptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        let result_start = offset >> 2;

        pka.alength.write(|w| unsafe { w.bits(num1.len() as u32) });
        pka.blength.write(|w| unsafe { w.bits(num2.len() as u32) });

        // Start the add operation.
        pka.function.write(|w| w.add().set_bit().run().set_bit());
        while Self::is_pka_in_use() {}

        let result_end = pka.msw.read().msw_address().bits() as usize;

        if pka.msw.read().result_is_zero().bit_is_set() {
            result.fill_with(|| 0);
            return Ok(0);
        }

        let len = result_end - result_start + 1;

        PkaRam::read_slice(&mut result[..len], result_start << 2);
        Ok(len)
    }

    /// Subtraction of two bignums.
    ///
    /// The length of `result` should be max(num1, num2).
    pub fn sub(
        num1: impl AsRef<[u32]>,
        num2: impl AsRef<[u32]>,
        result: &mut (impl AsMut<[u32]> + ?Sized),
    ) -> Result<usize, CryptoError> {
        let num1 = num1.as_ref();
        let num2 = num2.as_ref();
        let result = result.as_mut();

        if Self::is_pka_in_use() {
            return Err(CryptoError::PkaBusy);
        }

        let pka = Self::pka();
        let mut offset: usize = 0;

        // Save the address of the A vector.
        pka.aptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        PkaRam::write_slice(num1, offset);
        offset += 4 * (num1.len() + num1.len() % 2);

        // Save the address of the B vector.
        pka.bptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        PkaRam::write_slice(num2, offset);
        offset += 4 * (num2.len() + num2.len() % 2 + 2);

        // Save the address of the C vector.
        pka.cptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        let result_start = offset >> 2;

        pka.alength.write(|w| unsafe { w.bits(num1.len() as u32) });
        pka.blength.write(|w| unsafe { w.bits(num2.len() as u32) });

        // Start the subtract operation.
        pka.function
            .write(|w| w.subtract().set_bit().run().set_bit());
        while Self::is_pka_in_use() {}

        let result_end = pka.msw.read().msw_address().bits() as usize;

        if pka.msw.read().result_is_zero().bit_is_set() {
            result.fill_with(|| 0);
            return Ok(0);
        }

        let len = result_end - result_start + 1;

        PkaRam::read_slice(&mut result[..len], result_start << 2);
        Ok(len)
    }

    /// Addition and subtraction of three bignums.
    ///
    /// A + C - B -> D
    pub fn add_sub(a: &[u32], c: &[u32], b: &[u32], result: &mut [u32]) {
        todo!()
    }

    /// Multiplication of two bignums.
    ///
    /// The length of `result` should be num1 + num2 + 6, where the last 6 bytes should be
    /// discarded.
    pub fn mul(
        num1: impl AsRef<[u32]>,
        num2: impl AsRef<[u32]>,
        result: &mut (impl AsMut<[u32]> + ?Sized),
    ) -> Result<usize, CryptoError> {
        let num1 = num1.as_ref();
        let num2 = num2.as_ref();
        let result = result.as_mut();

        if Self::is_pka_in_use() {
            return Err(CryptoError::PkaBusy);
        }

        let pka = Self::pka();
        let mut offset: usize = 0;

        // Save the address of the A vector.
        pka.aptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        PkaRam::write_slice(num1, offset);
        offset += 4 * (num1.len() + num1.len() % 2);

        // Save the address of the B vector.
        pka.bptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        PkaRam::write_slice(num2, offset);
        offset += 4 * (num2.len() + num2.len() % 2 + 2);

        // Save the address of the C vector.
        pka.cptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        let result_start = offset >> 2;

        pka.alength.write(|w| unsafe { w.bits(num1.len() as u32) });
        pka.blength.write(|w| unsafe { w.bits(num2.len() as u32) });

        // Start the multiplaction operation.
        pka.function
            .write(|w| w.multiply().set_bit().run().set_bit());
        while Self::is_pka_in_use() {}

        let result_end = pka.msw.read().msw_address().bits() as usize;
        if pka.msw.read().result_is_zero().bit_is_set() {
            result.fill_with(|| 0);
            return Ok(0);
        }

        let len = result_end - result_start + 1;

        PkaRam::read_slice(&mut result[..len], result_start << 2);
        Ok(len)
    }

    /// Division of two bignums.
    pub fn div(num1: &[u32], num2: &[u32], result: &mut [u32]) {
        todo!();
    }

    /// Modulo of a bignums.
    pub fn modulo(
        num1: impl AsRef<[u32]>,
        num2: impl AsRef<[u32]>,
        result: &mut (impl AsMut<[u32]> + ?Sized),
    ) -> Result<usize, CryptoError> {
        let num1 = num1.as_ref();
        let num2 = num2.as_ref();
        let result = result.as_mut();

        if Self::is_pka_in_use() {
            return Err(CryptoError::PkaBusy);
        }

        let pka = Self::pka();
        let mut offset: usize = 0;

        // Save the address of the A vector.
        pka.aptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        PkaRam::write_slice(num1, offset);
        offset += 4 * (num1.len() + num1.len() % 2);

        // Save the address of the B vector.
        pka.bptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        PkaRam::write_slice(num2, offset);
        offset += 4 * (num2.len() + num2.len() % 2 + 2);

        // Save the address of the C vector.
        pka.cptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });

        pka.alength.write(|w| unsafe { w.bits(num1.len() as u32) });
        pka.blength.write(|w| unsafe { w.bits(num2.len() as u32) });

        // Start the modulo operation.
        pka.function.write(|w| w.modulo().set_bit().run().set_bit());
        while Self::is_pka_in_use() {}

        if pka.msw.read().result_is_zero().bit_is_set() {
            result.fill_with(|| 0);
            return Ok(num2.len() + 1);
        }

        PkaRam::read_slice(&mut result[..num2.len() + 1], offset);
        Ok(num2.len() + 1)
    }

    /// Inverse modulo of a bignums.
    pub fn inv_modulo(num1: &[u32], num2: &[u32], result: &mut [u32]) {
        if Self::is_pka_in_use() {
            return;
        }

        let pka = Self::pka();
        let mut offset: usize = 0;

        // Save the address of the A vector.
        pka.aptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        PkaRam::write_slice(num1, offset);
        offset += 4 * (num1.len() + num1.len() % 2);

        // Save the address of the B vector.
        pka.bptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        PkaRam::write_slice(num2, offset);
        offset += 4 * (num2.len() + num2.len() % 2 + 2);

        // Save the address of the C vector.
        pka.cptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });

        pka.alength.write(|w| unsafe { w.bits(num1.len() as u32) });
        pka.blength.write(|w| unsafe { w.bits(num2.len() as u32) });

        // Start the inverse module operation
        pka.function
            .write(|w| unsafe { w.sequencer_operations().bits(0b111).run().set_bit() });
        while Self::is_pka_in_use() {}

        let status = pka.shift.read().bits();
        match status {
            0 => PkaRam::read_slice(&mut result[..num1.len()], offset),
            7 => todo!(),
            31 => todo!(),
            _ => unreachable!(),
        }
    }

    /// Exponentiation of a bignums.
    /// c^a mod b -> d
    pub fn exp(
        exponent: impl AsRef<[u32]>,
        modulus: impl AsRef<[u32]>,
        base: impl AsRef<[u32]>,
        result: &mut (impl AsMut<[u32]> + ?Sized),
    ) {
        let exponent = exponent.as_ref();
        let modulus = modulus.as_ref();
        let base = base.as_ref();
        let result = result.as_mut();

        if Self::is_pka_in_use() {
            return;
        }

        let pka = Self::pka();

        let mut offset: usize = 0;

        // Save the address of the A vector.
        pka.aptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        PkaRam::write_slice(exponent, offset);
        offset += 4 * (exponent.len() + exponent.len() % 2);

        // Save the address of the B vector.
        pka.bptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        PkaRam::write_slice(modulus, offset);
        offset += 4 * (modulus.len() + modulus.len() % 2 + 2);

        // Save the address of the C vector.
        pka.cptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        PkaRam::write_slice(base, offset);

        // C and D can share the same address.
        // Save the address of the D vector.
        pka.dptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });

        pka.alength
            .write(|w| unsafe { w.bits(exponent.len() as u32) });
        pka.blength
            .write(|w| unsafe { w.bits(modulus.len() as u32) });

        // Start the exp operation.
        pka.function
            .write(|w| unsafe { w.sequencer_operations().bits(0b010).run().set_bit() });
        while Self::is_pka_in_use() {}

        let msw_val = pka.msw.read().msw_address().bits() as usize;
        if msw_val == 0 || pka.msw.read().result_is_zero().bit_is_set() {
            return;
        }

        let len1 = msw_val + 1;
        let len2 = pka.dptr.read().bits() as usize;
        let len = len1 - len2;

        PkaRam::read_slice(&mut result[..len], offset);
    }

    /// Comparison of two bignums.
    pub fn cmp(num1: impl AsRef<[u32]>, num2: impl AsRef<[u32]>) -> Option<Ordering> {
        let num1 = num1.as_ref();
        let num2 = num2.as_ref();

        if Self::is_pka_in_use() {
            return None;
        }

        let pka = Self::pka();
        let mut offset = 0;

        // Save the address of the A vector.
        pka.aptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        PkaRam::write_slice(num1, offset);
        offset += 4 * (num1.len() + num1.len() % 2);

        // Save the address of the C vector.
        pka.cptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        PkaRam::write_slice(num2, offset);

        pka.alength.write(|w| unsafe { w.bits(num1.len() as u32) });

        // Start the comparison operation.
        pka.function
            .write(|w| w.compare().set_bit().run().set_bit());
        while Self::is_pka_in_use() {}

        let compare = Crypto::pka().compare.read();
        if compare.a_equals_b().bit_is_set() {
            Some(Ordering::Equal)
        } else if compare.a_less_than_b().bit_is_set() {
            Some(Ordering::Less)
        } else if compare.a_greater_than_b().bit_is_set() {
            Some(Ordering::Greater)
        } else {
            None
        }
    }
}
