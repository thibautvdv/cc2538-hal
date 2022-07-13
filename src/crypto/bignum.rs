use rtt_target::rprintln;

use super::Crypto;
use super::PkaRam;

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
    pub fn add(&mut self, num1: &[u32], num2: &[u32], result: &mut [u32]) {
        if self.is_pka_in_use() {
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
        //PkaRam::write_slice(base, offset);

        //pka.dptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });

        pka.alength.write(|w| unsafe { w.bits(num1.len() as u32) });
        pka.blength.write(|w| unsafe { w.bits(num2.len() as u32) });

        // Start the exp operation.
        pka.function.write(|w| w.add().set_bit().run().set_bit());
        while self.is_pka_in_use() {}

        let msw_val = pka.msw.read().msw_address().bits() as usize;
        if msw_val == 0 || pka.msw.read().result_is_zero().bit_is_set() {
            return;
        }

        let len1 = msw_val + 1;
        let len2 = pka.cptr.read().bits() as usize;
        let len = len1 - len2;

        PkaRam::read_slice(&mut result[..len], offset);
    }

    /// Subtraction of two bignums.
    ///
    /// The length of `result` should be max(num1, num2).
    pub fn sub(&mut self, num1: &[u32], num2: &[u32], result: &mut [u32]) {
        assert!(
            result.len()
                >= if num1.len() > num2.len() {
                    num1.len()
                } else {
                    num2.len()
                }
        );

        if self.is_pka_in_use() {
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
        //PkaRam::write_slice(base, offset);

        //pka.dptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });

        pka.alength.write(|w| unsafe { w.bits(num1.len() as u32) });
        pka.blength.write(|w| unsafe { w.bits(num2.len() as u32) });

        // Start the exp operation.
        pka.function
            .write(|w| w.subtract().set_bit().run().set_bit());
        while self.is_pka_in_use() {}

        let msw_val = pka.msw.read().msw_address().bits() as usize;
        if msw_val == 0 || pka.msw.read().result_is_zero().bit_is_set() {
            return;
        }

        let len1 = msw_val + 1;
        let len2 = pka.cptr.read().bits() as usize;
        let len = len1 - len2;

        PkaRam::read_slice(&mut result[..len], offset);
    }

    /// Multiplication of two bignums.
    ///
    /// The length of `result` should be num1 + num2 + 6, where the last 6 bytes should be
    /// discarded.
    pub fn mul(&mut self, num1: &[u32], num2: &[u32], result: &mut [u32]) {
        assert!(result.len() >= num1.len() + num2.len() + 6);

        if self.is_pka_in_use() {
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
        //PkaRam::write_slice(base, offset);

        //pka.dptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });

        pka.alength.write(|w| unsafe { w.bits(num1.len() as u32) });
        pka.blength.write(|w| unsafe { w.bits(num2.len() as u32) });

        // Start the exp operation.
        pka.function
            .write(|w| w.multiply().set_bit().run().set_bit());
        while self.is_pka_in_use() {}

        let msw_val = pka.msw.read().msw_address().bits() as usize;
        if msw_val == 0 || pka.msw.read().result_is_zero().bit_is_set() {
            return;
        }

        let len1 = msw_val + 1;
        let len2 = pka.cptr.read().bits() as usize;
        let len = len1 - len2;

        PkaRam::read_slice(&mut result[..len], offset);
    }

    /// Division of two bignums.
    pub fn div(&mut self, num1: &[u32], num2: &[u32], result: &mut [u32]) {
        todo!();
    }

    /// Comparison of two bignums.
    pub fn cmp(&mut self, num1: &[u32], num2: &[u32], result: &mut [u32]) {
        todo!();
    }

    /// Modulo of a bignums.
    pub fn modulo(&mut self, num1: &[u32], num2: &[u32], result: &mut [u32]) {
        assert!(result.len() + 1 >= num2.len());
        if self.is_pka_in_use() {
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
        //PkaRam::write_slice(base, offset);

        //pka.dptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });

        pka.alength.write(|w| unsafe { w.bits(num1.len() as u32) });
        pka.blength.write(|w| unsafe { w.bits(num2.len() as u32) });

        // Start the exp operation.
        pka.function.write(|w| w.modulo().set_bit().run().set_bit());
        while self.is_pka_in_use() {}

        let msw_val = pka.msw.read().msw_address().bits() as usize;
        if msw_val == 0 || pka.msw.read().result_is_zero().bit_is_set() {
            return;
        }

        let len1 = msw_val + 1;
        let len2 = pka.cptr.read().bits() as usize;
        let len = len1 - len2;

        PkaRam::read_slice(&mut result[..len], offset);
    }

    /// Todo
    /// Inverse modulo of a bignums.
    pub fn inv_modulo(&mut self, num1: &[u32], num2: &[u32], result: &mut [u32]) {
        if self.is_pka_in_use() {
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
        //PkaRam::write_slice(base, offset);

        //pka.dptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });

        pka.alength.write(|w| unsafe { w.bits(num1.len() as u32) });
        pka.blength.write(|w| unsafe { w.bits(num2.len() as u32) });

        // Start the exp operation.
        pka.function
            .write(|w| w.multiply().set_bit().run().set_bit());
        while self.is_pka_in_use() {}

        let msw_val = pka.msw.read().msw_address().bits() as usize;
        if msw_val == 0 || pka.msw.read().result_is_zero().bit_is_set() {
            return;
        }

        let len1 = msw_val + 1;
        let len2 = pka.cptr.read().bits() as usize;
        let len = len1 - len2;

        PkaRam::read_slice(&mut result[..len], offset);
    }

    /// Exponentiation of a bignums.
    /// c^a mod b -> d
    pub fn exp(&mut self, exponent: &[u32], modulus: &[u32], base: &[u32], result: &mut [u32]) {
        if self.is_pka_in_use() {
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
        while self.is_pka_in_use() {}

        let msw_val = pka.msw.read().msw_address().bits() as usize;
        if msw_val == 0 || pka.msw.read().result_is_zero().bit_is_set() {
            return;
        }

        let len1 = msw_val + 1;
        let len2 = pka.dptr.read().bits() as usize;
        let len = len1 - len2;

        PkaRam::read_slice(&mut result[..len], offset);
    }
}
