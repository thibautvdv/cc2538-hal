use super::Crypto;
use super::PkaRam;

impl<'p> Crypto<'p> {
    pub fn exp(&mut self, num: &[u32], modulus: &[u32], base: &[u32], result: &mut [u32]) {
        if self.is_pka_in_use() {
            return;
        }

        let pka = Self::pka();

        let mut offset: usize = 0;

        // Save the address of the A vector.
        pka.aptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        PkaRam::write_slice(num, offset);
        offset += 4 * (num.len() + num.len() % 2);

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
        
        pka.alength.write(|w| unsafe { w.bits(num.len() as u32) });
        pka.blength.write(|w| unsafe { w.bits(modulus.len() as u32) });

        // Start the exp operation.
        pka.function
            .write(|w| unsafe { w.sequencer_operations().bits(0b110).run().set_bit() });
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
