use super::Crypto;
use super::CryptoError;
use super::PkaRam;

pub struct EccEngine {}

pub struct EccCurveInfo<'e> {
    pub name: &'e str,
    pub size: usize,
    pub prime: &'e [u32],
    pub order: &'e [u32],
    pub a_coef: &'e [u32],
    pub b_coef: &'e [u32],
    pub bp_x: &'e [u32],
    pub bp_y: &'e [u32],
}

impl<'e> EccCurveInfo<'e> {
    /// Create the curve information for the NIST P-256 curve.
    pub const fn nist_p_256() -> EccCurveInfo<'e> {
        EccCurveInfo {
            name: "NIST P-256",
            size: 8,
            prime: &[
                0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001,
                0xFFFFFFFF,
            ],
            order: &[
                0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
                0xFFFFFFFF,
            ],
            a_coef: &[
                0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001,
                0xFFFFFFFF,
            ],
            b_coef: &[
                0x27D2604B, 0x3BCE3C3E, 0xCC53B0F6, 0x651D06B0, 0x769886BC, 0xB3EBBD55, 0xAA3A93E7,
                0x5AC635D8,
            ],
            bp_x: &[
                0xD898C296, 0xF4A13945, 0x2DEB33A0, 0x77037D81, 0x63A440F2, 0xF8BCE6E5, 0xE12C4247,
                0x6B17D1F2,
            ],
            bp_y: &[
                0x37BF51F5, 0xCBB64068, 0x6B315ECE, 0x2BCE3357, 0x7C0F9E16, 0x8EE7EB4A, 0xFE1A7F9B,
                0x4FE342E2,
            ],
        }
    }

    /// Create the curve information for the NIST P-192 curve.
    pub const fn nist_p_192() -> EccCurveInfo<'e> {
        EccCurveInfo {
            name: "NIST P-192",
            size: 6,
            prime: &[
                0xffffffff, 0xffffffff, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff,
            ],
            order: &[
                0xfffffffc, 0xffffffff, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff,
            ],
            a_coef: &[
                0xc146b9b1, 0xfeb8deec, 0x72243049, 0x0fa7e9ab, 0xe59c80e7, 0x64210519,
            ],
            b_coef: &[
                0x82ff1012, 0xf4ff0afd, 0x43a18800, 0x7cbf20eb, 0xb03090f6, 0x188da80e,
            ],
            bp_x: &[
                0x1e794811, 0x73f977a1, 0x6b24cdd5, 0x631011ed, 0xffc8da78, 0x07192b95,
            ],
            bp_y: &[
                0xb4d22831, 0x146bc9b1, 0x99def836, 0xffffffff, 0xffffffff, 0xffffffff,
            ],
        }
    }
}

pub struct EcPoint<'p> {
    pub x: &'p [u32],
    pub y: &'p [u32],
}

impl<'p> Crypto<'p> {
    pub fn ecc_mul(
        &mut self,
        curve: &EccCurveInfo,
        scalar: &[u32],
        point: &EcPoint,
        result: &mut [u32],
    ) -> Result<(), CryptoError> {
        if self.is_pka_in_use() {
            return Err(CryptoError::PkaBusy);
        }

        let pka = Self::pka();

        let extra_buf: u8 = (2 + curve.size as u8 % 2) * 4;
        let mut offset: usize = 0;

        // Save the address of the A vector.
        pka.aptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        // Write the scalar to it.
        offset += PkaRam::write_slice(scalar, offset) + curve.size % 2;

        // Save the address of the B vector.
        pka.bptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        // First write the primes, followed by the a and b coef.
        offset += PkaRam::write_slice(curve.prime, offset) + extra_buf as usize;
        offset += PkaRam::write_slice(curve.a_coef, offset) + extra_buf as usize;
        offset += PkaRam::write_slice(curve.b_coef, offset) + extra_buf as usize;

        // Save the address of the C vector.
        pka.cptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        // First write the x coordinate, followed by the y coordinate.
        offset += PkaRam::write_slice(&point.x[..curve.size], offset) + extra_buf as usize;
        offset += PkaRam::write_slice(&point.y[..curve.size], offset) + extra_buf as usize;

        // Save the address of the D vector.
        pka.dptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });

        // Set the size of the A vector.
        pka.alength.write(|w| unsafe { w.bits(curve.size as u32) });
        // Set the size of the B vector.
        pka.blength.write(|w| unsafe { w.bits(curve.size as u32) });

        // Start the multiplication operation.
        //pka.function.write(|w| unsafe { w.bits(0x0000d000) });
        pka.function
            .write(|w| unsafe { w.sequencer_operations().bits(0b101).run().set_bit() });
        while self.is_pka_in_use() {}

        if pka.shift.read().bits() != 0x0 && pka.shift.read().bits() != 0x7 {
            return Err(CryptoError::PkaFailure);
        }

        let msw_val = pka.msw.read().msw_address().bits() as usize;
        if msw_val == 0 || pka.msw.read().result_is_zero().bit_is_set() {
            return Err(CryptoError::PkaFailure);
        }

        let len1 = msw_val + 1;
        let len2 = pka.dptr.read().bits() as usize;
        let len = len1 - len2;

        PkaRam::read_slice(&mut result[..len], offset);
        offset += 4 * (len + 2 + (len % 2));
        PkaRam::read_slice(&mut result[len..][..len], offset);

        Ok(())
    }

    pub fn ecc_add(
        &mut self,
        curve: &EccCurveInfo,
        point_a: &EcPoint,
        point_b: &EcPoint,
        result: &mut [u32],
    ) -> Result<(), CryptoError> {
        if self.is_pka_in_use() {
            return Err(CryptoError::PkaBusy);
        }

        let pka = Self::pka();

        let extra_buf: u8 = 2 + (curve.size as u8 % 2);
        let mut offset: usize = 0;

        // Save the address of the A vector.
        pka.aptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        // Write the scalar to it.
        offset += PkaRam::write_slice(&point_a.x[..curve.size], offset) + 4 * extra_buf as usize;
        offset += PkaRam::write_slice(&point_a.y[..curve.size], offset) + 4 * extra_buf as usize;

        // Save the address of the B vector.
        pka.bptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        // First write the primes, followed by the a and b coef.
        offset += PkaRam::write_slice(curve.prime, offset) + 4 * extra_buf as usize;
        offset += PkaRam::write_slice(curve.a_coef, offset) + 4 * extra_buf as usize;

        // Save the address of the C vector.
        pka.cptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });
        // First write the x coordinate, followed by the y coordinate.
        offset += PkaRam::write_slice(&point_b.x[..curve.size], offset) + 4 * extra_buf as usize;
        offset += PkaRam::write_slice(&point_b.y[..curve.size], offset) + 4 * extra_buf as usize;

        // Save the address of the D vector.
        pka.dptr.write(|w| unsafe { w.bits(offset as u32 >> 2) });

        // Set the size of the A vector.
        //pka.alength.write(|w| unsafe { w.bits(curve.size as u32) });
        // Set the size of the B vector.
        pka.blength.write(|w| unsafe { w.bits(curve.size as u32) });

        // Start the multiplication operation.
        //pka.function.write(|w| unsafe { w.bits(0x0000b000) });
        pka.function
            .write(|w| unsafe { w.sequencer_operations().bits(0b011).run().set_bit() });
        while self.is_pka_in_use() {}

        if pka.shift.read().bits() != 0x0 && pka.shift.read().bits() != 0x7 {
            return Err(CryptoError::PkaFailure);
        }

        let msw_val = pka.msw.read().msw_address().bits() as usize;
        if msw_val == 0 || pka.msw.read().result_is_zero().bit_is_set() {
            return Err(CryptoError::PkaFailure);
        }

        let len1 = msw_val + 1;
        let len2 = pka.dptr.read().bits() as usize;
        let len = len1 - len2;

        PkaRam::read_slice(&mut result[..len], offset);
        offset += 4 * (len + 2 + (len % 2));
        PkaRam::read_slice(&mut result[len..][..len], offset);

        Ok(())
    }
}
