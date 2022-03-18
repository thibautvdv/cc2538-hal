#[derive(Debug, Clone, Copy)]
pub struct AesKeys {
    pub keys: [u8; 128],   // 1024 bits of memory (8 128-bit keys)
    pub sizes: AesKeySize, // The type of keys stored
    pub count: u8,         // How many keys are stored
    pub start_area: u8,    // The start area in 128 bits
}

#[derive(Debug, Clone, Copy)]
pub enum AesKeySize {
    Key128 = 0b01,
    Key192 = 0b10,
    Key256 = 0b11,
}

#[derive(Debug, Clone, Copy)]
pub enum AesKey {
    Key128([u8; 16]),
    Key192([u8; 24]),
    Key256([u8; 32]),
}

impl AesKeys {
    // XXX Create a better key management system for AES
    /// Create a correctly aligned key buffer for the AES engine.
    pub fn create(keys: &[AesKey], sizes: AesKeySize, start_area: u8) -> Self {
        let mut aligned = AesKeys {
            keys: [0; 128],
            sizes,
            count: 0,
            start_area,
        };

        let mut offset = 0;
        for k in keys.iter() {
            match k {
                AesKey::Key128(k) => {
                    aligned.keys[offset..offset + k.len()].copy_from_slice(k);
                    offset += 128 / 8;
                    aligned.count += 1;
                }
                AesKey::Key192(k) => {
                    aligned.keys[offset..offset + k.len()].copy_from_slice(k);
                    offset += 128 / 8 * 2;
                    aligned.count += 2;
                }
                AesKey::Key256(k) => {
                    aligned.keys[offset..offset + k.len()].copy_from_slice(k);
                    offset += 128 / 8 * 2;
                    aligned.count += 2;
                }
            }
        }

        aligned
    }
}
