use crate::ZUC;

#[derive(Debug)]
pub struct EIA {
    zuc: ZUC,
}

impl EIA {
    pub fn new(ik: &[u8], count: u32, bearer: u32, direction: u32) -> EIA {
        let mut iv = [0u8; 16];
        iv[0] = (count >> 24) as u8;
        iv[1] = (count >> 16) as u8;
        iv[2] = (count >> 8) as u8;
        iv[3] = count as u8;
        iv[4] = (bearer << 3) as u8;

        iv[8] = iv[0] ^ ((direction << 7) as u8);
        iv[9] = iv[1];
        iv[10] = iv[2];
        iv[11] = iv[3];
        iv[12] = iv[4];
        iv[14] = iv[6] ^ ((direction << 7) as u8);
        EIA {
            zuc: ZUC::new(ik, &iv),
        }
    }

    /// Return MAC
    pub fn gen_mac(&mut self, m: &[u32], ilen: u32) -> u32 {
        let keylength = (ilen + 31) / 32 + 2;
        let keys = self.zuc.generate_keystream(keylength as usize);
        let keys = keys.as_slice();
        let mut t = 0_u32;
        for i in 0..ilen as usize {
            if m[i >> 5] & (0x1 << (31 - (i & 0x1f))) > 0 {
                t ^= find_word(keys, i);
            }
        }

        t ^= find_word(keys, ilen as usize);
        t ^ find_word(keys, 32 * (keylength - 1) as usize)
    }
}

/// Return
/// ```txt
/// K_i = K[i] || K[i+1] || ... || K[i+31]
/// ```
fn find_word(keys: &[u32], i: usize) -> u32 {
    let j = i >> 5;
    let m = i & 0x1f;
    if m == 0 {
        keys[j]
    } else {
        (keys[j] << m) | (keys[j + 1] >> (32 - m))
    }
}

#[cfg(test)]
mod eia_test {
    use crate::eia::EIA;

    #[test]
    pub fn test_eia() {
        let ik: [u8; 16] = [
            0xc9, 0xe6, 0xce, 0xc4, 0x60, 0x7c, 0x72, 0xdb, 0x00, 0x0a, 0xef, 0xa8, 0x83, 0x85,
            0xab, 0x0a,
        ];

        let count = 0xa94059da_u32;
        let bearer = 0x0a_u32;
        let direction = 0x01_u32;
        let length = 0x0241_u32;

        let m: [u32; 19] = [
            0x983b41d4, 0x7d780c9e, 0x1ad11d7e, 0xb70391b1, 0xde0b35da, 0x2dc62f83, 0xe7b78d63,
            0x06ca0ea0, 0x7e941b7b, 0xe91348f9, 0xfcb170e2, 0x217fecd9, 0x7f9f68ad, 0xb16e5d7d,
            0x21e569d2, 0x80ed775c, 0xebde3f40, 0x93c53881, 0x00000000,
        ];

        let mac = 0xfae8ff0b_u32;

        let mut eia = EIA::new(&ik, count, bearer, direction);
        let rs = eia.gen_mac(&m, length);
        assert_eq!(mac, rs)
    }
}
