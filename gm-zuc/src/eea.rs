use crate::ZUC;

#[derive(Debug)]
pub struct EEA {
    zuc: ZUC,
}

impl EEA {
    pub fn new(ck: &[u8], count: u32, bearer: u32, direction: u32) -> EEA {
        let mut iv = [0u8; 16];

        iv[0] = (count >> 24) as u8;
        iv[1] = (count >> 16) as u8;
        iv[2] = (count >> 8) as u8;
        iv[3] = count as u8;
        iv[4] = (((bearer << 1) | (direction & 1)) << 2) as u8;

        iv[8] = iv[0];
        iv[9] = iv[1];
        iv[10] = iv[2];
        iv[11] = iv[3];
        iv[12] = iv[4];
        let zuc = ZUC::new(ck, &iv);
        EEA { zuc }
    }

    pub fn encrypt(&mut self, msg: &[u32], ilen: u32) -> Vec<u32> {
        let mut rs = vec![];
        let keylength = (ilen + 31) / 32;
        let keys = self.zuc.generate_keystream(keylength as usize);
        let keys = keys.as_slice();
        for i in 0..keylength as usize {
            rs.push(msg[i] ^ keys[i]);
        }

        if ilen % 32 != 0 {
            rs[keylength as usize - 1] &= 0xffffffff << (32 - (ilen % 32));
        }

        rs
    }
}

#[cfg(test)]
mod eea_test {
    use crate::eea::EEA;

    #[test]
    fn test_eea() {
        let ck: [u8; 16] = [
            0x17, 0x3d, 0x14, 0xba, 0x50, 0x03, 0x73, 0x1d, 0x7a, 0x60, 0x04, 0x94, 0x70, 0xf0,
            0x0a, 0x29,
        ];

        let count = 0x66035492_u32;
        let bearer = 0xf_u32;
        let direction = 0_u32;
        let length = 0xc1_u32;

        let ibs: [u32; 7] = [
            0x6cf65340, 0x735552ab, 0x0c9752fa, 0x6f9025fe, 0x0bd675d9, 0x005875b2, 0x00000000,
        ];

        let obs: [u32; 7] = [
            0xa6c85fc6, 0x6afb8533, 0xaafc2518, 0xdfe78494, 0x0ee1e4b0, 0x30238cc8, 0x00000000,
        ];

        // encrypt
        let mut eea = EEA::new(&ck, count, bearer, direction);
        let rs = eea.encrypt(&ibs, length);
        assert_eq!(obs, rs.as_slice());

        // decrypt
        let mut eea = EEA::new(&ck, count, bearer, direction);
        let rs = eea.encrypt(&rs, length);
        assert_eq!(ibs, rs.as_slice());
    }
}
