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

    pub fn encrypt(&mut self, msg: &[u8], ilen: u32) -> Vec<u8> {
        let zero_bits = ilen & 0x7;
        let mut rs = vec![];
        let keylength = (ilen + 31) / 32;
        let len = ilen >> 3;

        let keys = self.zuc.generate_keystream(keylength as usize);
        let keys = keys.as_slice();
        for i in 0..keylength as usize {
            let mut j = 0;
            while j < 4 && (i * 4 + j) < len as usize {
                rs[4 * i + j] = msg[4 * i + j] ^ (((&keys[i] >> (8 * (3 - j))) & 0xff) as u8);
                j += 1;
            }
            rs[i] ^= msg[i];
        }

        if zero_bits > 0 {
            rs[len as usize - 1] = rs[len as usize - 1] & (((0xff) << (8 - zero_bits)) as u8)
        }

        for k in len as usize..rs.len() {
            rs[k] =0;
        }
        rs
    }
}
