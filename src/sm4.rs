use std::error;
use std::fmt::{Display, Formatter};

static SBOX: [u8; 256] = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
];

static FK: [u32; 4] = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];

static CK: [u32; 32] = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
];

pub type Sm4Result<T> = Result<T, Sm4Error>;

pub enum Sm4Error {
    ErrorBlockSize,
    ErrorDataLen,
    InvalidLastU8,
}

impl ::std::fmt::Debug for Sm4Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl From<Sm4Error> for &str {
    fn from(e: Sm4Error) -> Self {
        match e {
            Sm4Error::ErrorBlockSize => "the block size of SM4 must be 16",
            Sm4Error::ErrorDataLen => "the data len of SM4 must be 16",
            Sm4Error::InvalidLastU8 => {
                "the last u8 of cbc_decrypt out in SM4 must be positive which isn't greater than 16"
            }
        }
    }
}

impl error::Error for Sm4Error {}

impl Display for Sm4Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Sm4Error::ErrorBlockSize => "the block size of SM4 must be 16",
                Sm4Error::ErrorDataLen => "the data len of SM4 must be 16",
                Sm4Error::InvalidLastU8 => {
                    "the last u8 of cbc_decrypt out in SM4 must be positive which isn't greater than 16"
                }
            }
        )
    }
}


#[inline]
fn tau(a: u32) -> u32 {
    let mut buf = a.to_be_bytes();
    buf[0] = SBOX[buf[0] as usize];
    buf[1] = SBOX[buf[1] as usize];
    buf[2] = SBOX[buf[2] as usize];
    buf[3] = SBOX[buf[3] as usize];
    u32::from_be_bytes(buf)
}

/// L: linear transformation
#[inline]
fn el(b: u32) -> u32 {
    b ^ b.rotate_left(2) ^ b.rotate_left(10) ^ b.rotate_left(18) ^ b.rotate_left(24)
}

#[inline]
fn el_prime(b: u32) -> u32 {
    b ^ b.rotate_left(13) ^ b.rotate_left(23)
}

#[inline]
fn t(val: u32) -> u32 {
    el(tau(val))
}

#[inline]
fn t_prime(val: u32) -> u32 {
    el_prime(tau(val))
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Sm4Cipher {
    rk: [u32; 32],
}

impl Sm4Cipher {
    pub fn new(k: &[u8]) -> Sm4Result<Sm4Cipher> {
        let mut rk = [0u32; 32];
        let mk = [
            u32::from_be_bytes(k[0..4].try_into().unwrap()),
            u32::from_be_bytes(k[4..8].try_into().unwrap()),
            u32::from_be_bytes(k[8..12].try_into().unwrap()),
            u32::from_be_bytes(k[12..16].try_into().unwrap()),
        ];
        let mut k = [mk[0] ^ FK[0], mk[1] ^ FK[1], mk[2] ^ FK[2], mk[3] ^ FK[3]];

        for i in 0..8 {
            k[0] ^= t_prime(k[1] ^ k[2] ^ k[3] ^ CK[i * 4]);
            k[1] ^= t_prime(k[2] ^ k[3] ^ k[0] ^ CK[i * 4 + 1]);
            k[2] ^= t_prime(k[3] ^ k[0] ^ k[1] ^ CK[i * 4 + 2]);
            k[3] ^= t_prime(k[0] ^ k[1] ^ k[2] ^ CK[i * 4 + 3]);

            rk[i * 4] = k[0];
            rk[i * 4 + 1] = k[1];
            rk[i * 4 + 2] = k[2];
            rk[i * 4 + 3] = k[3];
        }
        Ok(Sm4Cipher { rk })
    }

    pub fn encrypt(&self, block: &[u8]) -> Sm4Result<Vec<u8>> {
        let mut x = [
            u32::from_be_bytes(block[0..4].try_into().unwrap()),
            u32::from_be_bytes(block[4..8].try_into().unwrap()),
            u32::from_be_bytes(block[8..12].try_into().unwrap()),
            u32::from_be_bytes(block[12..16].try_into().unwrap()),
        ];

        let rk = &self.rk;
        for i in 0..8 {
            x[0] ^= t(x[1] ^ x[2] ^ x[3] ^ rk[i * 4]);
            x[1] ^= t(x[2] ^ x[3] ^ x[0] ^ rk[i * 4 + 1]);
            x[2] ^= t(x[3] ^ x[0] ^ x[1] ^ rk[i * 4 + 2]);
            x[3] ^= t(x[0] ^ x[1] ^ x[2] ^ rk[i * 4 + 3]);
        }

        let mut out: [u8; 16] = [0; 16];
        out[0..4].copy_from_slice(&x[3].to_be_bytes());
        out[4..8].copy_from_slice(&x[2].to_be_bytes());
        out[8..12].copy_from_slice(&x[1].to_be_bytes());
        out[12..16].copy_from_slice(&x[0].to_be_bytes());

        Ok(out.to_vec())
    }

    pub fn decrypt(&self, block: &[u8]) -> Sm4Result<Vec<u8>> {
        let mut x = [
            u32::from_be_bytes(block[0..4].try_into().unwrap()),
            u32::from_be_bytes(block[4..8].try_into().unwrap()),
            u32::from_be_bytes(block[8..12].try_into().unwrap()),
            u32::from_be_bytes(block[12..16].try_into().unwrap()),
        ];
        let rk = &self.rk;
        for i in 0..8 {
            x[0] ^= t(x[1] ^ x[2] ^ x[3] ^ rk[31 - i * 4]);
            x[1] ^= t(x[2] ^ x[3] ^ x[0] ^ rk[31 - (i * 4 + 1)]);
            x[2] ^= t(x[3] ^ x[0] ^ x[1] ^ rk[31 - (i * 4 + 2)]);
            x[3] ^= t(x[0] ^ x[1] ^ x[2] ^ rk[31 - (i * 4 + 3)]);
        }
        let mut out: [u8; 16] = [0; 16];
        out[0..4].copy_from_slice(&x[3].to_be_bytes());
        out[4..8].copy_from_slice(&x[2].to_be_bytes());
        out[8..12].copy_from_slice(&x[1].to_be_bytes());
        out[12..16].copy_from_slice(&x[0].to_be_bytes());
        Ok(out.to_vec())
    }
}

pub enum CipherMode {
    Cfb,
    Ofb,
    Ctr,
    Cbc,
}

pub struct Sm4CipherMode {
    cipher: Sm4Cipher,
    mode: CipherMode,
}

fn block_xor(a: &[u8], b: &[u8]) -> [u8; 16] {
    let mut out: [u8; 16] = [0; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn block_add_one(a: &mut [u8]) {
    let mut carry = 1;

    for i in 0..16 {
        let (t, c) = a[15 - i].overflowing_add(carry);
        a[15 - i] = t;
        if !c {
            return;
        }
        carry = c as u8;
    }
}

impl Sm4CipherMode {
    pub fn new(key: &[u8], mode: CipherMode) -> Sm4Result<Sm4CipherMode> {
        let cipher = Sm4Cipher::new(key)?;
        Ok(Sm4CipherMode { cipher, mode })
    }

    pub fn encrypt(&self, data: &[u8], iv: &[u8]) -> Sm4Result<Vec<u8>> {
        if iv.len() != 16 {
            return Err(Sm4Error::ErrorBlockSize);
        }
        match self.mode {
            CipherMode::Cfb => self.cfb_encrypt(data, iv),
            CipherMode::Ofb => self.ofb_encrypt(data, iv),
            CipherMode::Ctr => self.ctr_encrypt(data, iv),
            CipherMode::Cbc => self.cbc_encrypt(data, iv),
        }
    }

    pub fn decrypt(&self, data: &[u8], iv: &[u8]) -> Sm4Result<Vec<u8>> {
        if iv.len() != 16 {
            return Err(Sm4Error::ErrorBlockSize);
        }
        match self.mode {
            CipherMode::Cfb => self.cfb_decrypt(data, iv),
            CipherMode::Ofb => self.ofb_encrypt(data, iv),
            CipherMode::Ctr => self.ctr_encrypt(data, iv),
            CipherMode::Cbc => self.cbc_decrypt(data, iv),
        }
    }

    fn cfb_encrypt(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, Sm4Error> {
        let block_num = data.len() / 16;
        let tail_len = data.len() - block_num * 16;

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf: Vec<u8> = vec![0; 16];
        vec_buf.clone_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&vec_buf[..])?;
            let ct = block_xor(&enc, &data[i * 16..i * 16 + 16]);
            for i in ct.iter() {
                out.push(*i);
            }
            vec_buf.clone_from_slice(&ct);
        }

        // Last block
        let enc = self.cipher.encrypt(&vec_buf[..])?;
        for i in 0..tail_len {
            let b = data[block_num * 16 + i] ^ enc[i];
            out.push(b);
        }
        Ok(out)
    }

    fn cfb_decrypt(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, Sm4Error> {
        let block_num = data.len() / 16;
        let tail_len = data.len() - block_num * 16;

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf: Vec<u8> = vec![0; 16];
        vec_buf.clone_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&vec_buf[..])?;
            let ct = &data[i * 16..i * 16 + 16];
            let pt = block_xor(&enc, ct);
            for i in pt.iter() {
                out.push(*i);
            }
            vec_buf.clone_from_slice(ct);
        }

        // Last block
        let enc = self.cipher.encrypt(&vec_buf[..])?;
        for i in 0..tail_len {
            let b = data[block_num * 16 + i] ^ enc[i];
            out.push(b);
        }
        Ok(out)
    }

    fn ofb_encrypt(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, Sm4Error> {
        let block_num = data.len() / 16;
        let tail_len = data.len() - block_num * 16;

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf: Vec<u8> = vec![0; 16];
        vec_buf.clone_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&vec_buf[..])?;
            let ct = block_xor(&enc, &data[i * 16..i * 16 + 16]);
            for i in ct.iter() {
                out.push(*i);
            }
            vec_buf.clone_from_slice(&enc);
        }

        // Last block
        let enc = self.cipher.encrypt(&vec_buf[..])?;
        for i in 0..tail_len {
            let b = data[block_num * 16 + i] ^ enc[i];
            out.push(b);
        }
        Ok(out)
    }

    fn ctr_encrypt(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, Sm4Error> {
        let block_num = data.len() / 16;
        let tail_len = data.len() - block_num * 16;

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf: Vec<u8> = vec![0; 16];
        vec_buf.clone_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&vec_buf[..])?;
            let ct = block_xor(&enc, &data[i * 16..i * 16 + 16]);
            for i in ct.iter() {
                out.push(*i);
            }
            block_add_one(&mut vec_buf[..]);
        }

        // Last block
        let enc = self.cipher.encrypt(&vec_buf[..])?;
        for i in 0..tail_len {
            let b = data[block_num * 16 + i] ^ enc[i];
            out.push(b);
        }
        Ok(out)
    }

    fn cbc_encrypt(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, Sm4Error> {
        let block_num = data.len() / 16;
        let remind = data.len() % 16;

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf: Vec<u8> = vec![0; 16];
        vec_buf.copy_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let ct = block_xor(&vec_buf, &data[i * 16..i * 16 + 16]);
            let enc = self.cipher.encrypt(&ct)?;

            out.extend_from_slice(&enc);
            vec_buf = enc;
        }

        if remind != 0 {
            let mut last_block = [16 - remind as u8; 16];
            last_block[..remind].copy_from_slice(&data[block_num * 16..]);

            let ct = block_xor(&vec_buf, &last_block);
            let enc = self.cipher.encrypt(&ct)?;
            out.extend_from_slice(&enc);
        } else {
            let ff_padding = block_xor(&vec_buf, &[0x10; 16]);
            let enc = self.cipher.encrypt(&ff_padding)?;
            out.extend_from_slice(&enc);
        }

        Ok(out)
    }

    fn cbc_decrypt(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, Sm4Error> {
        let data_len = data.len();
        let block_num = data_len / 16;
        if data_len % 16 != 0 {
            return Err(Sm4Error::ErrorDataLen);
        }

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf = [0; 16];
        vec_buf.copy_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.decrypt(&data[i * 16..i * 16 + 16])?;
            let ct = block_xor(&vec_buf, &enc);

            for j in ct.iter() {
                out.push(*j);
            }
            vec_buf.copy_from_slice(&data[i * 16..i * 16 + 16]);
        }

        let last_u8 = out[data_len - 1];
        if last_u8 > 0x10 || last_u8 == 0 {
            return Err(Sm4Error::InvalidLastU8);
        }
        out.resize(data_len - last_u8 as usize, 0);

        Ok(out)
    }
}

#[cfg(test)]
mod sm4test {
    use crate::sm4::Sm4Cipher;
    use hex_literal::hex;

    #[test]
    fn test_en_1() {
        let key = hex!("0123456789abcdeffedcba9876543210");
        let plaintext = key.clone();
        let ciphertext = hex!("681edf34d206965e86b3e94f536e4246");

        let cipher = Sm4Cipher::new(&key).unwrap();

        let enc = cipher.encrypt(&plaintext).unwrap();
        assert_eq!(&ciphertext, enc.as_slice());
    }

    #[test]
    fn test_en_2() {
        let key = hex!("0123456789abcdeffedcba9876543210");
        let plaintext = key.clone();
        let ciphertext = hex!("595298c7c6fd271f0402f804c33d3f66");

        let cipher = Sm4Cipher::new(&key).unwrap();

        let mut block = plaintext.to_vec();
        for _ in 0..1_000_000 {
             block = cipher.encrypt(&block.as_slice()).unwrap();
        }
        assert_eq!(&ciphertext, block.as_slice());
    }
}
