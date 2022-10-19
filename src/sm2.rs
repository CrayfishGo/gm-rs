use byteorder::{BigEndian, WriteBytesExt};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::RngCore;

use crate::sm2::p256_field::FieldElement;
use crate::sm2::p256_ecc::P256C_PARAMS;
use crate::sm3;

pub mod error;
pub mod p256_field;
pub mod key;
mod macros;
pub mod p256_ecc;



// pub(crate) fn random_hex(x: usize) -> String {
//     let c = vec![
//         "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
//     ];
//     let mut s: String = "".to_string();
//     for _ in 0..x {
//         s += *c.choose(&mut rand::thread_rng()).unwrap();
//     }
//     s
// }

pub(crate) fn random_uint() -> BigUint {
    let n: &FieldElement = &P256C_PARAMS.n;
    let mut rng = rand::thread_rng();
    let mut buf: [u8; 32] = [0; 32];
    let mut ret;
    loop {
        rng.fill_bytes(&mut buf[..]);
        ret = BigUint::from_bytes_be(&buf[..]);
        if ret < n.inner() - BigUint::one() && ret != BigUint::zero() {
            break;
        }
    }
    ret
}

/// A Mod B = A-(A/B)*B
pub trait ModOperation {
    /// Returns `(self + other) % modulus`.
    ///
    /// Panics if the modulus is zero.
    fn modadd(&self, other: &Self, modulus: &Self) -> BigUint;

    /// Returns `(self - other) % modulus`.
    ///
    /// Panics if the modulus is zero.
    fn modsub(&self, other: &Self, modulus: &Self) -> BigUint;

    /// Returns `(self * other) % modulus`.
    ///
    /// Panics if the modulus is zero.
    fn modmul(&self, other: &Self, modulus: &Self) -> BigUint;
}

impl ModOperation for BigUint {
    fn modadd(&self, other: &Self, modulus: &Self) -> BigUint {
        (self + other) % modulus
    }

    fn modsub(&self, other: &Self, modulus: &Self) -> BigUint {
        if self >= other {
            (self - other) % modulus
        } else {
            // 负数取模
            let d = other - self;
            let e = d.div_ceil(modulus);
            e * modulus - d
        }
    }

    fn modmul(&self, other: &Self, modulus: &Self) -> BigUint {
        (self * other) % modulus
    }
}

pub fn kdf(z: &[u8], klen: usize) -> Vec<u8> {
    let mut ct = 0x00000001u32;
    let bound = ((klen as f64) / 32.0).ceil() as u32;
    let mut h_a = Vec::new();
    for _i in 1..bound {
        let mut prepend = Vec::new();
        prepend.extend_from_slice(z);
        prepend.extend_from_slice(&ct.to_be_bytes());

        let h_a_i = sm3::sm3_hash(&prepend[..]);
        h_a.extend_from_slice(&h_a_i);
        ct += 1;
    }

    let mut prepend = Vec::new();
    prepend.extend_from_slice(z);
    prepend.extend_from_slice(&ct.to_be_bytes());

    let last = sm3::sm3_hash(&prepend[..]);
    if klen % 32 == 0 {
        h_a.extend_from_slice(&last);
    } else {
        h_a.extend_from_slice(&last[0..(klen % 32)]);
    }
    h_a
}
