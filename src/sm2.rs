use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::RngCore;

use crate::sm2::p256_ecc::P256C_PARAMS;
use crate::sm3;

pub mod error;
pub mod key;
mod macros;
mod operation;
pub mod p256_ecc;
pub mod p256_field;
pub mod signature;

pub(crate) fn random_uint() -> BigUint {
    let n = &P256C_PARAMS.n;
    let mut rng = rand::thread_rng();
    let mut buf: [u8; 32] = [0; 32];
    let mut ret;
    loop {
        rng.fill_bytes(&mut buf[..]);
        ret = BigUint::from_bytes_be(&buf[..]);
        if ret < n - BigUint::one() && ret != BigUint::zero() {
            break;
        }
    }
    ret
}

/// Fp 的加法，减法，乘法并不是简单的四则运算。其运算结果的值必须在Fp的有限域中，这样保证椭圆曲线变成离散的点
///
/// 这里我们规定一个有限域Fp
///
/// * 取大质数p，则有限域中有p-1个有限元：0，1，2...p-1
/// * Fp上的加法为模p加法`a+b≡c(mod p)`
/// * Fp上的乘法为模p乘法`a×b≡c(mod p)`
/// * Fp上的减法为模p减法`a-b≡c(mod p)`
/// * Fp上的除法就是乘除数的乘法逆元`a÷b≡c(mod p)`，即 `a×b^(-1)≡c (mod p)`
/// * Fp的乘法单位元为1，零元为0
/// * Fp域上满足交换律，结合律，分配律
pub trait FeOperation {
    /// Returns `(self + other) % modulus`.
    ///
    /// Panics if the modulus is zero.
    ///
    fn mod_add(&self, other: &Self, modulus: &Self) -> Self;

    fn mod_add_number(&self, other: u64, modulus: &Self) -> Self;

    /// Returns `(self - other) % modulus`.
    ///
    /// Panics if the modulus is zero.
    ///
    fn mod_sub(&self, other: &Self, modulus: &Self) -> Self;

    /// Returns `(self * other) % modulus`.
    ///
    /// Panics if the modulus is zero.
    ///
    fn mod_mul(&self, other: &Self, modulus: &Self) -> Self;

    fn mod_mul_number(&self, other: u64, modulus: &Self) -> Self;

    /// Extended Eulidean Algorithm(EEA) to calculate x^(-1) mod p
    fn inv(&self, modulus: &Self) -> Self;

    /// Self >>= carry
    fn right_shift(&self, carry: u32) -> Self;
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

#[cfg(test)]
mod test {
    use crate::sm2::key::{gen_keypair, CompressModle};
    use crate::sm2::signature;

    #[test]
    fn test_gen_keypair() {
        gen_keypair(CompressModle::Compressed).unwrap();
    }

    #[test]
    fn test_encrypt_decrypt() {
        let (pk, sk) = gen_keypair(CompressModle::Compressed).unwrap();
        let msg = "你好 world,asjdkajhdjadahkubbhj12893718927391873891,@@！！ world,1231 wo12321321313asdadadahello world，hello world".as_bytes();
        let encrypt = pk.encrypt(msg).unwrap();
        let plain = sk.decrypt(&encrypt).unwrap();
        assert_eq!(msg, plain)
    }

    #[test]
    fn test_sign() {
        let (pk, sk) = gen_keypair(CompressModle::Compressed).unwrap();
        signature::sign(None, b"hello", &sk.d, &pk).unwrap();
    }

    #[test]
    fn test_sign_verify() {
        let msg = b"hello";
        let (pk, sk) = gen_keypair(CompressModle::Compressed).unwrap();
        let signature = signature::sign(None, msg, &sk.d, &pk).unwrap();
        let r = signature.verify(None, msg, &pk).unwrap();
        println!("test_sign_verify = {}", r)
    }
}
