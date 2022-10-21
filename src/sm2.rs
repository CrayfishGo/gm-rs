use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::RngCore;

use crate::sm2::p256_ecc::P256C_PARAMS;
use crate::sm3;

pub mod error;
pub mod key;
mod macros;
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
pub trait ModOperation {
    /// Returns `(self + other) % modulus`.
    ///
    /// Panics if the modulus is zero.
    ///
    fn modadd(&self, other: &Self, modulus: &Self) -> BigUint;

    fn modadd_u32(&self, other: u32, modulus: &Self) -> BigUint;

    /// Returns `(self - other) % modulus`.
    ///
    /// Panics if the modulus is zero.
    ///
    fn modsub(&self, other: &Self, modulus: &Self) -> BigUint;

    /// Returns `(self * other) % modulus`.
    ///
    /// Panics if the modulus is zero.
    ///
    fn modmul(&self, other: &Self, modulus: &Self) -> BigUint;

    fn modmul_u32(&self, other: u32, modulus: &Self) -> BigUint;

    /// Extended Eulidean Algorithm(EEA) to calculate x^(-1) mod p
    fn inv(&self, modulus: &Self) -> BigUint;
}

impl ModOperation for BigUint {
    fn modadd(&self, other: &Self, modulus: &Self) -> BigUint {
        (self + other) % modulus
    }

    fn modadd_u32(&self, other: u32, modulus: &Self) -> BigUint {
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

    fn modmul_u32(&self, other: u32, modulus: &Self) -> BigUint {
        (self * other) % modulus
    }

    fn inv(&self, modulus: &Self) -> BigUint {
        let mut ru = self.clone();
        let mut rv = modulus.clone();
        let mut ra = BigUint::one();
        let mut rc = BigUint::zero();
        let rn = modulus.clone();
        while ru != BigUint::zero() {
            if ru.is_even() {
                ru >>= 1;
                if ra.is_even() {
                    ra >>= 1;
                } else {
                    ra = (ra + &rn) >> 1;
                }
            }

            if rv.is_even() {
                rv >>= 1;
                if rc.is_even() {
                    rc >>= 1;
                } else {
                    rc = (rc + &rn) >> 1;
                }
            }

            if ru >= rv {
                ru -= &rv;
                if ra >= rc {
                    ra -= &rc;
                } else {
                    ra = ra + &rn - &rc;
                }
            } else {
                rv -= &ru;
                if rc >= ra {
                    rc -= &ra;
                } else {
                    rc = rc + &rn - &ra;
                }
            }
        }
        rc
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
