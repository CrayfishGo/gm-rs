pub mod error;
pub mod exchange;
pub mod key;
mod macros;
pub(crate) mod operation;
pub mod p256_ecc;
pub mod p256_field;
pub mod p256_pre_table;
pub mod signature;
pub mod util;
pub(crate) mod formulas;
mod field64;

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

    /// Extended Eulidean Algorithm(EEA) to calculate x^(-1) mod p
    fn inv(&self, modulus: &Self) -> Self;

    /// Self >>= carry
    fn right_shift(&self, carry: u32) -> Self;

    /// Returns `(self + other)`.
    fn raw_add(&self, other: &Self) -> Self;

    /// Returns `(self - other)`.
    fn raw_sub(&self, other: &Self) -> Self;

    /// Returns `(self * other)`.
    fn raw_mul(&self, other: &Self) -> Self;


}

#[cfg(test)]
mod test_sm2 {
    use crate::sm2::exchange::Exchange;
    use crate::sm2::key::{CompressModle, gen_keypair};
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
    fn test_sign_verify() {
        let msg = b"hello";
        let (pk, sk) = gen_keypair(CompressModle::Compressed).unwrap();
        let signature = signature::sign(None, msg, &sk.d, &pk).unwrap();
        let r = signature.verify(None, msg, &pk).unwrap();
        assert_eq!(r, true)
    }

    #[test]
    fn test_key_exchange() {
        let id_a = "alice123@qq.com";
        let id_b = "bob456@qq.com";

        let (pk_a, sk_a) = gen_keypair(CompressModle::Compressed).unwrap();
        let (pk_b, sk_b) = gen_keypair(CompressModle::Compressed).unwrap();

        let mut user_a = Exchange::new(8, Some(id_a), &pk_a, &sk_a, Some(id_b), &pk_b).unwrap();
        let mut user_b = Exchange::new(8, Some(id_b), &pk_b, &sk_b, Some(id_a), &pk_a).unwrap();

        let ra_point = user_a.exchange_1().unwrap();
        let (rb_point, sb) = user_b.exchange_2(&ra_point).unwrap();
        let sa = user_a.exchange_3(&rb_point, sb).unwrap();
        let succ = user_b.exchange_4(sa, &ra_point).unwrap();
        assert_eq!(succ, true);
        assert_eq!(user_a.k, user_b.k);
    }
}
