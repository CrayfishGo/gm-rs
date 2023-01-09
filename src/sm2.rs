pub mod error;
pub mod exchange;
pub(crate) mod formulas;
pub mod key;
mod macros;
pub mod montgomery;
pub(crate) mod operation;
pub mod p256_ecc;
pub mod p256_field;
pub mod p256_pre_table;
pub mod util;

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
}

#[cfg(test)]
mod test_sm2 {
    use crate::sm2::exchange;
    use crate::sm2::key::{gen_keypair, CompressModle};

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
        let signature = sk.sign(None, msg).unwrap();
        pk.verify(None, msg, &signature).unwrap();
    }

    #[test]
    fn test_key_exchange() {
        let id_a = "alice123@qq.com";
        let id_b = "bob456@qq.com";

        let (mut alice, mut bob) = exchange::build_ex_pair(8, id_a, id_b).unwrap();

        let ra_point = alice.exchange_1().unwrap();
        let (rb_point, sb) = bob.exchange_2(&ra_point).unwrap();
        let sa = alice.exchange_3(&rb_point, sb).unwrap();
        let succ = bob.exchange_4(sa, &ra_point).unwrap();
        assert_eq!(succ, true);
        assert_eq!(alice.k, bob.k);
    }

}
