#![doc = include_str!("../README.md")]

use pkcs8::ObjectIdentifier;
use pkcs8::spki::AlgorithmIdentifier;

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
pub mod pkcs;

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

/// oid to pkcs8
pub const OID_SM2_PKCS8: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.156.10197.1.301");
pub const ALGORITHM_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

const ALGORITHM_IDENTIFIER: AlgorithmIdentifier<ObjectIdentifier> = AlgorithmIdentifier {
    oid: ALGORITHM_OID,
    parameters: Some(OID_SM2_PKCS8),
};

/// oid refer to GM/T 0006
pub const OID_SM2_CMS_1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.156.10197.1.301.1");
pub const OID_SM2_CMS_3: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.156.10197.1.301.3");

/// oid refer to GM/T 0010  pkcs#7
pub const OID_SM2_CMS_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.156.10197.6.1.4.2.1");
pub const OID_SM2_CMS_SIGNED: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.156.10197.6.1.4.2.2");
pub const OID_SM2_CMS_ENVELOPED: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.156.10197.6.1.4.2.3");
pub const OID_SM2_CMS_SIGNED_AND_ENVELOPED: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.156.10197.6.1.4.2.4");
pub const OID_SM2_CMS_ENCRYPTED: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.156.10197.6.1.4.2.5");
pub const OID_SM2_CMS_KEY_AGREEMENT_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.156.10197.6.1.4.2.6");

#[cfg(test)]
mod test_sm2 {
    use crate::exchange;
    use crate::key::{gen_keypair, Sm2Model, Sm2PrivateKey, Sm2PublicKey};

    #[test]
    fn test_encrypt_decrypt() {
        let (pk, sk) = gen_keypair().unwrap();
        let msg = "你好 world,asjdkajhdjadahkubbhj12893718927391873891,@@！！ world,1231 wo12321321313asdadadahello world，hello world".as_bytes();
        let encrypt = pk.encrypt(msg, false, Sm2Model::C1C2C3).unwrap();
        let plain = sk.decrypt(&encrypt, false, Sm2Model::C1C2C3).unwrap();
        println!("public key {}", pk.to_hex_string(false));
        println!("private key {}", sk.to_hex_string());
        assert_eq!(msg, plain)
    }

    #[test]
    fn test_encrypt_decrypt2() {
        let public_key = "048626c62a8582c639cb3c87b59118713a519988c5f6497f91dd672abbdaaed0420ea7bc2cd03a7c938adc42b450549d312bec823b74cf22cf57c63cebd011c595";
        let private_key = "eb20009ffbffc90aeeb288ca7d782c722332d1d16a206cafec7dd6c64e6fc525";
        let pk = Sm2PublicKey::from_hex_string(public_key).unwrap();
        let sk = Sm2PrivateKey::from_hex_string(private_key).unwrap();

        let msg = "你好 world,asjdkajhdjadahkubbhj12893718927391873891,@@！！ world,1231 wo12321321313asdadadahello world，hello world".as_bytes();
        let encrypt = pk.encrypt(msg, false, Sm2Model::C1C3C2).unwrap();
        let plain = sk.decrypt(&encrypt, false, Sm2Model::C1C3C2).unwrap();
        assert_eq!(msg, plain);
    }

    #[test]
    fn test_sign_verify() {
        let msg = b"hello";
        let (pk, sk) = gen_keypair().unwrap();
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
