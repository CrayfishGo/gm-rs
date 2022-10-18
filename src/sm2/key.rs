use crate::sm2::error::Sm2Result;
use crate::sm2::p256_ecc::{Point, P256C_PARAMS};
use crate::sm2::{key, p256_ecc};
use num_bigint::BigUint;
use crate::sm2::field::FieldElement;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Sm2PublicKey {
    p: Point,
}

impl Sm2PublicKey {
    pub fn encrypt(&self, msg: &[u8]) -> Sm2Result<Vec<u8>> {
        unimplemented!()
    }

    pub fn to_str_hex(&self) -> String {
        format!("{}{}", self.p.x.to_str_radix(16), self.p.y.to_str_radix(16))
    }
}

#[derive(Debug, Clone)]
pub struct Sm2PrivateKey {
    d: FieldElement,
}

impl Sm2PrivateKey {
    pub fn decrypt(&self, ciphertext: &[u8]) -> Sm2Result<Vec<u8>> {
        unimplemented!()
    }
}

/// generate key pair
pub fn gen_keypair() -> (Sm2PublicKey, Sm2PrivateKey) {
    let sk = Sm2PrivateKey {
        d: p256_ecc::random_uint(),
    };
    (public_from_private(&sk), sk)
}

pub fn public_from_private(sk: &Sm2PrivateKey) -> Sm2PublicKey {
    let p = p256_ecc::base_mul_point(&sk.d, &P256C_PARAMS.g_point);
    println!("check PK point = {}", p.is_valid());
    Sm2PublicKey { p }
}

#[cfg(test)]
mod test {
    use crate::format_hex;
    use crate::sm2::key::gen_keypair;

    #[test]
    fn test_gen_keypair() {
        let (pk, sk) = gen_keypair();
        println!("sk={}", format!("{:x}", &sk.d));
        println!("pk point={:?}", pk);
        println!("pk hex str={}", pk.to_str_hex());
    }
}
