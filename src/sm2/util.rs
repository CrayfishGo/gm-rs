use crate::sm2::error::{Sm2Error, Sm2Result};
use crate::sm2::key::Sm2PublicKey;
use crate::sm2::p256_ecc::P256C_PARAMS;
use crate::sm3;
use crate::sm3::sm3_hash;
use byteorder::{BigEndian, WriteBytesExt};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::RngCore;

pub(crate) const DEFAULT_ID: &'static str = "1234567812345678";

pub fn random_uint() -> BigUint {
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

/// compute ZA = H256(ENTLA ∥ IDA ∥ a ∥ b ∥ xG ∥ yG ∥ xA ∥ yA)
pub fn compute_za(id: &str, pk: &Sm2PublicKey) -> Sm2Result<[u8; 32]> {
    if !pk.is_valid() {
        return Err(Sm2Error::InvalidPublic);
    }
    let mut prepend: Vec<u8> = Vec::new();
    if id.len() * 8 > 65535 {
        return Err(Sm2Error::IdTooLong);
    }
    prepend
        .write_u16::<BigEndian>((id.len() * 8) as u16)
        .unwrap();
    for c in id.bytes() {
        prepend.push(c);
    }

    prepend.extend_from_slice(&P256C_PARAMS.a.to_bytes_be());
    prepend.extend_from_slice(&P256C_PARAMS.b.to_bytes_be());
    prepend.extend_from_slice(&P256C_PARAMS.g_point.x.to_bytes_be());
    prepend.extend_from_slice(&P256C_PARAMS.g_point.y.to_bytes_be());

    let pk_affine = pk.value().to_affine();
    prepend.extend_from_slice(&pk_affine.x.to_bytes_be());
    prepend.extend_from_slice(&pk_affine.y.to_bytes_be());

    Ok(sm3_hash(&prepend))
}

pub fn kdf(z: &[u8], klen: usize) -> Vec<u8> {
    let mut ct = 0x00000001u32;
    let bound = ((klen as f64) / 32.0).ceil() as u32;
    let mut h_a = Vec::new();
    for _i in 1..bound {
        let mut prepend = Vec::new();
        prepend.extend_from_slice(z);
        prepend.extend_from_slice(&ct.to_be_bytes());

        let h_a_i = sm3_hash(&prepend[..]);
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
