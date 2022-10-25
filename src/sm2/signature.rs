use num_bigint::BigUint;
use num_traits::{FromPrimitive, One, Zero};

use crate::sm2::error::{Sm2Error, Sm2Result};
use crate::sm2::key::Sm2PublicKey;
use crate::sm2::p256_ecc::P256C_PARAMS;
use crate::sm2::util::{compute_za, random_uint, DEFAULT_ID};
use crate::sm2::{p256_ecc, FeOperation};
use crate::sm3::sm3_hash;

pub struct Signature {
    r: BigUint,
    s: BigUint,
}

/// 生成签名
///
pub fn sign(
    id: Option<&'static str>,
    msg: &[u8],
    sk: &BigUint,
    pk: &Sm2PublicKey,
) -> Sm2Result<Signature> {
    let id = match id {
        None => DEFAULT_ID,
        Some(u_id) => u_id,
    };
    let mut digest = compute_za(id, &pk)?;
    digest = sm3_hash(&[digest.to_vec(), msg.to_vec()].concat());
    sign_raw(&digest[..], sk)
}

fn sign_raw(digest: &[u8], sk: &BigUint) -> Sm2Result<Signature> {
    if digest.len() != 32 {
        return Err(Sm2Error::InvalidDigestLen);
    }
    let e = BigUint::from_bytes_be(&digest);
    let n = &P256C_PARAMS.n;
    loop {
        let k = random_uint();
        let p_x = p256_ecc::g_mul(&k).to_affine();
        let x1 = BigUint::from_bytes_be(&p_x.x.to_bytes_be());
        let r = e.mod_add(&x1, n);
        if r.is_zero() || &r + &k == *n {
            continue;
        }

        let s1 = &(BigUint::one() + sk).modpow(&(n - BigUint::from_u32(2).unwrap()), n);

        let s2_1 = r.mod_mul(&sk, n);
        let s2 = k.mod_sub(&s2_1, n);

        let s = s1.mod_mul(&s2, n);

        if s.is_zero() {
            return Err(Sm2Error::ZeroSig);
        }
        return Ok(Signature { r, s });
    }
}

impl Signature {
    /// 验证签名
    ///
    pub fn verify(
        &self,
        id: Option<&'static str>,
        msg: &[u8],
        pk: &Sm2PublicKey,
    ) -> Sm2Result<bool> {
        let id = match id {
            None => DEFAULT_ID,
            Some(u_id) => u_id,
        };
        let mut digest = compute_za(id, &pk)?;
        digest = sm3_hash(&[digest.to_vec(), msg.to_vec()].concat());
        self.verify_raw(&digest[..], pk)
    }

    fn verify_raw(&self, digest: &[u8], pk: &Sm2PublicKey) -> Sm2Result<bool> {
        if digest.len() != 32 {
            return Err(Sm2Error::InvalidDigestLen);
        }
        let n = &P256C_PARAMS.n;
        let r = &self.r;
        let s = &self.s;
        if r.is_zero() || s.is_zero() {
            return Ok(false);
        }

        if r >= n || s >= n {
            return Ok(false);
        }

        let t = s.mod_add(r, n);
        if t.is_zero() {
            return Ok(false);
        }

        let s_g = p256_ecc::g_mul(&s);
        let t_p = p256_ecc::scalar_mul(&t, &pk.value());

        let p = s_g.add(&t_p).to_affine();
        let x1 = BigUint::from_bytes_be(&p.x.to_bytes_be());
        let e = BigUint::from_bytes_be(digest);
        let r1 = x1.mod_add(&e, n);
        Ok(&r1 == r)
    }
}