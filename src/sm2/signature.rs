use byteorder::{BigEndian, WriteBytesExt};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{FromPrimitive, One, Zero};

use crate::sm2::error::{Sm2Error, Sm2Result};
use crate::sm2::key::Sm2PublicKey;
use crate::sm2::p256_ecc::P256C_PARAMS;
use crate::sm2::{p256_ecc, random_uint, ModOperation};
use crate::sm3::sm3_hash;

const DEFAULT_ID: &'static str = "1234567812345678";

pub struct Signature {
    r: BigUint,
    s: BigUint,
}

/// 生成签名
///
pub(crate) fn sign(
    id: Option<&'static str>,
    msg: &[u8],
    sk: &BigUint,
    pk: &Sm2PublicKey,
) -> Sm2Result<Signature> {
    let id = match id {
        None => DEFAULT_ID,
        Some(u_id) => u_id,
    };
    let digest = e_hash(id, &pk, msg)?;
    sign_raw(&digest[..], sk)
}

pub(crate) fn e_hash(id: &str, pk: &Sm2PublicKey, msg: &[u8]) -> Sm2Result<[u8; 32]> {
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

    let za = sm3_hash(&prepend);

    Ok(sm3_hash(&[za.to_vec(), msg.to_vec()].concat()))
}

fn sign_raw(digest: &[u8], sk: &BigUint) -> Sm2Result<Signature> {
    if digest.len() != 32 {
        return Err(Sm2Error::InvalidDigestLen);
    }
    let e = BigUint::from_bytes_be(digest);
    let n = &P256C_PARAMS.n;
    loop {
        let k = random_uint();
        let p_x = p256_ecc::scalar_mul(&k, &P256C_PARAMS.g_point).to_affine();
        let x1 = BigUint::from_bytes_be(&p_x.x.to_bytes_be());
        let r = (&e + x1) % n;
        if r.is_zero() || &r + &k == *n {
            continue;
        }

        let s1 = &(BigUint::one() + sk).modpow(&(n - BigUint::from_u32(2).unwrap()), n);

        let s2_1 = &r.modmul(&sk, n);
        let s2 = k.modsub(s2_1, n);

        let s = s1.modmul(&s2, n);

        if s.is_zero() {
            return Err(Sm2Error::ZeroSig);
        }
        return Ok(Signature { r, s });
    }
}

// Extended Eulidean Algorithm(EEA) to calculate x^(-1) mod p
// Reference:
// http://delta.cs.cinvestav.mx/~francisco/arith/julio.pdf
pub fn inv_n(x: &BigUint) -> Sm2Result<BigUint> {
    if *x == BigUint::zero() {
        return Err(Sm2Error::ZeroDivisor);
    }
    let n = &P256C_PARAMS.n;
    let mut ru = x.clone();
    let mut rv = n.clone();
    let mut ra = BigUint::one();
    let mut rc = BigUint::zero();

    let rn = n.clone();

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
    Ok(rc)
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
        let digest = e_hash(id, pk, msg)?;
        self.verify_raw(&digest[..], pk)
    }

    fn verify_raw(&self, digest: &[u8], pk: &Sm2PublicKey) -> Sm2Result<bool> {
        if digest.len() != 32 {
            return Err(Sm2Error::InvalidDigestLen);
        }
        let n = &P256C_PARAMS.n;
        let e = BigUint::from_bytes_be(digest);
        let r = &self.r;
        let s = &self.s;
        if r.is_zero() || s.is_zero() {
            return Ok(false);
        }

        if r >= n || s >= n {
            return Ok(false);
        }

        let t = s.modadd(r, n);
        if t.is_zero() {
            return Ok(false);
        }

        let s_g = p256_ecc::scalar_mul(&s, &P256C_PARAMS.g_point);
        let t_p = p256_ecc::scalar_mul(&t, &pk.value());

        let p = s_g.add(&t_p).to_affine();
        let x1 = BigUint::from_bytes_be(&p.x.to_bytes_be());
        let r1 = x1.modadd(&e, n);
        Ok(&r1 == r)
    }
}
