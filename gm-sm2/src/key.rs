use crate::error::{Sm2Error, Sm2Result};
use crate::p256_ecc::{Point, P256C_PARAMS};
use gm_sm3::sm3_hash;
use num_bigint::BigUint;
use num_traits::{FromPrimitive, One, Zero};

use crate::util::{compute_za, kdf, random_uint, DEFAULT_ID};
use crate::{p256_ecc, FeOperation};

#[derive(Debug, Clone, Copy)]
pub struct Sm2PublicKey {
    value: Point,
    compress_modle: CompressModle,
}

impl Sm2PublicKey {
    pub fn new(pk: &[u8], compress_modle: CompressModle) -> Sm2Result<Sm2PublicKey> {
        let value = Point::from_byte(pk, compress_modle)?;
        let public_key = Self {
            value,
            compress_modle,
        };
        if public_key.is_valid() {
            Ok(public_key)
        } else {
            Err(Sm2Error::InvalidPublic)
        }
    }

    pub fn is_valid(&self) -> bool {
        self.value.is_valid()
    }

    pub fn encrypt(&self, msg: &[u8]) -> Sm2Result<Vec<u8>> {
        loop {
            let klen = msg.len();
            let k = random_uint();
            let c1_p = p256_ecc::g_mul(&k);
            let c1_p = c1_p.to_affine(); // 根据加密算法，z坐标会被丢弃，为保证解密还原回来的坐标在曲线上，则必须转换坐标系到 affine 坐标系

            let s_p = p256_ecc::scalar_mul(&P256C_PARAMS.h, &self.value);
            if s_p.is_zero() {
                return Err(Sm2Error::ZeroPoint);
            }

            let c2_p = p256_ecc::scalar_mul(&k, &self.value).to_affine();
            let x2_bytes = c2_p.x.to_bytes_be();
            let y2_bytes = c2_p.y.to_bytes_be();
            let mut c2_append = vec![];
            c2_append.extend_from_slice(&x2_bytes);
            c2_append.extend_from_slice(&y2_bytes);

            let t = kdf(&c2_append[..], klen);
            let mut flag = true;
            for elem in &t {
                if elem != &0 {
                    flag = false;
                    break;
                }
            }
            if !flag {
                let c2 = BigUint::from_bytes_be(msg) ^ BigUint::from_bytes_be(&t[..]);
                let mut c3_append: Vec<u8> = vec![];
                c3_append.extend_from_slice(&x2_bytes);
                c3_append.extend_from_slice(msg);
                c3_append.extend_from_slice(&y2_bytes);
                let c3 = sm3_hash(&c3_append);

                let mut c: Vec<u8> = vec![];
                c.extend_from_slice(&c1_p.to_byte(self.compress_modle));
                c.extend_from_slice(&c2.to_bytes_be());
                c.extend_from_slice(&c3);
                return Ok(c);
            }
        }
    }

    pub fn verify(&self, id: Option<&'static str>, msg: &[u8], sig: &[u8]) -> Sm2Result<()> {
        let id = match id {
            None => DEFAULT_ID,
            Some(u_id) => u_id,
        };
        let mut digest = compute_za(id, self)?;
        digest = sm3_hash(&[digest.to_vec(), msg.to_vec()].concat());
        self.verify_raw(&digest[..], self, sig)
    }

    fn verify_raw(&self, digest: &[u8], pk: &Sm2PublicKey, sig: &[u8]) -> Sm2Result<()> {
        if digest.len() != 32 {
            return Err(Sm2Error::InvalidDigestLen);
        }
        let n = &P256C_PARAMS.n;
        let r = &BigUint::from_bytes_be(&sig[..32]);
        let s = &BigUint::from_bytes_be(&sig[32..]);
        if r.is_zero() || s.is_zero() {
            return Err(Sm2Error::ZeroSig);
        }

        if r >= n || s >= n {
            return Err(Sm2Error::InvalidDigest);
        }

        let t = s.mod_add(r, n);
        if t.is_zero() {
            return Err(Sm2Error::InvalidDigest);
        }

        let s_g = p256_ecc::g_mul(&s);
        let t_p = p256_ecc::scalar_mul(&t, &pk.value());

        let p = s_g.add(&t_p).to_affine();
        let x1 = BigUint::from_bytes_be(&p.x.to_bytes_be());
        let e = BigUint::from_bytes_be(digest);
        let r1 = x1.mod_add(&e, n);
        return if &r1 == r {
            Ok(())
        } else {
            Err(Sm2Error::InvalidDigest)
        };
    }

    pub fn to_str_hex(&self) -> String {
        format!(
            "{}{}",
            self.value.x.to_str_radix(16),
            self.value.y.to_str_radix(16)
        )
    }
    pub fn value(&self) -> &Point {
        &self.value
    }
}

#[derive(Debug, Clone)]
pub struct Sm2PrivateKey {
    pub d: BigUint,
    pub compress_modle: CompressModle,
    pub public_key: Sm2PublicKey,
}

impl Sm2PrivateKey {
    pub fn new(sk: &[u8], compress_modle: CompressModle) -> Sm2Result<Self> {
        let d = BigUint::from_bytes_be(sk);
        let public_key = public_from_private(&d, compress_modle)?;
        let private_key = Self {
            d,
            compress_modle,
            public_key,
        };

        Ok(private_key)
    }

    pub fn sign(&self, id: Option<&'static str>, msg: &[u8]) -> Sm2Result<Vec<u8>> {
        let id = match id {
            None => DEFAULT_ID,
            Some(u_id) => u_id,
        };
        let mut digest = compute_za(id, &self.public_key)?;
        digest = sm3_hash(&[digest.to_vec(), msg.to_vec()].concat());
        self.sign_raw(&digest[..], &self.d)
    }

    fn sign_raw(&self, digest: &[u8], sk: &BigUint) -> Sm2Result<Vec<u8>> {
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
            let mut sig: Vec<u8> = vec![];
            sig.extend_from_slice(&r.to_bytes_be());
            sig.extend_from_slice(&s.to_bytes_be());
            return Ok(sig);
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Sm2Result<Vec<u8>> {
        let c1_end_index = match self.compress_modle {
            CompressModle::Compressed => 33,
            CompressModle::Uncompressed | CompressModle::Mixed => 65,
        };

        let c1_bytes = &ciphertext[0..c1_end_index];
        let c2_bytes = &ciphertext[c1_end_index..(ciphertext.len() - 32)];
        let c3_bytes = &ciphertext[(ciphertext.len() - 32)..];

        let kelen = c2_bytes.len();
        let c1_point = Point::from_byte(c1_bytes, self.compress_modle)?;
        if !c1_point.to_affine().is_valid_affine() {
            return Err(Sm2Error::CheckPointErr);
        }

        let s_point = p256_ecc::scalar_mul(&P256C_PARAMS.h, &c1_point);
        if s_point.is_zero() {
            return Err(Sm2Error::ZeroPoint);
        }

        let c2_point = p256_ecc::scalar_mul(&self.d, &c1_point).to_affine();
        let x2_bytes = c2_point.x.to_bytes_be();
        let y2_bytes = c2_point.y.to_bytes_be();
        let mut prepend: Vec<u8> = vec![];
        prepend.extend_from_slice(&x2_bytes);
        prepend.extend_from_slice(&y2_bytes);
        let t = kdf(&prepend, kelen);
        let mut flag = true;
        for elem in &t {
            if elem != &0 {
                flag = false;
                break;
            }
        }
        if flag {
            return Err(Sm2Error::ZeroData);
        }

        let m = BigUint::from_bytes_be(c2_bytes) ^ BigUint::from_bytes_be(&t);
        let mut prepend: Vec<u8> = vec![];
        prepend.extend_from_slice(&x2_bytes);
        prepend.extend_from_slice(&m.to_bytes_be());
        prepend.extend_from_slice(&y2_bytes);

        let u = sm3_hash(&prepend);
        if u != c3_bytes {
            return Err(Sm2Error::HashNotEqual);
        }
        Ok(m.to_bytes_be())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum CompressModle {
    Compressed,
    Uncompressed,
    Mixed,
}

/// generate key pair
pub fn gen_keypair(compress_modle: CompressModle) -> Sm2Result<(Sm2PublicKey, Sm2PrivateKey)> {
    let d = random_uint();
    let pk = public_from_private(&d, compress_modle)?;
    let sk = Sm2PrivateKey {
        d,
        compress_modle,
        public_key: pk,
    };
    Ok((pk, sk))
}

fn public_from_private(sk: &BigUint, compress_modle: CompressModle) -> Sm2Result<Sm2PublicKey> {
    let p = p256_ecc::g_mul(&sk);
    if p.is_valid() {
        Ok(Sm2PublicKey {
            value: p,
            compress_modle,
        })
    } else {
        Err(Sm2Error::InvalidPublic)
    }
}
