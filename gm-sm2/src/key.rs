use hex::{FromHexError, ToHex};
use num_bigint::BigUint;

use gm_sm3::sm3_hash;

use crate::error::{Sm2Error, Sm2Result};
use crate::fields::FieldModOperation;
use crate::fields::fn64::{fn_add, fn_mul, fn_pow, fn_sub, SM2_N, SM2_N_MINUS_TWO};
use crate::fields::fp64::{from_mont, random_u256};
use crate::p256_ecc::{g_mul, Point};
use crate::u256::{SM2_ONE, U256, u256_add, u256_cmp, u256_from_be_bytes};
use crate::util::{compute_za, DEFAULT_ID, kdf, xor_bytes};

pub enum Sm2Model {
    C1C2C3,
    C1C3C2,
}

#[derive(Debug, Clone, Copy)]
pub struct Sm2PublicKey {
    pub point: Point,
}

impl Sm2PublicKey {
    pub fn to_bytes(&self, compress: bool) -> Vec<u8> {
        self.point.to_byte_be(compress)
    }

    pub fn new(pk: &[u8]) -> Sm2Result<Sm2PublicKey> {
        let p = Point::from_byte(pk)?;
        if p.is_valid() {
            Ok(Self { point: p })
        } else {
            Err(Sm2Error::InvalidPublic)
        }
    }

    pub fn is_valid(&self) -> bool {
        self.point.is_valid()
    }

    /// Encrypt the given message and return ASN.1 data
    pub fn encrypt_asn1(
        &self,
        msg: &[u8],
        compressed: bool,
        model: Sm2Model,
    ) -> Sm2Result<Vec<u8>> {
        let cipher = self.encrypt(msg, compressed, model).unwrap();
        let x = BigUint::from_bytes_be(&cipher[0..32]);
        let y = BigUint::from_bytes_be(&cipher[32..64]);
        let sm3 = &cipher[64..96];
        let secret = &cipher[96..];
        Ok(yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_biguint(&x);
                writer.next().write_biguint(&y);
                writer.next().write_bytes(&sm3);
                writer.next().write_bytes(&secret);
            });
        }))
    }

    /// Encrypt the given message.
    pub fn encrypt(&self, msg: &[u8], compressed: bool, model: Sm2Model) -> Sm2Result<Vec<u8>> {
        loop {
            let klen = msg.len();
            let k = random_u256();
            let c1_p = g_mul(&k);
            let c1_p = c1_p.to_affine_point(); // 根据加密算法，z坐标会被丢弃，为保证解密还原回来的坐标在曲线上，则必须转换坐标系到 affine 坐标系

            let s_p = self.point.scalar_mul(&SM2_ONE);
            if s_p.is_zero() {
                return Err(Sm2Error::ZeroPoint);
            }

            let c2_p = self.point.scalar_mul(&k).to_affine_point();
            let x2_bytes = from_mont(&c2_p.x).to_byte_be();
            let y2_bytes = from_mont(&c2_p.y).to_byte_be();
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
                let c2 = xor_bytes(msg, &t[..]);
                let mut c3_append: Vec<u8> = vec![];
                c3_append.extend_from_slice(&x2_bytes);
                c3_append.extend_from_slice(msg);
                c3_append.extend_from_slice(&y2_bytes);
                let c3 = sm3_hash(&c3_append);
                let mut c: Vec<u8> = vec![];
                match model {
                    Sm2Model::C1C2C3 => {
                        c.extend_from_slice(&c1_p.to_byte_be(compressed));
                        c.extend_from_slice(&c2);
                        c.extend_from_slice(&c3);
                    }
                    Sm2Model::C1C3C2 => {
                        c.extend_from_slice(&c1_p.to_byte_be(compressed));
                        c.extend_from_slice(&c3);
                        c.extend_from_slice(&c2);
                    }
                }
                return Ok(c);
            }
        }
    }

    pub fn verify(&self, id: Option<&'static str>, msg: &[u8], sig: &[u8]) -> Sm2Result<()> {
        let id = id.unwrap_or_else(|| DEFAULT_ID);
        let mut digest = compute_za(id, &self.point)?;
        digest = sm3_hash(&[digest.to_vec(), msg.to_vec()].concat());
        self.verify_raw(&digest[..], &self.point, sig)
    }

    fn verify_raw(&self, digest: &[u8], pk: &Point, sig: &[u8]) -> Sm2Result<()> {
        if digest.len() != 32 {
            return Err(Sm2Error::InvalidDigestLen);
        }
        let n = &SM2_N;
        let r = &u256_from_be_bytes(&sig[..32]);
        let s = &u256_from_be_bytes(&sig[32..]);
        if r.is_zero() || s.is_zero() {
            return Err(Sm2Error::ZeroSig);
        }
        if u256_cmp(r, n) >= 0 || u256_cmp(s, n) >= 0 {
            return Err(Sm2Error::InvalidDigest);
        }
        let t = fn_add(&s, &r);
        if t.is_zero() {
            return Err(Sm2Error::InvalidDigest);
        }
        let s_g = g_mul(&s);
        let t_p = pk.scalar_mul(&t);
        let p = s_g.point_add(&t_p).to_affine_point();
        let x1 = u256_from_be_bytes(&from_mont(&p.x).to_byte_be());
        let e = u256_from_be_bytes(&digest);
        let r1 = fn_add(&x1, &e);
        return if u256_cmp(r, &r1) == 0 {
            Ok(())
        } else {
            Err(Sm2Error::InvalidDigest)
        };
    }

    pub fn to_hex_string(&self, compressed: bool) -> String {
        let bytes = self.to_bytes(compressed);
        bytes.encode_hex::<String>()
    }

    pub fn from_hex_string(hex_str: &str) -> Result<Self, FromHexError> {
        let bytes = hex::decode(hex_str);
        match bytes {
            Ok(b) => Ok(Self {
                point: Point::from_byte(b.as_slice()).unwrap(),
            }),
            Err(e) => Err(e),
        }
    }

    pub fn value(&self) -> &Point {
        &self.point
    }
}

#[derive(Debug, Clone)]
pub struct Sm2PrivateKey {
    pub d: U256,
    pub public_key: Sm2PublicKey,
}

impl Eq for Sm2PrivateKey {}

impl PartialEq<Self> for Sm2PrivateKey {
    #[inline]
    fn eq(&self, other: &Sm2PrivateKey) -> bool {
        self.d == other.d
    }
}

impl AsRef<Sm2PublicKey> for Sm2PrivateKey {
    fn as_ref(&self) -> &Sm2PublicKey {
        &self.public_key
    }
}

impl Sm2PrivateKey {
    pub fn new(sk: &[u8]) -> Sm2Result<Self> {
        let d = u256_from_be_bytes(sk);
        let public_key = public_from_private(&d)?;
        let private_key = Self { d, public_key };
        Ok(private_key)
    }

    #[inline]
    pub fn to_bytes_be(&self) -> Vec<u8> {
        self.d.to_byte_be()
    }

    /// Sign the given digest.
    pub fn sign(&self, id: Option<&'static str>, msg: &[u8]) -> Sm2Result<Vec<u8>> {
        let id = id.unwrap_or_else(|| DEFAULT_ID);
        let mut digest = compute_za(id, &self.public_key.point)?;
        digest = sm3_hash(&[digest.to_vec(), msg.to_vec()].concat());
        self.sign_raw(&digest[..], &self.d)
    }

    fn sign_raw(&self, digest: &[u8], sk: &U256) -> Sm2Result<Vec<u8>> {
        if digest.len() != 32 {
            return Err(Sm2Error::InvalidDigestLen);
        }
        let e = u256_from_be_bytes(&digest);
        let n = &SM2_N;
        let s1 = fn_pow(&u256_add(&SM2_ONE, &sk).0, &SM2_N_MINUS_TWO);
        loop {
            let k = random_u256();
            let p_x = g_mul(&k).to_affine_point();
            let x1 = u256_from_be_bytes(&from_mont(&p_x.x).to_byte_be());
            let r = fn_add(&e, &x1);
            if r.is_zero() || u256_add(&r, &k).0 == *n {
                continue;
            }
            let s2_1 = fn_mul(&r, &sk);
            let s2 = fn_sub(&k, &s2_1);
            let s = fn_mul(&s1, &s2);
            if s.is_zero() {
                continue;
            }
            let mut sig: Vec<u8> = vec![];
            sig.extend_from_slice(&r.to_byte_be());
            sig.extend_from_slice(&s.to_byte_be());
            return Ok(sig);
        }
    }

    /// Decrypt the given ASN.1 message.
    pub fn decrypt_asn1(
        &self,
        ciphertext: &[u8],
        compressed: bool,
        model: Sm2Model,
    ) -> Sm2Result<Vec<u8>> {
        let (x, y, sm3, secret) = yasna::parse_der(ciphertext, |reader| {
            reader.read_sequence(|reader| {
                let x = reader.next().read_biguint()?;
                let y = reader.next().read_biguint()?;
                let sm3 = reader.next().read_bytes()?;
                let secret = reader.next().read_bytes()?;
                return Ok((x, y, sm3, secret));
            })
        })
        .unwrap();
        let x = BigUint::to_bytes_be(&x);
        let y = BigUint::to_bytes_be(&y);
        let mut cipher: Vec<u8> = vec![];
        cipher.extend_from_slice(&x);
        cipher.extend_from_slice(&y);
        cipher.extend_from_slice(&sm3);
        cipher.extend_from_slice(&secret);
        self.decrypt(&cipher, compressed, model)
    }

    /// Decrypt the given message.
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        compressed: bool,
        model: Sm2Model,
    ) -> Sm2Result<Vec<u8>> {
        let c1_end_index = match compressed {
            true => 33,
            false => 65,
        };
        let c1_bytes = &ciphertext[0..c1_end_index];
        let len = ciphertext.len();
        let c2_bytes = match model {
            Sm2Model::C1C2C3 => &ciphertext[c1_end_index..(len - 32)],
            Sm2Model::C1C3C2 => &ciphertext[(c1_end_index + 32)..],
        };
        let c3_bytes = match model {
            Sm2Model::C1C2C3 => &ciphertext[(len - 32)..],
            Sm2Model::C1C3C2 => &ciphertext[c1_end_index..c1_end_index + 32],
        };

        let kelen = c2_bytes.len();
        let c1_point = Point::from_byte(c1_bytes)?;
        if !c1_point.to_affine_point().is_valid_affine_point() {
            return Err(Sm2Error::CheckPointErr);
        }

        let s_point = c1_point.scalar_mul(&SM2_ONE);
        if s_point.is_zero() {
            return Err(Sm2Error::ZeroPoint);
        }

        let c2_point = c1_point.scalar_mul(&self.d).to_affine_point();
        let x2_bytes = from_mont(&c2_point.x).to_byte_be();
        let y2_bytes = from_mont(&c2_point.y).to_byte_be();
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

        let m = xor_bytes(c2_bytes, &t);
        let mut mb = m;
        if mb.len() < kelen {
            for i in 0..kelen - mb.len() {
                mb.insert(i, 0);
            }
        }
        let mut prepend: Vec<u8> = vec![];
        prepend.extend_from_slice(&x2_bytes);
        prepend.extend_from_slice(&mb);
        prepend.extend_from_slice(&y2_bytes);
        let u = sm3_hash(&prepend);
        if u != c3_bytes {
            return Err(Sm2Error::HashNotEqual);
        }
        Ok(mb)
    }

    pub fn to_hex_string(&self) -> String {
        let bytes = self.d.to_byte_be();
        bytes.encode_hex::<String>()
    }

    pub fn from_hex_string(hex_str: &str) -> Result<Self, String> {
        let bytes = hex::decode(hex_str);
        match bytes {
            Ok(b) => {
                let r = Self::new(b.as_slice());
                match r {
                    Ok(sk) => Ok(sk),
                    Err(e) => Err(e.to_string()),
                }
            }
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn to_public_key(&self) -> Sm2PublicKey {
        self.public_key.clone()
    }
}

/// generate key pair
pub fn gen_keypair() -> Sm2Result<(Sm2PublicKey, Sm2PrivateKey)> {
    let d = random_u256();
    let pk = public_from_private(&d)?;
    let sk = Sm2PrivateKey { d, public_key: pk };
    Ok((pk, sk))
}

fn public_from_private(sk: &U256) -> Sm2Result<Sm2PublicKey> {
    let p = g_mul(&sk);
    if p.is_valid() {
        Ok(Sm2PublicKey { point: p })
    } else {
        Err(Sm2Error::InvalidPublic)
    }
}
