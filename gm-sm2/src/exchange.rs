use crate::error::{Sm2Error, Sm2Result};
use crate::key::{gen_keypair, CompressModle, Sm2PrivateKey, Sm2PublicKey};
use crate::p256_ecc::{g_mul, scalar_mul, Point, P256C_PARAMS};
use crate::util::{compute_za, kdf, random_uint, DEFAULT_ID};
use byteorder::{BigEndian, WriteBytesExt};
use gm_sm3::sm3_hash;
use num_bigint::BigUint;
use num_traits::{FromPrimitive, One, Pow};

#[derive(Debug)]
pub struct Exchange {
    klen: usize,
    za: [u8; 32],
    sk: Sm2PrivateKey,
    v: Option<Point>,
    r: Option<BigUint>,
    r_point: Option<Point>,
    pub(crate) k: Option<Vec<u8>>,

    rhs_za: [u8; 32],
    rhs_pk: Sm2PublicKey,
}

/// Build the exchange Pair
///
pub fn build_ex_pair(
    klen: usize,
    first_id: &str,
    other_id: &str,
) -> Sm2Result<(Exchange, Exchange)> {
    let (pk_a, sk_a) = gen_keypair(CompressModle::Compressed).unwrap();
    let (pk_b, sk_b) = gen_keypair(CompressModle::Compressed).unwrap();
    let user_a = Exchange::new(klen, Some(first_id), &pk_a, &sk_a, Some(other_id), &pk_b).unwrap();
    let user_b = Exchange::new(klen, Some(other_id), &pk_b, &sk_b, Some(first_id), &pk_a).unwrap();
    Ok((user_a, user_b))
}

impl Exchange {
    pub fn new(
        klen: usize,
        id: Option<&str>,
        pk: &Sm2PublicKey,
        sk: &Sm2PrivateKey,
        rhs_id: Option<&str>,
        rhs_pk: &Sm2PublicKey,
    ) -> Sm2Result<Exchange> {
        let id = match id {
            None => DEFAULT_ID,
            Some(s) => s,
        };
        let rhs_id = match rhs_id {
            None => DEFAULT_ID,
            Some(s) => s,
        };
        Ok(Exchange {
            klen,
            za: compute_za(id, &pk)?,
            sk: sk.clone(),
            v: None,
            r: None,
            r_point: None,
            k: None,
            rhs_za: compute_za(rhs_id, &rhs_pk)?,
            rhs_pk: rhs_pk.clone(),
        })
    }

    // Step1: UserA Call
    // A1：用随机数发生器产生随机数rA ∈ [1, n-1]；
    // A2：计算椭圆曲线点RA = [rA]G=(x1,y1)；
    // A3：将RA发送给用户B；
    pub fn exchange_1(&mut self) -> Sm2Result<Point> {
        let r = random_uint();
        let r_point = g_mul(&r);
        self.r = Some(r);
        self.r_point = Some(r_point);
        Ok(r_point)
    }

    // Step2: UserB Call
    //
    pub fn exchange_2(&mut self, ra_point: &Point) -> Sm2Result<(Point, [u8; 32])> {
        if !ra_point.is_valid() {
            return Err(Sm2Error::CheckPointErr);
        }
        let n = &P256C_PARAMS.n;
        let w = ((n.bits() as f64) / 2.0).ceil() - 1.0;
        let pow_w = BigUint::from_u32(2).unwrap().pow(w as u32);

        let r2 = random_uint();
        let r2_point = g_mul(&r2);
        self.r = Some(r2);
        self.r_point = Some(r2_point);
        let r2_point_affine = r2_point.to_affine();
        let x2 = r2_point_affine.x;
        let y2 = r2_point_affine.y;
        let x2_b = &pow_w + (x2.to_biguint() & (&pow_w - BigUint::one()));
        let t2 = (&self.sk.d + self.r.as_ref().unwrap() * &x2_b) % n;

        let ra_point_affine = ra_point.to_affine();
        let x1 = ra_point_affine.x;
        let y1 = ra_point_affine.y;
        let x1_a = &pow_w + (x1.to_biguint() & (&pow_w - BigUint::one()));

        let p = self.rhs_pk.value().add(&scalar_mul(&x1_a, ra_point));
        let v_point = scalar_mul(&(BigUint::one() * t2), &p);
        if v_point.is_zero() {
            return Err(Sm2Error::ZeroPoint);
        }
        self.v = Some(v_point);

        let v_affine_p = v_point.to_affine();
        let xv_bytes = v_affine_p.x.to_bytes_be();
        let yv_bytes = v_affine_p.y.to_bytes_be();

        let mut prepend = Vec::new();
        prepend.extend_from_slice(&xv_bytes);
        prepend.extend_from_slice(&yv_bytes);
        prepend.extend_from_slice(&self.rhs_za); // User A
        prepend.extend_from_slice(&self.za); // User B

        let k_b = kdf(&prepend, self.klen);
        self.k = Some(k_b);

        let mut temp: Vec<u8> = Vec::new();
        temp.extend_from_slice(&xv_bytes);
        temp.extend_from_slice(&self.rhs_za);
        temp.extend_from_slice(&self.za);
        temp.extend_from_slice(&x1.to_bytes_be());
        temp.extend_from_slice(&y1.to_bytes_be());
        temp.extend_from_slice(&x2.to_bytes_be());
        temp.extend_from_slice(&y2.to_bytes_be());

        let mut prepend: Vec<u8> = Vec::new();
        prepend.write_u16::<BigEndian>(0x02_u16).unwrap();
        prepend.extend_from_slice(&yv_bytes);
        prepend.extend_from_slice(&sm3_hash(&temp));
        Ok((r2_point, sm3_hash(&prepend)))
    }

    // Step4: UserA Call
    //
    pub fn exchange_3(&mut self, rb_point: &Point, sb: [u8; 32]) -> Sm2Result<[u8; 32]> {
        if !rb_point.is_valid() {
            return Err(Sm2Error::CheckPointErr);
        }
        let n = &P256C_PARAMS.n;
        let w = ((n.bits() as f64) / 2.0).ceil() - 1.0;
        let pow_w = BigUint::from_u32(2).unwrap().pow(w as u32);

        let ra_point_affine = self.r_point.unwrap().to_affine();
        let x1 = ra_point_affine.x;
        let y1 = ra_point_affine.y;
        let x1_a = &pow_w + (x1.to_biguint() & (&pow_w - BigUint::one()));
        let t_a = (&self.sk.d + x1_a * self.r.as_ref().unwrap()) % n;

        let rb_point_affine = rb_point.to_affine();
        let x2 = rb_point_affine.x;
        let y2 = rb_point_affine.y;
        let x2_b = &pow_w + (x2.to_biguint() & (&pow_w - BigUint::one()));

        let p = self.rhs_pk.value().add(&scalar_mul(&x2_b, rb_point));
        let u_point = scalar_mul(&(BigUint::one() * t_a), &p);
        if u_point.is_zero() {
            return Err(Sm2Error::ZeroPoint);
        }

        let u_affine_p = u_point.to_affine();
        let xu_bytes = u_affine_p.x.to_bytes_be();
        let yu_bytes = u_affine_p.y.to_bytes_be();

        let mut prepend = Vec::new();
        prepend.extend_from_slice(&xu_bytes);
        prepend.extend_from_slice(&yu_bytes);
        prepend.extend_from_slice(&self.za);
        prepend.extend_from_slice(&self.rhs_za);

        let k_a = kdf(&prepend, self.klen);
        self.k = Some(k_a);

        let mut temp: Vec<u8> = Vec::new();
        temp.extend_from_slice(&xu_bytes);
        temp.extend_from_slice(&self.za);
        temp.extend_from_slice(&self.rhs_za);
        temp.extend_from_slice(&x1.to_bytes_be());
        temp.extend_from_slice(&y1.to_bytes_be());
        temp.extend_from_slice(&x2.to_bytes_be());
        temp.extend_from_slice(&y2.to_bytes_be());
        let temp_hash = sm3_hash(&temp);

        let mut prepend: Vec<u8> = Vec::new();
        prepend.write_u16::<BigEndian>(0x02_u16).unwrap();
        prepend.extend_from_slice(&yu_bytes);
        prepend.extend_from_slice(&temp_hash);

        let s1 = sm3_hash(&prepend);
        if s1 != sb {
            return Err(Sm2Error::HashNotEqual);
        }

        let mut prepend: Vec<u8> = Vec::new();
        prepend.write_u16::<BigEndian>(0x03_u16).unwrap();
        prepend.extend_from_slice(&yu_bytes);
        prepend.extend_from_slice(&temp_hash);
        Ok(sm3_hash(&prepend))
    }

    // Step4: UserA Call
    pub fn exchange_4(&self, sa: [u8; 32], ra_point: &Point) -> Sm2Result<bool> {
        let ra_point_affine = ra_point.to_affine();
        let x1 = ra_point_affine.x;
        let y1 = ra_point_affine.y;

        let r2_point_affine = self.r_point.unwrap().to_affine();
        let x2 = r2_point_affine.x;
        let y2 = r2_point_affine.y;

        let v_point_affine = self.v.unwrap().to_affine();
        let xv = v_point_affine.x;
        let yv = v_point_affine.y;

        let mut temp: Vec<u8> = Vec::new();
        temp.extend_from_slice(&xv.to_bytes_be());
        temp.extend_from_slice(&self.rhs_za);
        temp.extend_from_slice(&self.za);
        temp.extend_from_slice(&x1.to_bytes_be());
        temp.extend_from_slice(&y1.to_bytes_be());
        temp.extend_from_slice(&x2.to_bytes_be());
        temp.extend_from_slice(&y2.to_bytes_be());

        let mut prepend: Vec<u8> = Vec::new();
        prepend.write_u16::<BigEndian>(0x03_u16).unwrap();
        prepend.extend_from_slice(&yv.to_bytes_be());
        prepend.extend_from_slice(&sm3_hash(&temp));
        let s_2 = sm3_hash(&prepend);
        Ok(s_2 == sa)
    }
}
