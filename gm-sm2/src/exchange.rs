use byteorder::{BigEndian, WriteBytesExt};

use gm_sm3::sm3_hash;

use crate::error::{Sm2Error, Sm2Result};
use crate::fields::FieldModOperation;
use crate::fields::fn64::{fn_add, fn_mul};
use crate::fields::fp64::{from_mont, random_u256};
use crate::key::{gen_keypair, Sm2PrivateKey, Sm2PublicKey};
use crate::p256_ecc::{g_mul, Point};
use crate::u256::{SM2_ONE, U256, u256_add, u256_bits_and, u256_sub};
use crate::util::{compute_za, DEFAULT_ID, kdf};

#[derive(Debug)]
pub struct Exchange {
    klen: usize,
    za: [u8; 32],
    sk: Sm2PrivateKey,
    v: Option<Point>,
    r: Option<U256>,
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
    let (pk_a, sk_a) = gen_keypair().unwrap();
    let (pk_b, sk_b) = gen_keypair().unwrap();
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
        let id = id.unwrap_or_else(|| DEFAULT_ID);
        let rhs_id = rhs_id.unwrap_or_else(|| DEFAULT_ID);
        Ok(Exchange {
            klen,
            za: compute_za(id, &pk.point)?,
            sk: sk.clone(),
            v: None,
            r: None,
            r_point: None,
            k: None,
            rhs_za: compute_za(rhs_id, &rhs_pk.point)?,
            rhs_pk: rhs_pk.clone(),
        })
    }

    // Step1: UserA Call
    // A1：用随机数发生器产生随机数rA ∈ [1, n-1]；
    // A2：计算椭圆曲线点RA = [rA]G=(x1,y1)；
    // A3：将RA发送给用户B；
    pub fn exchange_1(&mut self) -> Sm2Result<Point> {
        let r = random_u256();
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
        // 2^127
        let pow: [u64; 4] = [
            0x8000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
        ];

        let r2 = random_u256();
        let r2_point = g_mul(&r2);
        self.r = Some(r2);
        self.r_point = Some(r2_point);
        let r2_point_affine = r2_point.to_affine_point();
        let x2 = from_mont(&r2_point_affine.x);
        let y2 = from_mont(&r2_point_affine.y);
        let x2_b = u256_add(&pow, &u256_bits_and(&x2, &u256_sub(&pow, &SM2_ONE).0)).0;
        let t2 = fn_add(
            &self.sk.d,
            &fn_mul(
                &self.r.as_ref().unwrap(),
                &x2_b,
            ),
        );

        let ra_point_affine = ra_point.to_affine_point();
        let x1 = from_mont(&ra_point_affine.x);
        let y1 = from_mont(&ra_point_affine.y);
        let x1_a = u256_add(&pow, &u256_bits_and(&x1, &u256_sub(&pow, &SM2_ONE).0)).0;

        let p = self
            .rhs_pk
            .value()
            .point_add(&ra_point.scalar_mul(&x1_a));
        let v_point = p.scalar_mul(&t2);
        if v_point.is_zero() {
            return Err(Sm2Error::ZeroPoint);
        }
        self.v = Some(v_point);

        let v_affine_p = v_point.to_affine_point();
        let xv_bytes = from_mont(&v_affine_p.x).to_byte_be();
        let yv_bytes = from_mont(&v_affine_p.y).to_byte_be();

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
        temp.extend_from_slice(&x1.to_byte_be());
        temp.extend_from_slice(&y1.to_byte_be());
        temp.extend_from_slice(&x2.to_byte_be());
        temp.extend_from_slice(&y2.to_byte_be());

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
        // 2^127
        let pow: [u64; 4] = [
            0x8000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
        ];

        let ra_point_affine = self.r_point.unwrap().to_affine_point();
        let x1 = from_mont(&ra_point_affine.x);
        let y1 = from_mont(&ra_point_affine.y);
        let x1_a = u256_add(&pow, &u256_bits_and(&x1, &u256_sub(&pow, &SM2_ONE).0)).0;
        let t_a = fn_add(
            &self.sk.d,
            &fn_mul(
                &self.r.as_ref().unwrap(),
                &x1_a,
            ),
        );

        let rb_point_affine = rb_point.to_affine_point();
        let x2 = from_mont(&rb_point_affine.x);
        let y2 = from_mont(&rb_point_affine.y);
        let x2_b = u256_add(&pow, &u256_bits_and(&x2, &u256_sub(&pow, &SM2_ONE).0)).0;
        let p = self
            .rhs_pk
            .value()
            .point_add(&rb_point.scalar_mul(&x2_b));
        let u_point = p.scalar_mul(&t_a);
        if u_point.is_zero() {
            return Err(Sm2Error::ZeroPoint);
        }

        let u_affine_p = u_point.to_affine_point();
        let xu_bytes = from_mont(&u_affine_p.x).to_byte_be();
        let yu_bytes = from_mont(&u_affine_p.y).to_byte_be();

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
        temp.extend_from_slice(&x1.to_byte_be());
        temp.extend_from_slice(&y1.to_byte_be());
        temp.extend_from_slice(&x2.to_byte_be());
        temp.extend_from_slice(&y2.to_byte_be());
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
        let ra_point_affine = ra_point.to_affine_point();
        let x1 = from_mont(&ra_point_affine.x);
        let y1 = from_mont(&ra_point_affine.y);

        let r2_point_affine = self.r_point.unwrap().to_affine_point();
        let x2 = from_mont(&r2_point_affine.x);
        let y2 = from_mont(&r2_point_affine.y);

        let v_point_affine = self.v.unwrap().to_affine_point();
        let xv = from_mont(&v_point_affine.x);
        let yv = from_mont(&v_point_affine.y);

        let mut temp: Vec<u8> = Vec::new();
        temp.extend_from_slice(&xv.to_byte_be());
        temp.extend_from_slice(&self.rhs_za);
        temp.extend_from_slice(&self.za);
        temp.extend_from_slice(&x1.to_byte_be());
        temp.extend_from_slice(&y1.to_byte_be());
        temp.extend_from_slice(&x2.to_byte_be());
        temp.extend_from_slice(&y2.to_byte_be());

        let mut prepend: Vec<u8> = Vec::new();
        prepend.write_u16::<BigEndian>(0x03_u16).unwrap();
        prepend.extend_from_slice(&yv.to_byte_be());
        prepend.extend_from_slice(&sm3_hash(&temp));
        let s_2 = sm3_hash(&prepend);
        Ok(s_2 == sa)
    }
}
