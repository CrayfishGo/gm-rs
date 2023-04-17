use byteorder::{BigEndian, WriteBytesExt};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::RngCore;

use gm_sm3::sm3_hash;

use crate::error::{Sm2Error, Sm2Result};
use crate::key::Sm2PublicKey;
use crate::p256_ecc::P256C_PARAMS;

pub(crate) const DEFAULT_ID: &'static str = "1234567812345678";

#[inline]
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

#[inline]
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

    let last = sm3_hash(&prepend[..]);
    if klen % 32 == 0 {
        h_a.extend_from_slice(&last);
    } else {
        h_a.extend_from_slice(&last[0..(klen % 32)]);
    }
    h_a
}

#[inline(always)]
pub const fn adc_u64(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + (b as u128) + (carry as u128);
    ((ret & 0xffff_ffff_ffff_ffff) as u64, (ret >> 64) as u64)
}

#[inline(always)]
pub const fn add_u32(a: u32, b: u32, carry: u32) -> (u32, bool) {
    let (m, c1) = a.overflowing_add(b);
    let (r, c2) = m.overflowing_add(carry as u32);
    (r & 0xffff_ffff, c1 || c2)
}

#[inline(always)]
pub const fn fe32_to_fe64(fe32: &[u32; 8]) -> [u64; 4] {
    [
        (fe32[0] as u64) | ((fe32[1] as u64) << 32),
        (fe32[2] as u64) | ((fe32[3] as u64) << 32),
        (fe32[4] as u64) | ((fe32[5] as u64) << 32),
        (fe32[6] as u64) | ((fe32[7] as u64) << 32),
    ]
}

#[inline(always)]
pub const fn fe64_to_fe32(fe64: &[u64; 4]) -> [u32; 8] {
    let (w0, w1, w2, w3) = (fe64[0], fe64[1], fe64[2], fe64[3]);
    [
        (w0 & 0xFFFFFFFF) as u32,
        (w0 >> 32) as u32,
        (w1 & 0xFFFFFFFF) as u32,
        (w1 >> 32) as u32,
        (w2 & 0xFFFFFFFF) as u32,
        (w2 >> 32) as u32,
        (w3 & 0xFFFFFFFF) as u32,
        (w3 >> 32) as u32,
    ]
}

#[inline(always)]
pub const fn add_raw(a: &[u32; 8], b: &[u32; 8]) -> ([u32; 8], bool) {
    let mut sum = [0; 8];
    let mut carry = false;
    let mut i = 7;
    loop {
        let (t_sum, c) = add_u32(a[i], b[i], carry as u32);
        sum[i] = t_sum;
        carry = c;
        if i == 0 {
            break;
        }
        i -= 1;
    }
    (sum, carry)
}

#[inline(always)]
pub const fn sub_raw(a: &[u32; 8], b: &[u32; 8]) -> ([u32; 8], bool) {
    let mut r = [0; 8];
    let mut borrow = false;
    let mut j = 0;
    while j < 8 {
        let i = 7 - j;
        let (diff, bor) = sub_u32(a[i], b[i], borrow);
        r[i] = diff;
        borrow = bor;
        j += 1;
    }
    (r, borrow)
}

#[inline(always)]
pub const fn sub_u32(a: u32, b: u32, borrow: bool) -> (u32, bool) {
    let (a, b1) = a.overflowing_sub(borrow as u32);
    let (res, b2) = a.overflowing_sub(b);
    (res, b1 || b2)
}

#[inline(always)]
pub const fn mul_u32(a: u32, b: u32) -> (u64, u64) {
    let uv = (a as u64) * (b as u64);
    let u = uv >> 32;
    let v = uv & 0xffff_ffff;
    (u, v)
}

#[inline(always)]
pub const fn mul_raw(a: &[u32; 8], b: &[u32; 8]) -> [u32; 16] {
    let mut local: u64 = 0;
    let mut carry: u64 = 0;
    let mut ret: [u32; 16] = [0; 16];
    let mut ret_idx = 0;
    while ret_idx < 15 {
        let index = 15 - ret_idx;
        let mut a_idx = 0;
        while a_idx < 8 {
            if a_idx > ret_idx {
                break;
            }
            let b_idx = ret_idx - a_idx;
            if b_idx < 8 {
                let (hi, lo) = mul_u32(a[7 - a_idx], b[7 - b_idx]);
                local += lo;
                carry += hi;
            }
            a_idx += 1;
        }
        carry += local >> 32;
        local &= 0xffff_ffff;
        ret[index] = local as u32;
        local = carry;
        carry = 0;
        ret_idx += 1;
    }
    ret[0] = local as u32;
    ret
}

