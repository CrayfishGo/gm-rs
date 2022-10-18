// Elliptk Curve Cryptograp
// 椭圆曲线方程：y^2 = x^3 + a * x + b

use crate::sm2::error::Sm2Result;
use crate::sm2::field::FieldElement;
use crate::sm2::ModOperation;
use byteorder::{BigEndian, WriteBytesExt};
use lazy_static::lazy_static;
use num_traits::{FromPrimitive, Num, One, Zero};
use rand::prelude::SliceRandom;
use rand::RngCore;
use std::ops::{Div, Neg};

lazy_static! {
    pub static ref P256C_PARAMS: CurveParameters = CurveParameters::new();
}

/// ecc equation: y^2 == x^3 +ax + b (mod p)
#[derive(Debug, Clone)]
pub struct CurveParameters {
    pub(crate) p: FieldElement,
    pub(crate) n: FieldElement,
    pub(crate) a: FieldElement,
    pub(crate) b: FieldElement,
    pub(crate) g_point: Point,
}

impl CurveParameters {
    pub fn new() -> CurveParameters {
        let p = FieldElement::from_str_radix(
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
            16,
        )
        .unwrap();
        let n = FieldElement::from_str_radix(
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
            16,
        )
        .unwrap();
        let a = FieldElement::from_str_radix(
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
            16,
        )
        .unwrap();
        let b = FieldElement::from_str_radix(
            "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
            16,
        )
        .unwrap();

        let g_x = FieldElement::from_str_radix(
            "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
            16,
        )
        .unwrap();
        let g_y = FieldElement::from_str_radix(
            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
            16,
        )
        .unwrap();

        let g_point = Point {
            x: g_x,
            y: g_y,
            z: FieldElement::one(),
        };

        let ctx = CurveParameters {
            p,
            n,
            a,
            b,
            g_point,
        };
        ctx
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Point {
    pub x: FieldElement,
    pub y: FieldElement,
    pub z: FieldElement,
}

impl Point {
    pub fn is_zero(&self) -> bool {
        self.z.is_zero()
    }

    pub fn is_valid(&self) -> bool {
        if self.is_zero() {
            true
        } else {
            // y^2 = x^3 + a * x * z^4 + b * z^6
            let ecc_p = &P256C_PARAMS.p;
            let yy = &self.y * &self.y;
            let xxx = &self.x * &self.x * &self.x;
            let axz = &P256C_PARAMS.a * &self.x * &self.z.modpow(&FieldElement::from_u32(4), ecc_p);

            let bz = &P256C_PARAMS.b * &self.z.modpow(&FieldElement::from_u32(6), ecc_p);
            let exp = &xxx + &axz + &bz;
            yy.eq(&exp)
        }
    }

    pub fn zero() -> Point {
        Point {
            x: FieldElement::one(),
            y: FieldElement::one(),
            z: FieldElement::zero(),
        }
    }

    pub fn neg(&self) -> Point {
        Point {
            x: self.x.clone(),
            y: &P256C_PARAMS.p - &self.y,
            z: self.z.clone(),
        }
    }

    /// see GMT 0003.1-2012
    ///
    /// A.1.2.3.2  Jacobian 加重射影坐标
    // XX = X1^2
    // YY = Y1^2
    // ZZ = Z1^2
    // lambda1 = 3 * XX + a * ZZ^2
    // lambda2 = 4 * X1 * YY
    // lambda3 = 8 * YY^2
    // X3 = lambda1^2 - 2 * lambda2
    // Y3 = lambda1 * (lambda2 - X3) - lambda3
    // Z3 = 2 * Y1 * Z1
    pub fn double(&self) -> Point {
        let ecc_a = &P256C_PARAMS.a;
        let (x1, y1, z1) = (&self.x, &self.y, &self.z);
        let yy = y1 * y1;
        let xx = x1 * x1;
        let zz = z1 * z1;
        let lambda1 = &xx * 3u32 + ecc_a * (&zz * &zz);
        let lambda2 = x1 * 4u32 * &yy;
        let lambda3 = &yy * &yy * 8u32;
        let x3 = &lambda1 * &lambda1 - &lambda2 * 2u32;
        let y3 = &lambda1 * (&lambda2 - &x3) - &lambda3;
        let z3 = y1 * 2u32 * z1;
        let p = Point {
            x: x3,
            y: y3,
            z: z3,
        };
        p
    }

    /// see GMT 0003.1-2012
    ///
    /// A.1.2.3.2  Jacobian 加重射影坐标
    // The algorithm: "add-1998-cmo-2"
    //       Z1Z1 = Z1^2
    //       Z2Z2 = Z2^2
    //       U1 = X1*Z2Z2
    //       U2 = X2*Z1Z1
    //       S1 = Y1*Z2^3
    //       S2 = Y2*Z1^3
    //       H = U2-U1
    //       HH = H^2
    //       HHH = H*H^H
    //       r = S2-S1
    //       V = U1*HH
    //       X3 = r^2-HHH-2*V
    //       Y3 = r*(V-X3)-S1*HHH
    //       Z3 = Z1*Z2*H
    pub fn add(&self, p2: &Point) -> Point {
        let ecc_p = &P256C_PARAMS.p;
        // 0 + p2 = p2
        if self.is_zero() {
            return p2.clone();
        }
        // p1 + 0 = p1
        if p2.is_zero() {
            return self.clone();
        }
        let x1 = &self.x;
        let y1 = &self.y;
        let z1 = &self.z;

        let x2 = &p2.x;
        let y2 = &p2.y;
        let z2 = &p2.z;
        // p1 = p2
        if x1 == x2 && y1 == y2 && z1 == z2 {
            return self.double();
        } else {
            let z1z1 = z1 * z1;
            let z2z2 = z2 * z2;
            let u1 = x1 * &z2z2;
            let u2 = x2 * &z1z1;
            let s1 = y1 * z2 * &z2z2;
            let s2 = y2 * z1 * &z1z1;
            let h = &u2 - &u1;
            let r = &s2 - &s1;
            let hh = &h * &h;
            let hhh = &h * &hh;
            let v = &u1 * &hh;

            let x3 = &r * &r - &hhh - &v * 2u32;
            let y3 = &r * (&v - &x3) - &s1 * &hhh;
            let z3 = z1 * z2 * &h;
            let p = Point {
                x: x3,
                y: y3,
                z: z3,
            };
            p
        }
    }
}

// pub(crate) fn random_hex(x: usize) -> String {
//     let c = vec![
//         "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
//     ];
//     let mut s: String = "".to_string();
//     for _ in 0..x {
//         s += *c.choose(&mut rand::thread_rng()).unwrap();
//     }
//     s
// }

pub(crate) fn random_uint() -> FieldElement {
    let n: &FieldElement = &P256C_PARAMS.n;
    let mut rng = rand::thread_rng();
    let mut buf: [u8; 32] = [0; 32];
    let mut ret;
    loop {
        rng.fill_bytes(&mut buf[..]);
        ret = FieldElement::from_bytes_be(&buf[..]);
        if ret < n - FieldElement::one() && ret != FieldElement::zero() {
            break;
        }
    }
    ret
}

//
// P = [k]G
pub fn base_mul_point(m: &FieldElement, p: &Point) -> Point {
    let m = m % &P256C_PARAMS.n;
    let k = m.to_u32_digits();
    mul_raw_naf(k.as_slice(), p)
}

// 滑动窗口法
pub fn mul_raw_naf(k: &[u32], p: &Point) -> Point {
    let mut i = 256;
    let mut q = Point::zero();
    let naf = w_naf(k, 5, &mut i);
    let offset = 16;
    let mut table = vec![];
    for _ in 0..32 {
        table.push(Point::zero());
    }

    let double_p = p.double();

    table[1 + offset] = p.clone();
    table[offset - 1] = table[1 + offset].neg();
    for i in 1..8 {
        table[2 * i + offset + 1] = double_p.add(&table[2 * i + offset - 1]);
        table[offset - 2 * i - 1] = table[2 * i + offset + 1].neg();
    }

    loop {
        q = q.double();
        if naf[i] != 0 {
            let index = (naf[i] + 16) as usize;
            q = q.add(&table[index]);
        }

        if i == 0 {
            break;
        }
        i -= 1;
    }
    q
}

//w-naf algorithm
//See https://crypto.stackexchange.com/questions/82013/simple-explanation-of-sliding-window-and-wnaf-methods-of-elliptic-curve-point-mu
pub fn w_naf(k: &[u32], w: usize, lst: &mut usize) -> [i8; 257] {
    let mut carry = 0;
    let mut bit = 0;
    let mut ret: [i8; 257] = [0; 257];
    let mut n: [u32; 9] = [0; 9];

    n[1..9].clone_from_slice(&k[..8]);

    let window: u32 = (1 << w) - 1;

    while bit < 256 {
        let u32_idx = 8 - bit as usize / 32;
        let bit_idx = 31 - bit as usize % 32;

        if ((n[u32_idx] >> (31 - bit_idx)) & 1) == carry {
            bit += 1;
            continue;
        }

        let mut word: u32 = if bit_idx >= w - 1 {
            (n[u32_idx] >> (31 - bit_idx)) & window
        } else {
            ((n[u32_idx] >> (31 - bit_idx)) | (n[u32_idx - 1] << (bit_idx + 1))) & window
        };

        word += carry;

        carry = (word >> (w - 1)) & 1;
        ret[bit] = word as i8 - (carry << w) as i8;

        *lst = bit;
        bit += w;
    }

    if carry == 1 {
        ret[256] = 1;
        *lst = 256;
    }
    ret
}

pub fn mod_sub_raw(a: &[u32; 8], b: &[u32; 8], modulus: &[u32; 8]) -> [u32; 8] {
    let (modulus_complete, _) = sub_raw(&[0; 8], &modulus);
    let (raw_diff, borrow) = sub_raw(a, b);
    if borrow == 1 {
        let (diff, _borrow) = sub_raw(&raw_diff, &modulus_complete);
        diff
    } else {
        raw_diff
    }
}

fn sub_raw(a: &[u32; 8], b: &[u32; 8]) -> ([u32; 8], u32) {
    let mut sum = [0; 8];
    let mut borrow: u32 = 0;
    let mut j = 0;
    while j < 8 {
        let i = 7 - j;
        let t_sum: i64 = i64::from(a[i]) - i64::from(b[i]) - i64::from(borrow);
        if t_sum < 0 {
            sum[i] = (t_sum + (1 << 32)) as u32;
            borrow = 1;
        } else {
            sum[i] = t_sum as u32;
            borrow = 0;
        }
        j += 1;
    }
    (sum, borrow)
}

pub fn mod_add_raw(a: &[u32; 8], b: &[u32; 8], modulus: &[u32; 8]) -> [u32; 8] {
    let (raw_sum, carry) = add_raw(a, b);
    if carry == 1 || raw_sum >= *modulus {
        let (sum, _borrow) = sub_raw(&raw_sum, &modulus);
        sum
    } else {
        raw_sum
    }
}

fn add_raw(a: &[u32; 8], b: &[u32; 8]) -> ([u32; 8], u32) {
    let mut sum = [0; 8];
    let mut carry: u32 = 0;

    let t_sum: u64 = u64::from(a[7]) + u64::from(b[7]) + u64::from(carry);
    sum[7] = (t_sum & 0xffff_ffff) as u32;
    carry = (t_sum >> 32) as u32;

    let t_sum: u64 = u64::from(a[6]) + u64::from(b[6]) + u64::from(carry);
    sum[6] = (t_sum & 0xffff_ffff) as u32;
    carry = (t_sum >> 32) as u32;

    let t_sum: u64 = u64::from(a[5]) + u64::from(b[5]) + u64::from(carry);
    sum[5] = (t_sum & 0xffff_ffff) as u32;
    carry = (t_sum >> 32) as u32;

    let t_sum: u64 = u64::from(a[4]) + u64::from(b[4]) + u64::from(carry);
    sum[4] = (t_sum & 0xffff_ffff) as u32;
    carry = (t_sum >> 32) as u32;

    let t_sum: u64 = u64::from(a[3]) + u64::from(b[3]) + u64::from(carry);
    sum[3] = (t_sum & 0xffff_ffff) as u32;
    carry = (t_sum >> 32) as u32;

    let t_sum: u64 = u64::from(a[2]) + u64::from(b[2]) + u64::from(carry);
    sum[2] = (t_sum & 0xffff_ffff) as u32;
    carry = (t_sum >> 32) as u32;

    let t_sum: u64 = u64::from(a[1]) + u64::from(b[1]) + u64::from(carry);
    sum[1] = (t_sum & 0xffff_ffff) as u32;
    carry = (t_sum >> 32) as u32;

    let t_sum: u64 = u64::from(a[0]) + u64::from(b[0]) + u64::from(carry);
    sum[0] = (t_sum & 0xffff_ffff) as u32;
    carry = (t_sum >> 32) as u32;

    (sum, carry)
}

pub fn mod_mul_raw(a: &[u32; 8], b: &[u32; 8], modulus: &[u32; 8]) -> [u32; 8] {
    let raw_prod = mul_raw(a, b);
    fast_reduction(&raw_prod, &modulus)
}

fn mul_raw(a: &[u32; 8], b: &[u32; 8]) -> [u32; 16] {
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
                let (hi, lo) = u32_mul(a[7 - a_idx], b[7 - b_idx]);
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

#[inline(always)]
fn u32_mul(a: u32, b: u32) -> (u64, u64) {
    let uv = u64::from(a) * u64::from(b);
    let u = uv >> 32;
    let v = uv & 0xffff_ffff;
    (u, v)
}

// a quick algorithm to reduce elements on SCA-256 field
// Reference:
// http://ieeexplore.ieee.org/document/7285166/ for details
#[inline]
fn fast_reduction(input: &[u32; 16], modulus: &[u32; 8]) -> [u32; 8] {
    let mut rs: [[u32; 8]; 10] = [[0; 8]; 10];
    let mut rx: [u32; 16] = [0; 16];

    let mut i = 0;
    while i < 16 {
        rx[i] = input[15 - i];
        i += 1;
    }

    rs[0] = [rx[7], rx[6], rx[5], rx[4], rx[3], rx[2], rx[1], rx[0]];
    rs[1] = [rx[15], 0, 0, 0, 0, 0, rx[15], rx[14]];
    rs[2] = [rx[14], 0, 0, 0, 0, 0, rx[14], rx[13]];
    rs[3] = [rx[13], 0, 0, 0, 0, 0, 0, 0];
    rs[4] = [rx[12], 0, rx[15], rx[14], rx[13], 0, 0, rx[15]];
    rs[5] = [rx[15], rx[15], rx[14], rx[13], rx[12], 0, rx[11], rx[10]];
    rs[6] = [rx[11], rx[14], rx[13], rx[12], rx[11], 0, rx[10], rx[9]];
    rs[7] = [rx[10], rx[11], rx[10], rx[9], rx[8], 0, rx[13], rx[12]];
    rs[8] = [rx[9], 0, 0, rx[15], rx[14], 0, rx[9], rx[8]];
    rs[9] = [rx[8], 0, 0, 0, rx[15], 0, rx[12], rx[11]];

    let mut carry: i32 = 0;
    let mut sum = [0; 8];

    let (rt, rc) = add_raw(&sum, &rs[1]);
    sum = rt;
    carry += rc as i32;
    let (rt, rc) = add_raw(&sum, &rs[2]);
    sum = rt;
    carry += rc as i32;
    let (rt, rc) = add_raw(&sum, &rs[3]);
    sum = rt;
    carry += rc as i32;
    let (rt, rc) = add_raw(&sum, &rs[4]);
    sum = rt;
    carry += rc as i32;

    let (rt, rc) = add_raw(&sum, &sum);
    sum = rt;
    carry = carry * 2 + rc as i32;

    let (rt, rc) = add_raw(&sum, &rs[5]);
    sum = rt;
    carry += rc as i32;
    let (rt, rc) = add_raw(&sum, &rs[6]);
    sum = rt;
    carry += rc as i32;
    let (rt, rc) = add_raw(&sum, &rs[7]);
    sum = rt;
    carry += rc as i32;
    let (rt, rc) = add_raw(&sum, &rs[8]);
    sum = rt;
    carry += rc as i32;
    let (rt, rc) = add_raw(&sum, &rs[9]);
    sum = rt;
    carry += rc as i32;

    let mut part3 = [0; 8];
    let rt: u64 = u64::from(rx[8]) + u64::from(rx[9]) + u64::from(rx[13]) + u64::from(rx[14]);
    part3[5] = (rt & 0xffff_ffff) as u32;
    part3[4] = (rt >> 32) as u32;

    let (rt, rc) = add_raw(&sum, &rs[0]);
    sum = rt;
    carry += rc as i32;

    let (rt, rc) = sub_raw(&sum, &part3);
    sum = rt;
    carry -= rc as i32;

    while carry > 0 || sum >= *modulus {
        let (rs, rb) = sub_raw(&sum, modulus);
        sum = rs;
        carry -= rb as i32;
    }
    sum
}

pub fn to_bytes_be(value: &[u32; 8]) -> Vec<u8> {
    let mut ret: Vec<u8> = Vec::new();
    for i in 0..8 {
        ret.write_u32::<BigEndian>(value[i]).unwrap();
    }
    ret
}

#[cfg(test)]
mod test {
    use crate::sm2::field::FieldElement;
    use crate::sm2::p256_ecc::{
         mod_sub_raw, sub_raw, to_bytes_be, Point, P256C_PARAMS,
    };
    use crate::sm2::ModOperation;
    use num_traits::{FromPrimitive, Num, One};
}
