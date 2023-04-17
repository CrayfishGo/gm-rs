use std::io::Cursor;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_bigint::{BigUint, ModInverse};
use num_integer::Integer;

use crate::FeOperation;
use crate::p256_field::{Conversion, Fe, FieldElement};
use crate::util::{add_raw, mul_raw, sub_raw};

impl Conversion for Fe {
    fn fe_to_bigunit(&self) -> BigUint {
        let mut ret: Vec<u8> = Vec::new();
        for i in 0..8 {
            ret.write_u32::<BigEndian>(self[i]).unwrap();
        }
        BigUint::from_bytes_be(&ret[..])
    }

    fn bigunit_fe(&self) -> Fe {
        unimplemented!()
    }
}

impl Conversion for BigUint {
    fn fe_to_bigunit(&self) -> BigUint {
        unimplemented!()
    }

    fn bigunit_fe(&self) -> Fe {
        let v = self.to_bytes_be();
        let mut num_v = [0u8; 32];
        num_v[32 - v.len()..32].copy_from_slice(&v[..]);
        let mut elem = [0u32; 8];
        let mut c = Cursor::new(num_v);
        for i in 0..8 {
            let x = c.read_u32::<BigEndian>().unwrap();
            elem[i] = x;
        }
        elem
    }
}

impl FeOperation for Fe {
    #[inline]
    fn mod_add(&self, other: &Self, modulus: &Self) -> Self {
        let (raw_sum, carry) = add_raw(self, other);
        if carry || raw_sum >= *modulus {
            let (sum, _borrow) = sub_raw(&raw_sum, &modulus);
            sum
        } else {
            raw_sum
        }
    }

    #[inline]
    fn mod_sub(&self, other: &Self, modulus: &Self) -> Self {
        let (raw_diff, borrow) = sub_raw(&self, other);
        if borrow {
            let (modulus_complete, _) = sub_raw(&[0; 8], &modulus);
            let (diff, _borrow) = sub_raw(&raw_diff, &modulus_complete);
            diff
        } else {
            raw_diff
        }
    }

    #[inline]
    fn mod_mul(&self, other: &Self, modulus: &Self) -> Self {
        let raw_prod = mul_raw(self, other);
        fast_reduction(&raw_prod, &modulus)
    }

    #[inline]
    fn inv(&self, modulus: &Self) -> Self {
        let mut ru = *self;
        let mut rv = *modulus;
        let mut ra = FieldElement::from_number(1).inner;
        let mut rc = [0; 8];
        while ru != [0; 8] {
            if ru[7] & 0x01 == 0 {
                ru = ru.right_shift(0);
                if ra[7] & 0x01 == 0 {
                    ra = ra.right_shift(0);
                } else {
                    let (sum, car) = add_raw(&ra, &modulus);
                    ra = sum.right_shift(car as u32);
                }
            }

            if rv[7] & 0x01 == 0 {
                rv = rv.right_shift(0);
                if rc[7] & 0x01 == 0 {
                    rc = rc.right_shift(0);
                } else {
                    let (sum, car) = add_raw(&rc, &modulus);
                    rc = sum.right_shift(car as u32);
                }
            }

            if ru >= rv {
                ru = ru.mod_sub(&rv, &modulus);
                ra = ra.mod_sub(&rc, &modulus);
            } else {
                rv = rv.mod_sub(&ru, &modulus);
                rc = rc.mod_sub(&ra, &modulus);
            }
        }
        rc
    }

    #[inline]
    fn right_shift(&self, carry: u32) -> Self {
        let mut ret = [0; 8];
        let mut carry = carry;
        let mut i = 0;
        while i < 8 {
            ret[i] = (carry << 31) + (self[i] >> 1);
            carry = self[i] & 0x01;
            i += 1;
        }
        ret
    }
}

// a quick algorithm to reduce elements on SCA-256 field
// Reference:
// http://ieeexplore.ieee.org/document/7285166/ for details
// 国密SM2的快速约减算法详细描述
// S0 = (m7, m6, m5, m4, m3, m2, m1, m0)
// S1 = (m15, 0, 0, 0, 0, 0, m15, m14)
// S2 = (m14, 0, 0, 0, 0, 0, m14, m13)
// S3 = (m13, 0, 0, 0, 0, 0, 0, m15)
// S4 = (m12, 0, m15, m14, m13, 0, 0, m15)
// S5 = (m15, m15, m14, m13, m12, 0, m11, m10)
// S6 = (m11, m14, m13, m12, m11, 0, m10, m9)
// S7 = (m10, m11, m10, m9, m8, 0, m13, m12)
// S8 = (m9, 0, 0, m15, m14, 0, m9, m8)
// S9 = (m8, 0, 0, 0, m15, 0, m12, m11)
//
#[inline(always)]
pub fn fast_reduction(a: &[u32; 16], modulus: &[u32; 8]) -> [u32; 8] {
    let mut s: [[u32; 8]; 10] = [[0; 8]; 10];
    let mut m: [u32; 16] = [0; 16];

    let mut i = 0;
    while i < 16 {
        m[i] = a[15 - i];
        i += 1;
    }

    s[0] = [m[7], m[6], m[5], m[4], m[3], m[2], m[1], m[0]];

    s[1] = [m[15], 0, 0, 0, 0, 0, m[15], m[14]];
    s[2] = [m[14], 0, 0, 0, 0, 0, m[14], m[13]];
    s[3] = [m[13], 0, 0, 0, 0, 0, 0, 0];
    s[4] = [m[12], 0, m[15], m[14], m[13], 0, 0, m[15]];

    s[5] = [m[15], m[15], m[14], m[13], m[12], 0, m[11], m[10]];
    s[6] = [m[11], m[14], m[13], m[12], m[11], 0, m[10], m[9]];
    s[7] = [m[10], m[11], m[10], m[9], m[8], 0, m[13], m[12]];
    s[8] = [m[9], 0, 0, m[15], m[14], 0, m[9], m[8]];
    s[9] = [m[8], 0, 0, 0, m[15], 0, m[12], m[11]];

    let mut carry: i32 = 0;
    let mut ret = [0; 8];

    // part1: 2 * (s1+s2+s3+s4)
    let (rt, rc) = add_raw(&ret, &s[1]);
    ret = rt;
    carry += rc as i32;
    let (rt, rc) = add_raw(&ret, &s[2]);
    ret = rt;
    carry += rc as i32;
    let (rt, rc) = add_raw(&ret, &s[3]);
    ret = rt;
    carry += rc as i32;
    let (rt, rc) = add_raw(&ret, &s[4]);
    ret = rt;
    carry += rc as i32;
    let (rt, rc) = add_raw(&ret, &ret);
    ret = rt;
    carry = carry * 2 + rc as i32;

    // part2: s0+s5+s6+s7+s8+s9
    let (rt, rc) = add_raw(&ret, &s[5]);
    ret = rt;
    carry += rc as i32;
    let (rt, rc) = add_raw(&ret, &s[6]);
    ret = rt;
    carry += rc as i32;
    let (rt, rc) = add_raw(&ret, &s[7]);
    ret = rt;
    carry += rc as i32;
    let (rt, rc) = add_raw(&ret, &s[8]);
    ret = rt;
    carry += rc as i32;
    let (rt, rc) = add_raw(&ret, &s[9]);
    ret = rt;
    carry += rc as i32;
    let (rt, rc) = add_raw(&ret, &s[0]);
    ret = rt;
    carry += rc as i32;

    // part3:  m8+m9+m13+m14
    let mut part3 = [0; 8];
    let subtra: u64 = u64::from(m[8]) + u64::from(m[9]) + u64::from(m[13]) + u64::from(m[14]);
    part3[5] = (subtra & 0xffff_ffff) as u32;
    part3[4] = (subtra >> 32) as u32;

    // part1 + part2 - part3
    let (rt, rc) = sub_raw(&ret, &part3);
    ret = rt;
    carry -= rc as i32;

    while carry > 0 || ret >= *modulus {
        let (rs, rb) = sub_raw(&ret, modulus);
        ret = rs;
        carry -= rb as i32;
    }
    ret
}

impl FeOperation for BigUint {
    fn mod_add(&self, other: &Self, modulus: &Self) -> BigUint {
        (self + other) % modulus
    }

    fn mod_sub(&self, other: &Self, modulus: &Self) -> BigUint {
        if self >= other {
            (self - other) % modulus
        } else {
            // 负数取模
            let d = other - self;
            let e = d.div_ceil(modulus);
            e * modulus - d
        }
    }

    fn mod_mul(&self, other: &Self, modulus: &Self) -> BigUint {
        (self * other) % modulus
    }

    fn inv(&self, modulus: &Self) -> BigUint {
        self.mod_inverse(modulus).unwrap().to_biguint().unwrap()
    }

    fn right_shift(&self, carry: u32) -> BigUint {
        let mut ret = self.clone();
        ret = ret >> (carry as i32) as usize;
        ret
    }
}

#[cfg(test)]
mod test_op {
    use num_bigint::ModInverse;
    use rand::{Rng, thread_rng};

    use crate::p256_ecc::P256C_PARAMS;
    use crate::p256_pre_table::PRE_TABLE_1;
    use crate::sm2::FeOperation;
    use crate::sm2::p256_ecc::P256C_PARAMS;
    use crate::sm2::p256_pre_table::PRE_TABLE_1;

    #[test]
    fn test_mod_add() {
        let mut rng = thread_rng();
        let n: u32 = rng.gen_range(10..256);

        let modulus = &P256C_PARAMS.p;

        let p = &PRE_TABLE_1[n as usize];
        let x = p.x.to_biguint();
        let y = p.y.to_biguint();

        let ret1 = x.mod_add(&y, &modulus.to_biguint());
        let ret2 = (p.x + p.y).to_biguint();

        assert_eq!(ret2, ret1)
    }

    #[test]
    fn test_mod_sub() {
        let mut rng = thread_rng();
        let n: u32 = rng.gen_range(10..256);

        let modulus = &P256C_PARAMS.p;

        let p = &PRE_TABLE_1[n as usize];
        let x = p.x.to_biguint();
        let y = p.y.to_biguint();

        let ret1 = x.mod_sub(&y, &modulus.to_biguint());
        let ret2 = (p.x - p.y).to_biguint();

        assert_eq!(ret2, ret1)
    }

    #[test]
    fn test_mod_mul() {
        let mut rng = thread_rng();
        let n: u32 = rng.gen_range(10..256);

        let modulus = &P256C_PARAMS.p;

        let p = &PRE_TABLE_1[n as usize];
        let x = p.x.to_biguint();
        let y = p.y.to_biguint();

        let ret1 = x.mod_mul(&y, &modulus.to_biguint());
        let ret2 = (p.x * p.y).to_biguint();

        assert_eq!(ret2, ret1)
    }

    #[test]
    fn test_mod_inv() {
        let mut rng = thread_rng();
        let n: u32 = rng.gen_range(10..256);

        let modulus = &P256C_PARAMS.p;

        let p = &PRE_TABLE_1[n as usize];
        let x = p.x.to_biguint();

        let ret1 = x.inv(&modulus.to_biguint());
        let ret2 = x
            .mod_inverse(&modulus.to_biguint())
            .unwrap()
            .to_biguint()
            .unwrap();

        assert_eq!(ret2, ret1)
    }
}
