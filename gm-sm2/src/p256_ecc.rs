use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::{Num, One};

use crate::error::{Sm2Error, Sm2Result};
use crate::formulas::{add_1998_cmo, double_1998_cmo};
use crate::p256_field::FieldElement;
use crate::p256_pre_table::{PRE_TABLE_1, PRE_TABLE_2};

lazy_static! {
    pub static ref P256C_PARAMS: CurveParameters = CurveParameters::new_default();
}

/// ecc equation: y^2 == x^3 +ax + b (mod p)
#[derive(Debug, Clone)]
pub struct CurveParameters {
    /// p：大于3的素数
    ///
    /// p = 2^256 − 2^224 − 2^96 + 2^32 − 1
    pub p: FieldElement,

    /// n：基点G的阶(n是#E(Fq)的素因子)
    pub n: BigUint,

    /// a：Fq中的元素，它们定义Fq上的一条椭圆曲线E
    pub a: FieldElement,

    /// b：Fq中的元素，它们定义Fq上的一条椭圆曲线E
    pub b: FieldElement,

    /// The Cofactor, the recommended value is 1
    /// 余因子，h = #E(Fq)/n，其中n是基点G的阶
    pub h: BigUint,

    /// G：椭圆曲线的一个基点，其阶为素数
    pub g_point: Point,
}

impl Default for CurveParameters {
    fn default() -> Self {
        CurveParameters::new_default()
    }
}

impl CurveParameters {
    /// 生成椭圆曲线参数
    ///
    pub fn generate() -> Self {
        unimplemented!()
    }

    /// 验证椭圆曲线参数
    ///
    pub fn verify(&self) -> bool {
        unimplemented!()
    }

    pub fn new_default() -> CurveParameters {
        let p = FieldElement::new([
            0xffff_fffe,
            0xffff_ffff,
            0xffff_ffff,
            0xffff_ffff,
            0xffff_ffff,
            0x0000_0000,
            0xffff_ffff,
            0xffff_ffff,
        ]);
        let n = BigUint::from_str_radix(
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
            16,
        )
        .unwrap();
        let a = FieldElement::new([
            0xffff_fffe,
            0xffff_ffff,
            0xffff_ffff,
            0xffff_ffff,
            0xffff_ffff,
            0x0000_0000,
            0xffff_ffff,
            0xffff_fffc,
        ]);
        let b = FieldElement::new([
            0x28e9_fa9e,
            0x9d9f_5e34,
            0x4d5a_9e4b,
            0xcf65_09a7,
            0xf397_89f5,
            0x15ab_8f92,
            0xddbc_bd41,
            0x4d94_0e93,
        ]);

        let g_x = FieldElement::new([
            0x32c4_ae2c,
            0x1f19_8119,
            0x5f99_0446,
            0x6a39_c994,
            0x8fe3_0bbf,
            0xf266_0be1,
            0x715a_4589,
            0x334c_74c7,
        ]);
        let g_y = FieldElement::new([
            0xbc37_36a2,
            0xf4f6_779c,
            0x59bd_cee3,
            0x6b69_2153,
            0xd0a9_877c,
            0xc62a_4740,
            0x02df_32e5,
            0x2139_f0a0,
        ]);
        let ctx = CurveParameters {
            p,
            n,
            a,
            b,
            h: BigUint::one(), // The Cofactor, the recommended value is 1
            g_point: Point {
                x: g_x,
                y: g_y,
                z: FieldElement::one(),
            },
        };
        ctx
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Copy)]
pub struct Point {
    pub x: FieldElement,
    pub y: FieldElement,
    pub z: FieldElement,
}

impl Point {
    pub fn to_affine_point(&self) -> Point {
        let z_inv = &self.z.mod_inv();
        let z_inv2 = z_inv * z_inv;
        let z_inv3 = z_inv2 * z_inv;
        let x = &self.x * z_inv2;
        let y = &self.y * z_inv3;
        Point {
            x,
            y,
            z: FieldElement::one(),
        }
    }

    pub fn to_byte_be(&self, compress: bool) -> Vec<u8> {
        let p_affine = self.to_affine_point();
        let mut x_vec = p_affine.x.to_bytes_be();
        let mut y_vec = p_affine.y.to_bytes_be();
        let mut ret: Vec<u8> = Vec::new();
        if compress {
            if y_vec[y_vec.len() - 1] & 0x01 == 0 {
                ret.push(0x02);
            } else {
                ret.push(0x03);
            }
            ret.append(&mut x_vec);
        } else {
            ret.push(0x04);
            ret.append(&mut x_vec);
            ret.append(&mut y_vec);
        }
        ret
    }

    pub(crate) fn from_byte(b: &[u8]) -> Sm2Result<Point> {
        let flag = b[0];
        // Compressed Point
        if flag == 0x02 || flag == 0x03 {
            if b.len() != 33 {
                return Err(Sm2Error::InvalidPublic);
            }
            let y_q;
            if b[0] == 0x02 {
                y_q = 0;
            } else {
                y_q = 1
            }
            let x = FieldElement::from_bytes_be(&b[1..])?;
            let xxx = &x * &x * &x;
            let ax = &P256C_PARAMS.a * &x;
            let yy = &xxx + &ax + &P256C_PARAMS.b;

            let mut y = yy.sqrt()?;
            let y_vec = y.to_bytes_be();
            if y_vec[y_vec.len() - 1] & 0x01 != y_q {
                y = &P256C_PARAMS.p - y;
            }
            Ok(Point {
                x,
                y,
                z: FieldElement::one(),
            })
        }
        // uncompressed Point
        else {
            if b.len() != 65 {
                return Err(Sm2Error::InvalidPublic);
            }
            let x = FieldElement::from_bytes_be(&b[1..33])?;
            let y = FieldElement::from_bytes_be(&b[33..65])?;
            Ok(Point {
                x,
                y,
                z: FieldElement::one(),
            })
        }
    }
}

impl Point {
    pub fn is_zero(&self) -> bool {
        self.z.is_zero()
    }

    pub fn is_valid(&self) -> bool {
        if self.is_zero() {
            true
        } else {
            // y^2 = x * (x^2 + a * z^4) + b * z^6
            let yy = &self.y * &self.y;
            let xx = &self.x * &self.x;
            let z2 = &self.z * &self.z;
            let z4 = &z2 * &z2;
            let z6 = &z4 * &z2;
            let z6_b = &P256C_PARAMS.b * &z6;
            let a_z4 = &P256C_PARAMS.a * &z4;
            let xx_a_4z = &xx + &a_z4;
            let xxx_a_4z = &xx_a_4z * &self.x;
            let exp = &xxx_a_4z + &z6_b;
            yy.eq(&exp)
        }
    }

    pub fn is_valid_affine_point(&self) -> bool {
        // y^2 = x * (x^2 + a) + b
        let yy = &self.y * &self.y;
        let xx = &self.x * &self.x;
        let xx_a = &P256C_PARAMS.a + &xx;
        let xxx_a = &self.x * &xx_a;
        let b = &P256C_PARAMS.b;
        let exp = &xxx_a + b;
        yy.eq(&exp)
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

    pub fn double(&self) -> Point {
        double_1998_cmo(self)
    }

    pub fn add(&self, p2: &Point) -> Point {
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
            add_1998_cmo(self, &p2)
        }
    }
}

#[inline(always)]
const fn ith_bit(n: u32, i: i32) -> u32 {
    (n >> i) & 0x01
}

#[inline(always)]
const fn compose_index(v: &[u32], i: i32) -> u32 {
    ith_bit(v[7], i)
        + (ith_bit(v[6], i) << 1)
        + (ith_bit(v[5], i) << 2)
        + (ith_bit(v[4], i) << 3)
        + (ith_bit(v[3], i) << 4)
        + (ith_bit(v[2], i) << 5)
        + (ith_bit(v[1], i) << 6)
        + (ith_bit(v[0], i) << 7)
}

pub fn g_mul(m: &BigUint) -> Point {
    let k = FieldElement::from_biguint(&m).unwrap();
    let mut q = Point::zero();
    let mut i = 15;
    while i >= 0 {
        q = q.double();
        let low_index = compose_index(&k.inner, i);
        let high_index = compose_index(&k.inner, i + 16);
        let p1 = &PRE_TABLE_1[low_index as usize];
        let p2 = &PRE_TABLE_2[high_index as usize];
        q = q.add(p1).add(p2);
        i -= 1;
    }
    q
}

//
// P = [k]G
pub fn scalar_mul(m: &BigUint, p: &Point) -> Point {
    mul_naf(m, p)
}

// Montgomery ladder based scalar multiplication (MLSM)
// Input: integer k and point P, m = bit length of k
// 1: Initial: Q1 = Q0 = 0, QT = P, i = 0
// 2: While i < m, do:
// 3: Q1 = Q0 + QT , Q2 = 2QT
// 4: If(ki = 1) Switch(Q0, Q1)
// 5: QT = Q2, i = i + 1
// 6: end While
// TODO fixme: The mlsm_mul cause signature verify failed
pub fn mlsm_mul(k: &BigUint, p: &Point) -> Point {
    let bi = k.to_bytes_be();
    let mut q0 = Point::zero();
    let mut qt = p.clone();
    let mut i = 0;
    while i < bi.len() {
        let q1 = q0.add(&qt);
        let q2 = qt.double();
        if bi[i] & 0x1 == 1 {
            q0 = q1;
        }
        qt = q2;
        i += 1;
    }
    q0
}

fn mul_naf(k: &BigUint, p: &Point) -> Point {
    // 预处理计算
    let p1 = p.clone();
    let p2 = p.double();
    let mut pre_table = vec![];
    for _ in 0..32 {
        pre_table.push(Point::zero());
    }
    let offset = 16;
    pre_table[1 + offset] = p1;
    pre_table[offset - 1] = pre_table[1 + offset].neg();
    for i in 1..8 {
        pre_table[2 * i + offset + 1] = p2.add(&pre_table[2 * i + offset - 1]);
        pre_table[offset - 2 * i - 1] = pre_table[2 * i + offset + 1].neg();
    }

    let k = FieldElement::from_biguint(k).unwrap();
    let mut l = 256;
    let naf = w_naf(&k.inner, 5, &mut l);
    let mut q = Point::zero();
    loop {
        q = q.double();
        if naf[l] != 0 {
            let index = (naf[l] + 16) as usize;
            q = q.add(&pre_table[index]);
        }
        if l == 0 {
            break;
        }
        l -= 1;
    }
    q
}

/// w: 窗口宽度
///
/// NAF（Non-Adjacent Form)）： 非相邻形式的标量点乘算法
// #[inline(always)]
fn w_naf(k: &[u32], w: usize, lst: &mut usize) -> [i8; 257] {
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

fn pre_vec_gen(n: u32) -> [u32; 8] {
    let mut pre_vec: [u32; 8] = [0; 8];
    let mut i = 0;
    while i < 8 {
        pre_vec[7 - i] = (n >> i) & 0x01;
        i += 1;
    }
    pre_vec
}

fn pre_vec_gen2(n: u32) -> [u32; 8] {
    let mut pre_vec: [u32; 8] = [0; 8];
    let mut i = 0;
    while i < 8 {
        pre_vec[7 - i] = ((n >> i) & 0x01) << 16;
        i += 1;
    }
    pre_vec
}

#[cfg(test)]
mod test {
    use crate::p256_ecc::{pre_vec_gen, pre_vec_gen2, scalar_mul, Point, P256C_PARAMS};
    use crate::p256_field::FieldElement;

    #[test]
    fn test_g_table() {
        let mut table_1: Vec<Point> = Vec::new();
        for i in 0..256 {
            let k = FieldElement::from_slice(&pre_vec_gen(i as u32));
            let p1 = scalar_mul(&k.to_biguint(), &P256C_PARAMS.g_point);
            table_1.push(p1);
        }

        let mut table_2: Vec<Point> = Vec::new();
        for i in 0..256 {
            let k = FieldElement::from_slice(&pre_vec_gen2(i as u32));
            let p1 = scalar_mul(&k.to_biguint(), &P256C_PARAMS.g_point);
            table_2.push(p1);
        }

        println!("table_1 = {:?}", table_1);
        println!("table_2 = {:?}", table_2);
    }
}
