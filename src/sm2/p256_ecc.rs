use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::{Num, One};

use crate::sm2::error::{Sm2Error, Sm2Result};
use crate::sm2::formulas::*;
use crate::sm2::key::CompressModle;
use crate::sm2::p256_field::{FieldElement, ECC_P};
use crate::sm2::p256_pre_table::{PRE_TABLE_1, PRE_TABLE_2};

lazy_static! {
    pub static ref P256C_PARAMS: CurveParameters = CurveParameters::new_default();
}

/// ecc equation: y^2 == x^3 +ax + b (mod p)
#[derive(Debug, Clone)]
pub struct CurveParameters {
    /// p：大于3的素数
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

    // r modp
    pub r_p: BigUint,

    // r^2 modn
    pub rr_n: BigUint,

    // r^2 modn
    pub rr_p: BigUint,

    // r^-1 modp
    pub r_inv: BigUint,

    // Calculate the modular inverse of scalar |a| using Fermat's Little
    // Theorem:
    //
    //    a**-1 (mod n) == a**(n - 2) (mod n)
    // so, p_inv_r_neg == -p^-1 modr, ps. p^-1 = p^(r-2) modr
    pub p_inv_r_neg: BigUint,

    // like p_inv_r_neg, n_inv_r_neg == -n^-1 modr, ps. n^-1 = n^(r-2) modr
    pub n_inv_r_neg: BigUint,

    /// r = 2 ^256
    pub r: BigUint,
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
        let p = FieldElement::new(ECC_P);
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

        let r = BigUint::new(vec![2]).pow(256);

        let r_inv = BigUint::from_bytes_be(
            &hex::decode("FFFFFFFB00000005FFFFFFFC00000002FFFFFFFD00000006FFFFFFF900000004")
                .unwrap(),
        );

        let r_p = BigUint::from_str_radix(
            "100000000000000000000000000000000FFFFFFFF0000000000000001",
            16,
        )
        .unwrap();

        let rr_n = BigUint::from_str_radix(
            "1EB5E412A22B3D3B620FC84C3AFFE0D43464504ADE6FA2FA901192AF7C114F20",
            16,
        )
        .unwrap();

        let rr_p = BigUint::from_str_radix(
            "400000002000000010000000100000002FFFFFFFF0000000200000003",
            16,
        )
        .unwrap();

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
            r_p,
            rr_n,
            rr_p,
            r_inv,
            p_inv_r_neg: BigUint::from_bytes_be(
                &hex::decode("FFFFFFFC00000001FFFFFFFE00000000FFFFFFFF000000010000000000000001")
                    .unwrap(),
            ),
            n_inv_r_neg: BigUint::from_bytes_be(
                &hex::decode("6F39132F82E4C7BC2B0068D3B08941D4DF1E8D34FC8319A5327F9E8872350975")
                    .unwrap(),
            ),
            r,
        };
        ctx
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PointModel {
    AFFINE,
    JACOBIAN,
}

#[derive(Debug, Clone, Eq, PartialEq, Copy)]
pub struct Point {
    pub x: FieldElement,
    pub y: FieldElement,
    pub z: FieldElement,
}

impl Point {
    pub fn to_affine(&self) -> Point {
        let z_inv = &self.z.modinv();
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

    pub fn to_byte(&self, compress_modle: CompressModle) -> Vec<u8> {
        let p_affine = self.to_affine();
        let mut x_vec = p_affine.x.to_bytes_be();
        let mut y_vec = p_affine.y.to_bytes_be();
        let mut ret: Vec<u8> = Vec::new();
        match compress_modle {
            CompressModle::Compressed => {
                if y_vec[y_vec.len() - 1] & 0x01 == 0 {
                    ret.push(0x02);
                } else {
                    ret.push(0x03);
                }
                ret.append(&mut x_vec);
            }
            CompressModle::Uncompressed => {
                ret.push(0x04);
                ret.append(&mut x_vec);
                ret.append(&mut y_vec);
            }
            CompressModle::Mixed => {
                if y_vec[y_vec.len() - 1] & 0x01 == 0 {
                    ret.push(0x06);
                } else {
                    ret.push(0x07);
                }
                ret.append(&mut x_vec);
                ret.append(&mut y_vec);
            }
        }
        ret
    }

    pub(crate) fn from_byte(b: &[u8], compress_modle: CompressModle) -> Sm2Result<Point> {
        return match compress_modle {
            CompressModle::Compressed => {
                if b.len() != 33 {
                    return Err(Sm2Error::InvalidPublic);
                }
                let y_q;
                if b[0] == 0x02 {
                    y_q = 0;
                } else if b[0] == 0x03 {
                    y_q = 1
                } else {
                    return Err(Sm2Error::InvalidPublic);
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
            CompressModle::Uncompressed | CompressModle::Mixed => {
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
        };
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

    pub fn is_valid_affine(&self) -> bool {
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
        double_2007_bl(self)
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
const fn compose_k(v: &[u32], i: i32) -> u32 {
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
    let m = m % &P256C_PARAMS.n;
    let k = FieldElement::from_biguint(&m).unwrap();
    let mut q = Point::zero();
    let mut i = 15;
    while i >= 0 {
        q = q.double();
        let k1 = compose_k(&k.inner, i);
        let k2 = compose_k(&k.inner, i + 16);
        let p1 = &PRE_TABLE_1[k1 as usize];
        let p2 = &PRE_TABLE_2[k2 as usize];
        q = q.add(p1).add(p2);
        i -= 1;
    }
    q
}

//
// P = [k]G
pub fn scalar_mul(m: &BigUint, p: &Point) -> Point {
    mul_naf(&m, p)
    // if m.is_one() {
    //     mul_naf(&m, p)
    // } else {
    //     mul_binary(&m, p)
    // }
}

// 二进制展开法
// todo fix 会导致签名验证失败 -- 待修复
pub fn mul_binary(m: &BigUint, p: &Point) -> Point {
    let mut q = Point::zero();
    let mut order = p.clone();
    let k = m.to_bytes_be();
    for k_j in k {
        let mut bit: usize = 0;
        while bit < 8 {
            if (k_j >> bit) & 0x01 != 0 {
                q = q.add(&order);
            }
            order = order.double();
            bit += 1;
        }
    }
    // let mut j = k.len() - 1;
    // while j > 0 {
    //     q = q.double();
    //     if k[j] & 0x01 == 1 {
    //         q = q.add(p);
    //     }
    //     j -= 1;
    // }
    q
}

// 滑动窗法
pub fn mul_naf(m: &BigUint, p: &Point) -> Point {
    let k = FieldElement::from_biguint(m).unwrap();
    let mut l = 256;
    let naf = w_naf(&k.inner, 5, &mut l);

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

    // 主循环
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

//w-naf algorithm
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
    use crate::sm2::p256_ecc::{mul_naf, pre_vec_gen, pre_vec_gen2, Point, P256C_PARAMS};
    use crate::sm2::p256_field::FieldElement;
    use num_bigint::BigUint;
    use num_traits::Num;

    #[test]
    fn test_g_table() {
        let mut table_1: Vec<Point> = Vec::new();
        for i in 0..256 {
            let k = FieldElement::from_slice(&pre_vec_gen(i as u32));
            let p1 = mul_naf(&k.to_biguint(), &P256C_PARAMS.g_point);
            table_1.push(p1);
        }

        let mut table_2: Vec<Point> = Vec::new();
        for i in 0..256 {
            let k = FieldElement::from_slice(&pre_vec_gen2(i as u32));
            let p1 = mul_naf(&k.to_biguint(), &P256C_PARAMS.g_point);
            table_2.push(p1);
        }

        println!("table_1 = {:?}", table_1);
        println!("table_2 = {:?}", table_2);
    }

    #[test]
    fn test_r() {
        let r_1 = BigUint::from_str_radix(
            "010000000000000000000000000000000000000000000000000000000000000000",
            16,
        )
        .unwrap();

        let p = BigUint::from_str_radix(
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
            16,
        )
        .unwrap();

        let n = BigUint::from_str_radix(
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
            16,
        )
        .unwrap();

        let r = BigUint::new(vec![2]).pow(256);
        let rr = r.pow(2);
        println!("r = {:?}", r.to_str_radix(16));
        println!("r1= {:?}", r_1.to_str_radix(16));
        println!("r_p = {:?}", (&r % &p).to_str_radix(16));
        println!("r_n = {:?}", (&r % &n).to_str_radix(16));

        println!("rr_p = {:?}", (&rr % &p).to_str_radix(16));
        println!("rr_n = {:?}", (&rr % &n).to_str_radix(16));
    }
}
