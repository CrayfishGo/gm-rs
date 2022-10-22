use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::{Num, One};

use crate::sm2::error::{Sm2Error, Sm2Result};
use crate::sm2::key::CompressModle;
use crate::sm2::p256_field::{ECC_P, FieldElement};

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
    // pub r_p: BigUint,

    // r^2 modn
    // pub rr_n: BigUint,

    // r^2 modn
    // pub rr_p: BigUint,
    /// r^-1 modp
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

        let r = BigUint::from_bytes_be(
            &hex::decode("010000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
        );

        let r_inv = BigUint::from_bytes_be(
            &hex::decode("fffffffb00000005fffffffc00000002fffffffd00000006fffffff900000004")
                .unwrap(),
        );

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
            r_inv,
            p_inv_r_neg: BigUint::from_bytes_be(
                &hex::decode("fffffffc00000001fffffffe00000000ffffffff000000010000000000000001")
                    .unwrap(),
            ),
            n_inv_r_neg: BigUint::from_bytes_be(
                &hex::decode("6f39132f82e4c7bc2b0068d3b08941d4df1e8d34fc8319a5327f9e8872350975")
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

    /// see GMT 0003.1-2012
    ///
    /// The "dbl-2007-bl" doubling formulas
    ///
    /// Cost: 1M + 8S + 1*a + 10add + 2*2 + 1*3 + 1*8.
    //       XX = X12
    //       YY = Y12
    //       YYYY = YY2
    //       ZZ = Z12
    //       S = 2*((X1+YY)2-XX-YYYY)
    //       M = 3*XX+a*ZZ2
    //       T = M2-2*S
    //       X3 = T
    //       Y3 = M*(S-T)-8*YYYY
    //       Z3 = (Y1+Z1)2-YY-ZZ
    pub fn double(&self) -> Point {
        let ecc_a = &P256C_PARAMS.a;
        let (x1, y1, z1) = (&self.x, &self.y, &self.z);
        let xx = x1.square();
        let yy = y1.square();
        let zz = z1.square();

        let yyyy = &yy.square();
        let s = ((x1 + &yy).square() - &xx - yyyy).double();
        let m = &xx.double() + &xx + ecc_a * &zz.square();
        let t = &m.square() - &s.double();
        let y3 = &m * (&s - &t) - yyyy.double().double().double();
        let x3 = t;
        let z3 = (y1 + z1).square() - &yy - &zz;
        let p = Point {
            x: x3,
            y: y3,
            z: z3,
        };
        p
    }

    /// see https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-add-1998-cmo-2
    ///
    /// The "add-1998-cmo-2" addition formulas
    ///
    /// Cost: 12M + 4S + 6add + 1*2.
    //       Z1Z1 = Z12
    //       Z2Z2 = Z22
    //       U1 = X1*Z2Z2
    //       U2 = X2*Z1Z1
    //       S1 = Y1*Z2*Z2Z2
    //       S2 = Y2*Z1*Z1Z1
    //       H = U2-U1
    //       HH = H2
    //       HHH = H*HH
    //       r = S2-S1
    //       V = U1*HH
    //       X3 = r2-HHH-2*V
    //       Y3 = r*(V-X3)-S1*HHH
    //       Z3 = Z1*Z2*H
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
            let z1z1 = z1.square();
            let z2z2 = z2.square();
            let u1 = x1 * &z2z2;
            let u2 = x2 * &z1z1;
            let s1 = y1 * z2 * &z2z2;
            let s2 = y2 * z1 * &z1z1;
            let h = &u2 - &u1;

            // let i = h.double().square();
            // let j = &h * &i;
            // let r = (&s2 - &s1).double();
            // let v = &u1 * &i;
            // let x3 = &r.square() - &j - &v.double();
            // let y3 = &r * (&v - &x3) - &s1 * &j.double();
            // let z3 = &h * ((z1 + z2).square() - &z1z1 - z2z2);

            let r = &s2 - &s1;
            let hh = h.square();
            let hhh = &h * &hh;
            let v = &u1 * &hh;
            let x3 = &r.square() - &hhh - &v.double();
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
