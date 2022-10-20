use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::{FromPrimitive, One};

use crate::sm2::error::{Sm2Error, Sm2Result};
use crate::sm2::key::CompressModle;
use crate::sm2::p256_field::{from_biguint, FieldElement};

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
    pub(crate) h: FieldElement,
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
            h: FieldElement::from_u32(1),
            g_point,
        };
        ctx
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum PointModel {
    AFFINE,
    JACOBIAN,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Point {
    pub x: FieldElement,
    pub y: FieldElement,
    pub z: FieldElement,
}

impl Point {
    pub fn to_affine(&self) -> Point {
        let z_inv = &self.z.modinv();
        let x = &self.x * (z_inv * z_inv);
        let y = &self.y * (z_inv * z_inv * z_inv);
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
                let x = FieldElement::from_bytes_be(&b[1..]);
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
                let x = FieldElement::from_bytes_be(&b[1..33]);
                let y = FieldElement::from_bytes_be(&b[33..65]);
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
            // y^2 = x^3 + a * x * z^4 + b * z^6
            let ecc_p = &P256C_PARAMS.p;
            let yy = &self.y * &self.y;
            let xxx = &self.x * &self.x * &self.x;
            let axz = &P256C_PARAMS.a * &self.x * &self.z.modpow(&BigUint::from_u32(4).unwrap(), ecc_p);
            let bz = &P256C_PARAMS.b * &self.z.modpow(&BigUint::from_u32(6).unwrap(), ecc_p);
            let exp = &xxx + &axz + &bz;
            yy.eq(&exp)
        }
    }

    pub fn is_valid_affine(&self) -> bool {
        // y^2 = x^3 + a * x + b
        let yy = &self.y * &self.y;
        let xxx = &self.x * &self.x * &self.x;
        let ax = &P256C_PARAMS.a * &self.x;
        let b = &P256C_PARAMS.b;
        let exp = &xxx + &ax + b;
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
    /// A.1.2.3.2  Jacobian 加重射影坐标
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

            // let two = &FieldElement::from_u32(2);
            // let three = &FieldElement::from_u32(3);
            // let z1z1 = z1 * z1;
            // let z2z2 = z2 * z2;
            // let lambda1 = x1 * &z2z2;
            // let lambda2 = x2 * &z1z1;
            // let lambda3 = &lambda1 - &lambda2;
            // let lambda4 = y1 * &z2.modpow(three, ecc_p);
            // let lambda5 = y2 * &z1.modpow(three, ecc_p);
            // let lambda6 = &lambda4 - &lambda5;
            // let lambda7 = &lambda1 + &lambda2;
            // let lambda8 = &lambda4 + &lambda5;
            // let x3 = &lambda6.modpow(two, ecc_p) - &lambda7 * &lambda3.modpow(two, ecc_p);
            // let lambda9 = &lambda7 * &lambda3.modpow(two, ecc_p) - &x3 * 2u32;
            // let y3 = (&lambda9 * &lambda6 - &lambda8 * &lambda3.modpow(three, ecc_p))
            //     * FieldElement::from_u32(2).modinv();
            // let z3 = z1 * z2 * &lambda3;

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
pub fn base_mul_point(m: &BigUint, p: &Point) -> Point {
    let m = m % P256C_PARAMS.n.inner();
    if m.is_one() {
        mul_naf(&m, p)
    } else {
        mul_binary(&m, p)
    }
}

// 二进制展开法
pub fn mul_binary(m: &BigUint, p: &Point) -> Point {
    let mut q = Point::zero();
    let k = m.to_bytes_be();
    let mut j = k.len() - 1;
    while j > 0 {
        q = q.double();
        if k[j] & 0x01 == 1 {
            q = q.add(p);
        }
        j -= 1;
    }
    q
}

// 滑动窗口法
pub fn mul_naf(m: &BigUint, p: &Point) -> Point {
    let k = from_biguint(&m);
    let mut i = 256;
    let mut q = Point::zero();
    let naf = w_naf(&k, 5, &mut i);
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
