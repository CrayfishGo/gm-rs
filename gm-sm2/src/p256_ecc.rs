use crate::error::{Sm2Error, Sm2Result};
use crate::fields::fp64::{fp_sqrt, fp_from_mont, fp_to_mont, SM2_P};
use crate::fields::FieldModOperation;
use crate::sm2p256_table::SM2P256_PRECOMPUTED;
use crate::u256::{u256_from_be_bytes, SM2_ZERO, U256};

#[derive(Debug, Clone, Eq, PartialEq, Copy)]
pub struct Point {
    pub x: U256,
    pub y: U256,
    pub z: U256,
}

impl Point {
    pub fn zero() -> Point {
        Point {
            x: crate::fields::fp64::SM2_MODP_MONT_ONE,
            y: crate::fields::fp64::SM2_MODP_MONT_ONE,
            z: SM2_ZERO,
        }
    }

    pub fn is_zero(&self) -> bool {
        self.z == [0; 4]
    }

    pub fn is_valid(&self) -> bool {
        if self.is_zero() {
            true
        } else {
            // y^2 = x * (x^2 + a * z^4) + b * z^6
            let yy = self.y.fp_sqr();
            let xx = self.x.fp_sqr();
            let z2 = self.z.fp_sqr();
            let z4 = z2.fp_sqr();
            let z6 = z4.fp_mul(&z2);
            let z6_b = z6.fp_mul(&crate::fields::fp64::SM2_MODP_MONT_B);
            let a_z4 = z4.fp_mul(&crate::fields::fp64::SM2_MODP_MONT_A);

            let xx_a_4z = xx.fp_add(&a_z4);
            let xxx_a_4z = xx_a_4z.fp_mul(&self.x);
            let exp = xxx_a_4z.fp_add(&z6_b);
            yy.eq(&exp)
        }
    }

    pub fn is_valid_affine_point(&self) -> bool {
        // y^2 = x * (x^2 + a) + b
        let yy = self.y.fp_sqr();
        let xx = self.x.fp_sqr();
        let xx_a = xx.fp_add(&crate::fields::fp64::SM2_MODP_MONT_A);
        let xxx_a = self.x.fp_mul(&xx_a);
        let exp = xxx_a.fp_add(&crate::fields::fp64::SM2_MODP_MONT_B);
        yy.eq(&exp)
    }

    pub fn to_affine_point(&self) -> Point {
        let z_inv = self.z.fp_inv();
        let z_inv2 = z_inv.fp_sqr();
        let z_inv3 = z_inv2.fp_mul(&z_inv);
        let x = self.x.fp_mul(&z_inv2);
        let y = self.y.fp_mul(&z_inv3);
        Point {
            x,
            y,
            z: crate::fields::fp64::SM2_MODP_MONT_ONE,
        }
    }

    pub fn to_byte_be(&self, compress: bool) -> Vec<u8> {
        let p_affine = self.to_affine_point();
        let mut x_vec = fp_from_mont(&p_affine.x).to_byte_be();
        let mut y_vec = fp_from_mont(&p_affine.y).to_byte_be();
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
            let x = fp_to_mont(&U256::from_byte_be(&b[1..]));
            let xxx = x.fp_mul(&x).fp_mul(&x);
            let ax = x.fp_mul(&crate::fields::fp64::SM2_MODP_MONT_A);
            let yy = xxx
                .fp_add(&ax)
                .fp_add(&crate::fields::fp64::SM2_MODP_MONT_B);

            let mut y = fp_sqrt(&yy)?;
            let y_vec = fp_from_mont(&y).to_byte_be();
            if y_vec[y_vec.len() - 1] & 0x01 != y_q {
                y = SM2_P.fp_sub(&y);
            }
            Ok(Point {
                x,
                y,
                z: crate::fields::fp64::SM2_MODP_MONT_ONE,
            })
        }
        // uncompressed Point
        else {
            if b.len() != 65 {
                return Err(Sm2Error::InvalidPublic);
            }
            let x = fp_to_mont(&u256_from_be_bytes(&b[1..33]));
            let y = fp_to_mont(&u256_from_be_bytes(&b[33..65]));
            Ok(Point {
                x,
                y,
                z: crate::fields::fp64::SM2_MODP_MONT_ONE,
            })
        }
    }

    pub fn neg(&self) -> Point {
        Point {
            x: self.x.clone(),
            y: SM2_P.fp_sub(&self.y),
            z: self.z.clone(),
        }
    }

    pub fn point_add(&self, p: &Point) -> Point {
        // 0 + p2 = p2
        if self.is_zero() {
            return p.clone();
        }
        // p1 + 0 = p1
        if p.is_zero() {
            return self.clone();
        }

        let x1 = self.x;
        let y1 = self.y;
        let z1 = self.z;

        let x2 = p.x;
        let y2 = p.y;
        let z2 = p.z;

        // p1 = p2
        if x1 == x2 && y1 == y2 && z1 == z2 {
            return self.point_dbl();
        } else {
            let z1_sqr = z1.fp_sqr();
            let z2_sqr = z2.fp_sqr();
            let u1 = x1.fp_mul(&z2_sqr);
            let u2 = x2.fp_mul(&z1_sqr);
            let y1_z2 = y1.fp_mul(&z2);
            let s1 = y1_z2.fp_mul(&z2_sqr);
            let y2_z1 = y2.fp_mul(&z1);
            let s2 = y2_z1.fp_mul(&z1_sqr);
            let h = u2.fp_sub(&u1);
            let r = s2.fp_sub(&s1);
            let hh = h.fp_sqr();
            let hhh = hh.fp_mul(&h);
            let v = u1.fp_mul(&hh);
            let r_sqr = r.fp_sqr();
            let r_sqr_hhh = r_sqr.fp_sub(&hhh);
            let x3 = r_sqr_hhh.fp_sub(&v.fp_double());
            let v_x3 = v.fp_sub(&x3);
            let r_v_x3 = r.fp_mul(&v_x3);
            let s1_hhh = s1.fp_mul(&hhh);
            let y3 = r_v_x3.fp_sub(&s1_hhh);
            let z3 = z1.fp_mul(&z2).fp_mul(&h);
            Point {
                x: x3,
                y: y3,
                z: z3,
            }
        }
    }

    // P = [k]G
    pub fn scalar_mul(&self, scalar: &[u64]) -> Point {
        let mut pre_table = vec![];
        for _ in 0..16 {
            pre_table.push(Point::zero());
        }

        let mut r = Point::zero();
        pre_table[1 - 1] = *self;
        pre_table[2 - 1] = pre_table[1 - 1].point_dbl();
        pre_table[4 - 1] = pre_table[2 - 1].point_dbl();
        pre_table[8 - 1] = pre_table[4 - 1].point_dbl();
        pre_table[3 - 1] = pre_table[1 - 1].point_add(&pre_table[2 - 1]);
        pre_table[6 - 1] = pre_table[3 - 1].point_dbl();
        pre_table[7 - 1] = pre_table[1 - 1].point_add(&pre_table[6 - 1]);
        pre_table[12 - 1] = pre_table[6 - 1].point_dbl();
        pre_table[5 - 1] = pre_table[1 - 1].point_add(&pre_table[4 - 1]);
        pre_table[10 - 1] = pre_table[5 - 1].point_dbl();
        pre_table[14 - 1] = pre_table[7 - 1].point_dbl();
        pre_table[9 - 1] = pre_table[1 - 1].point_add(&pre_table[8 - 1]);
        pre_table[11 - 1] = pre_table[1 - 1].point_add(&pre_table[10 - 1]);
        pre_table[13 - 1] = pre_table[1 - 1].point_add(&pre_table[12 - 1]);
        pre_table[15 - 1] = pre_table[1 - 1].point_add(&pre_table[14 - 1]);

        for i in 0..scalar.len() {
            for j in 0..(64 / 4) {
                let index = scalar[4 - 1 - i] >> ((64 / 4 - 1 - j) * 4);
                if index & 0x0f != 0 {
                    r = pre_table[((index - 1) & 0x0f) as usize].point_add(&r)
                }

                if i + 1 == scalar.len() && j + 1 == 64 / 4 {
                    break;
                }
                r = r.point_dbl();
                r = r.point_dbl();
                r = r.point_dbl();
                r = r.point_dbl();
            }
        }
        r
    }

    pub fn point_dbl(&self) -> Point {
        let x1 = self.x;
        let y1 = self.y;
        let z1 = self.z;

        let z1_sqr = z1.fp_sqr(); // z1^2
        let y1_sqr = y1.fp_sqr(); // y1^2
        let alpha_m3 = x1.fp_sub(&z1_sqr).fp_mul(&x1.fp_add(&z1_sqr)).fp_triple(); // 3(x1-delta)*(x1+delta)
        let lam6_m4 = x1.fp_mul(&y1_sqr).fp_double().fp_double(); // 4(x1*(y1^2))
        let x3 = alpha_m3.fp_sqr().fp_sub(&lam6_m4.fp_double()); // x3=alpha^2 - 8(x1*(y1^2))

        let u1 = alpha_m3.fp_mul(&lam6_m4.fp_sub(&x3)); // alpha * (4(x1*(y1^2)) - x3)
        let u2 = y1_sqr.fp_sqr().fp_double().fp_double().fp_double(); // 8y1^4
        let y3 = u1.fp_sub(&u2);

        let y1_z1 = y1.fp_add(&z1);
        let z3 = y1_z1.fp_sqr().fp_sub(&y1_sqr).fp_sub(&z1_sqr);

        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }
}

pub fn g_mul(g: &U256) -> Point {
    let mut r = Point::zero();
    let num = 8;
    for (index, scalar_word) in g.iter().enumerate() {
        for m in 0..num {
            let raw_index = ((scalar_word >> (8 * m)) & 0xff) as usize;
            if raw_index != 0 {
                let a = to_jacobi(
                    &SM2P256_PRECOMPUTED[num * index + m][raw_index * 2 - 2],
                    &SM2P256_PRECOMPUTED[num * index + m][raw_index * 2 - 1],
                );
                r = r.point_add(&a);
            }
        }
    }
    r
}

pub(crate) fn to_jacobi(x: &U256, y: &U256) -> Point {
    let mut r = Point::zero();
    r.x.copy_from_slice(x);
    r.y.copy_from_slice(y);
    r.z.copy_from_slice(&crate::fields::fp64::SM2_MODP_MONT_ONE);
    r
}

#[cfg(test)]
mod test {
    use crate::fields::fp64::fp_to_mont;
    use crate::p256_ecc::{g_mul, to_jacobi, Point};
    use crate::u256::u256_from_be_bytes;

    #[test]
    fn test_mod_op() {
        // Point at Infinity (1:1:0)
        let p = Point {
            x: u256_from_be_bytes(
                &hex::decode("0000000100000000000000000000000000000000ffffffff0000000000000001")
                    .unwrap(),
            ),
            y: u256_from_be_bytes(
                &hex::decode("0000000100000000000000000000000000000000ffffffff0000000000000001")
                    .unwrap(),
            ),
            z: u256_from_be_bytes(
                &hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                    .unwrap(),
            ),
        };
        println!("is_valid = {}", p.is_valid());
        println!("is_valid_affine_point = {}", p.is_valid_affine_point());
        println!();

        // Affine Point [1]G with Montgomery Coordinates
        let p = Point {
            x: u256_from_be_bytes(
                &hex::decode("91167a5ee1c13b05d6a1ed99ac24c3c33e7981eddca6c05061328990f418029e")
                    .unwrap(),
            ),
            y: u256_from_be_bytes(
                &hex::decode("63cd65d481d735bd8d4cfb066e2a48f8c1f5e5788d3295fac1354e593c2d0ddd")
                    .unwrap(),
            ),
            z: u256_from_be_bytes(
                &hex::decode("0000000100000000000000000000000000000000ffffffff0000000000000001")
                    .unwrap(),
            ),
        };
        println!("is_valid = {}", p.is_valid());
        println!("is_valid_affine_point = {}", p.is_valid_affine_point());
        println!();

        // Jacobian Point [2]G with Montgomery Coordinates
        let p = Point {
            x: u256_from_be_bytes(
                &hex::decode("398874c476a3b1f77aef3e862601440903243d78d5b614a62eda8381e63c48d6")
                    .unwrap(),
            ),
            y: u256_from_be_bytes(
                &hex::decode("1fbbdfdddaf4fd475a86a7ae64921d4829f04a88f6cf4dc128385681c1a73e40")
                    .unwrap(),
            ),
            z: u256_from_be_bytes(
                &hex::decode("c79acba903ae6b7b1a99f60cdc5491f183ebcaf11a652bf5826a9cb2785a1bba")
                    .unwrap(),
            ),
        };

        println!("is_valid = {}", p.is_valid());
        println!(
            "is_valid_affine_point = {}",
            p.to_affine_point().is_valid_affine_point()
        );
        println!();

        let scalar: &[u64; 4] = &[
            0xfffff8950000053b,
            0xfffffdc600000543,
            0xfffffb8c00000324,
            0xfffffc4d0000064e,
        ];

        let p = g_mul(&scalar);
        println!("is_valid = {}", p.is_valid());
        println!(
            "is_valid_affine_point = {}",
            p.to_affine_point().is_valid_affine_point()
        );
        println!();

        let scalar: &[u64; 4] = &[
            0xd89cdf6229c4bddf,
            0xacf005cd78843090,
            0xe5a220abf7212ed6,
            0xdc30061d04874834,
        ];

        let g_x: &[u64; 4] = &[
            0x715a4589334c74c7,
            0x8fe30bbff2660be1,
            0x5f9904466a39c994,
            0x32c4ae2c1f198119,
        ];
        let g_y: &[u64; 4] = &[
            0x02df32e52139f0a0,
            0xd0a9877cc62a4740,
            0x59bdcee36b692153,
            0xbc3736a2f4f6779c,
        ];
        let mont_g_x = fp_to_mont(&g_x);
        let mont_g_y = fp_to_mont(&g_y);
        let pro_mont_point_g = to_jacobi(&mont_g_x, &mont_g_y);

        let r = pro_mont_point_g.scalar_mul(scalar);
        println!("is_valid = {}", r.is_valid());
        println!(
            "is_valid_affine_point = {}",
            r.to_affine_point().is_valid_affine_point()
        );
    }
}
