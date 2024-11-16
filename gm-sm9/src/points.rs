use crate::fields::fp::{fp_from_bytes, fp_from_hex, Fp};
use crate::fields::fp12::Fp12;
use crate::fields::fp2::Fp2;
use crate::fields::FieldElement;
use crate::sm9_p256_table::SM9_P256_PRECOMPUTED;
use crate::u256::{sm9_u256_get_booth, u256_cmp, u256_to_bits, SM9_ZERO, U256};
use crate::SM9_MODP_MONT_ONE;

#[derive(Copy, Debug, Clone)]
pub struct Point {
    pub(crate) x: Fp,
    pub(crate) y: Fp,
    pub(crate) z: Fp,
}

impl Point {
    pub(crate) fn from_bytes(b: &[u8]) -> Self {
        let x = fp_from_bytes(&b[1..33]);
        let y = fp_from_bytes(&b[33..65]);
        Self {
            x,
            y,
            z: SM9_MODP_MONT_ONE,
        }
    }

    pub fn to_bytes_be(&self) -> Vec<u8> {
        let mut ppend: Vec<u8> = vec![];
        let p = self.to_affine_point();
        ppend.push(0x04); // uncompress point
        ppend.extend_from_slice(&p.x.to_bytes_be());
        ppend.extend_from_slice(&p.y.to_bytes_be());
        ppend
    }
}

#[derive(Copy, Debug, Clone)]
pub struct TwistPoint {
    pub(crate) x: Fp2,
    pub(crate) y: Fp2,
    pub(crate) z: Fp2,
}

impl TwistPoint {
    pub(crate) fn point_pi1(&self) -> TwistPoint {
        // c = 0x3f23ea58e5720bdb843c6cfa9c08674947c5c86e0ddd04eda91d8354377b698b
        // mont version c
        let c: U256 = [
            0x1a98dfbd4575299f,
            0x9ec8547b245c54fd,
            0xf51f5eac13df846c,
            0x9ef74015d5a16393,
        ];
        let x = self.x.conjugate();
        let y = self.y.conjugate();
        let mut z = self.z.conjugate();
        z = z.fp_mul_fp(&c);
        Self { x, y, z }
    }

    pub(crate) fn point_neg_pi2(&self) -> TwistPoint {
        // c = 0xf300000002a3a6f2780272354f8b78f4d5fc11967be65334
        // mont version c
        let c: U256 = [
            0xb626197dce4736ca,
            0x8296b3557ed0186,
            0x9c705db2fd91512a,
            0x1c753e748601c992,
        ];
        let x = self.x;
        let y = self.y.fp_neg();
        let mut z = self.z.fp_mul_fp(&c);
        Self { x, y, z }
    }
}

// 群 G1的生成元 P1 = (xP1 , yP1);
// P1.X 0x93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD
// P1.Y 0x21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616
const G1: Point = Point {
    x: [
        0xe8c4e4817c66dddd,
        0xe1e4086909dc3280,
        0xf5ed0704487d01d6,
        0x93de051d62bf718f,
    ],
    y: [
        0x0c464cd70a3ea616,
        0x1c1c00cbfa602435,
        0x631065125c395bbc,
        0x21fe8dda4f21e607,
    ],
    z: [1, 0, 0, 0],
};

/*
    X : [0x3722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65b,
         0x85aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d8806141],
    Y : [0xa7cf28d519be3da65f3170153d278ff247efba98a71a08116215bba5c999a7c7,
         0x17509b092e845c1266ba0d262cbee6ed0736a96fa347c8bd856dc76b84ebeb96],
    Z : [1n, 0n],
*/
// 群 G2的生成元 P2 = (xP2, yP2)：
const G2: TwistPoint = TwistPoint {
    x: Fp2 {
        c0: [
            0xF9B7213BAF82D65B,
            0xEE265948D19C17AB,
            0xD2AAB97FD34EC120,
            0x3722755292130B08,
        ],
        c1: [
            0x54806C11D8806141,
            0xF1DD2C190F5E93C4,
            0x597B6027B441A01F,
            0x85AEF3D078640C98,
        ],
    },

    y: Fp2 {
        c0: [
            0x6215BBA5C999A7C7,
            0x47EFBA98A71A0811,
            0x5F3170153D278FF2,
            0xA7CF28D519BE3DA6,
        ],
        c1: [
            0x856DC76B84EBEB96,
            0x0736A96FA347C8BD,
            0x66BA0D262CBEE6ED,
            0x17509B092E845C12,
        ],
    },

    z: Fp2 {
        c0: [1, 0, 0, 0],
        c1: [0, 0, 0, 0],
    },
};

pub const SM9_U256_PPUBS: TwistPoint = TwistPoint {
    x: Fp2 {
        c0: [
            0x8F14D65696EA5E32,
            0x414D2177386A92DD,
            0x6CE843ED24A3B573,
            0x29DBA116152D1F78,
        ],
        c1: [
            0x0AB1B6791B94C408,
            0x1CE0711C5E392CFB,
            0xE48AFF4B41B56501,
            0x9F64080B3084F733,
        ],
    },

    y: Fp2 {
        c0: [
            0x0E75C05FB4E3216D,
            0x1006E85F5CDFF073,
            0x1A7CE027B7A46F74,
            0x41E00A53DDA532DA,
        ],
        c1: [
            0xE89E1408D0EF1C25,
            0xAD3E2FDB1A77F335,
            0xB57329F447E3A0CB,
            0x69850938ABEA0112,
        ],
    },

    z: Fp2 {
        c0: [1, 0, 0, 0],
        c1: [0, 0, 0, 0],
    },
};

const SM9_U256_MONT_G2: TwistPoint = TwistPoint {
    x: Fp2 {
        c0: [
            0x260226a68ce2da8f,
            0x7ee5645edbf6c06b,
            0xf8f57c82b1495444,
            0x61fcf018bc47c4d1,
        ],
        c1: [
            0xdb6db4822750a8a6,
            0x84c6135a5121f134,
            0x1874032f88791d41,
            0x905112f2b85f3a37,
        ],
    },

    y: Fp2 {
        c0: [
            0xc03f138f9171c24a,
            0x92fbab45a15a3ca7,
            0x2445561e2ff77cdb,
            0x108495e0c0f62ece,
        ],
        c1: [
            0xf7b82dac4c89bfbb,
            0x3706f3f6a49dc12f,
            0x1e29de93d3eef769,
            0x81e448c3c76a5d53,
        ],
    },

    z: Fp2 {
        c0: [
            0x1a9064d81caeba83,
            0xde0d6cb4e5851124,
            0x29fc54b00a7138ba,
            0x49bffffffd5c590e,
        ],
        c1: [0, 0, 0, 0],
    },
};

impl Point {
    pub fn from_hex(data: [&str; 2]) -> Self {
        Self {
            x: fp_from_hex(&data[0]),
            y: fp_from_hex(&data[1]),
            z: Fp::one(),
        }
    }

    pub fn zero() -> Self {
        Self {
            x: Fp::one(),
            y: Fp::one(),
            z: Fp::zero(),
        }
    }

    pub fn to_affine_point(&self) -> Point {
        if u256_cmp(&self.z, &SM9_MODP_MONT_ONE) == 0 {
            Point {
                x: self.x,
                y: self.y,
                z: Fp::one(),
            }
        } else {
            let mut z_inv = self.z.fp_inv();
            let mut y = self.y.fp_mul(&z_inv);
            z_inv = z_inv.fp_sqr();
            let x = self.x.fp_mul(&z_inv);
            y = y.fp_mul(&z_inv);
            Point { x, y, z: Fp::one() }
        }
    }

    pub fn point_equals(&self, rhs: &Self) -> bool {
        let (mut t1, mut t2, mut t3, mut t4) =
            (U256::zero(), U256::zero(), U256::zero(), U256::zero());
        t1 = self.z.fp_sqr();
        t2 = rhs.z.fp_sqr();
        t3 = self.x.fp_mul(&t2);
        t4 = rhs.x.fp_mul(&t1);
        if u256_cmp(&t3, &t4) != 0 {
            return false;
        }

        t1 = t1.fp_mul(&self.z);
        t2 = t2.fp_mul(&rhs.z);
        t3 = self.y.fp_mul(&t2);
        t4 = rhs.y.fp_mul(&t1);
        if u256_cmp(&t3, &t4) == 0 {
            return true;
        }
        false
    }

    pub fn is_zero(&self) -> bool {
        self.z.is_zero()
    }

    pub fn point_double(&self) -> Self {
        if self.is_zero() {
            return self.clone();
        }
        let mut x1 = self.x;
        let mut y1 = self.y;
        let z1 = self.z;

        let mut t1 = Fp::zero();
        let mut t2 = Fp::zero();
        let mut t3 = Fp::zero();

        let mut x3 = Fp::zero();
        let mut y3 = Fp::zero();
        let mut z3 = Fp::zero();

        t2 = x1.fp_sqr();
        t2 = t2.fp_triple();
        y3 = y1.fp_double();
        z3 = y3.fp_mul(&z1);
        y3 = y3.fp_sqr();
        t3 = y3.fp_mul(&x1);
        y3 = y3.fp_sqr();
        y3 = y3.fp_div2();
        x3 = t2.fp_sqr();

        t1 = t3.fp_double();
        x3 = x3.fp_sub(&t1);
        t1 = t3.fp_sub(&x3);
        t1 = t1.fp_mul(&t2);
        y3 = t1.fp_sub(&y3);

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    pub fn point_add(&self, rhs: &Self) -> Self {
        if rhs.is_zero() {
            return self.clone();
        }

        if self.is_zero() {
            return rhs.clone();
        }

        let x1 = self.x;
        let y1 = self.y;
        let z1 = self.z;

        let x2 = rhs.x;
        let y2 = rhs.y;
        let z2 = rhs.z;

        let mut t1 = z1.fp_sqr();
        let mut t2 = z2.fp_sqr();
        let u1 = x1.fp_mul(&t2);
        let mut u2 = x2.fp_mul(&t1);
        let mut z3 = z1.fp_add(&z2);
        z3 = z3.fp_sqr();
        z3 = z3.fp_sub(&t1);
        z3 = z3.fp_sub(&t2);
        t1 = t1.fp_mul(&z1);
        t2 = t2.fp_mul(&z2);
        let mut s1 = y1.fp_mul(&t2);
        let mut s2 = y2.fp_mul(&t1);
        let mut h = u2.fp_sub(&u1);
        u2 = s2.fp_sub(&s1);

        if h == SM9_ZERO {
            return if u2 == SM9_ZERO {
                rhs.point_double()
            } else {
                Point::zero()
            };
        }

        z3 = z3.fp_mul(&h);
        let mut i = h.fp_double();
        i = i.fp_sqr();
        h = h.fp_mul(&i);
        i = u1.fp_mul(&i);
        u2 = u2.fp_double();
        let mut x3 = u2.fp_sqr();
        x3 = h.fp_sub(&x3);
        let mut y3 = i.fp_triple();
        x3 = y3.fp_add(&x3);
        y3 = u2.fp_mul(&x3);
        s1 = s1.fp_mul(&h);
        s1 = s1.fp_double();
        y3 = y3.fp_sub(&s1);
        x3 = i.fp_sub(&x3);

        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    pub fn point_sub(&self, rhs: &Self) -> Self {
        let t = rhs.point_neg();
        self.point_add(&t)
    }

    pub fn point_neg(&self) -> Self {
        Point {
            x: self.x.clone(),
            y: self.y.fp_neg().clone(),
            z: self.z.clone(),
        }
    }

    pub fn point_double_x5(&self) -> Self {
        let mut r = self.point_double();
        r = r.point_double();
        r = r.point_double();
        r = r.point_double();
        r = r.point_double();
        r
    }

    pub fn point_mul(&self, k: &[u64]) -> Self {
        let mut pre_table = vec![];
        for _ in 0..16 {
            pre_table.push(Point::zero());
        }
        let window_size = 5u64;
        let n = (256 + window_size - 1) / window_size;
        pre_table[0] = *self;
        pre_table[2 - 1] = pre_table[1 - 1].point_double();
        pre_table[4 - 1] = pre_table[2 - 1].point_double();
        pre_table[8 - 1] = pre_table[4 - 1].point_double();
        pre_table[16 - 1] = pre_table[8 - 1].point_double();

        pre_table[3 - 1] = pre_table[2 - 1].point_add(self);
        pre_table[6 - 1] = pre_table[3 - 1].point_double();
        pre_table[12 - 1] = pre_table[6 - 1].point_double();

        pre_table[5 - 1] = pre_table[3 - 1].point_add(&pre_table[2 - 1]);
        pre_table[10 - 1] = pre_table[5 - 1].point_double();

        pre_table[7 - 1] = pre_table[4 - 1].point_add(&pre_table[3 - 1]);
        pre_table[14 - 1] = pre_table[7 - 1].point_double();

        pre_table[9 - 1] = pre_table[4 - 1].point_add(&pre_table[5 - 1]);
        pre_table[11 - 1] = pre_table[6 - 1].point_add(&pre_table[5 - 1]);
        pre_table[13 - 1] = pre_table[7 - 1].point_add(&pre_table[6 - 1]);
        pre_table[15 - 1] = pre_table[8 - 1].point_add(&pre_table[7 - 1]);

        let mut r = Point::zero();
        let mut r_infinity = true;
        for i in (0..n).rev() {
            let booth = sm9_u256_get_booth(k, window_size, i);
            if r_infinity {
                if booth != 0 {
                    r = pre_table[(booth - 1) as usize];
                    r_infinity = false;
                }
            } else {
                r = r.point_double_x5();
                if booth > 0 {
                    r = r.point_add(&pre_table[(booth - 1) as usize])
                } else if booth < 0 {
                    r = r.point_sub(&pre_table[(-booth - 1) as usize])
                }
            }
        }

        if r_infinity {
            r = Point::zero();
        }
        r
    }

    pub fn to_jacobi(&self) -> Self {
        Self {
            x: self.x,
            y: self.y,
            z: Fp::one(),
        }
    }

    pub fn g_mul(k: &[u64]) -> Point {
        let mut pre_com_points: Vec<Vec<Point>> = vec![];
        let p = &SM9_P256_PRECOMPUTED;
        for i in 0..p.len() {
            let mut points = vec![];
            let p1 = p[i];
            for j in 0..(p1.len() / 2) {
                points.push(Point {
                    x: p1[j * 2],
                    y: p1[j * 2 + 1],
                    z: Fp::one(),
                })
            }
            pre_com_points.push(points);
        }

        let mut r = Point::zero();
        let window_size = 7u64;
        let mut r_infinity = true;
        let n = (256 + window_size - 1) / window_size;
        for i in (0..n).rev() {
            let booth = sm9_u256_get_booth(&k, window_size, i);
            if r_infinity {
                if booth != 0 {
                    r = pre_com_points[i as usize][(booth - 1) as usize];
                    r_infinity = false;
                }
            } else {
                if booth > 0 {
                    let p = pre_com_points[i as usize][(booth - 1) as usize];
                    r = r.point_add(&p);
                } else if booth < 0 {
                    let p = pre_com_points[i as usize][(-booth - 1) as usize];
                    r = r.point_sub(&p);
                }
            }
        }
        r
    }
}

impl TwistPoint {
    pub fn from_hex(x_data: [&str; 2], y_data: [&str; 2]) -> Self {
        Self {
            x: Fp2::from_hex(x_data),
            y: Fp2::from_hex(y_data),
            z: Fp2::one(),
        }
    }

    pub fn zero() -> Self {
        Self {
            x: Fp2::one(),
            y: Fp2::one(),
            z: Fp2::zero(),
        }
    }

    pub fn point_equals(&self, rhs: &Self) -> bool {
        let (mut t1, mut t2, mut t3, mut t4) = (Fp2::zero(), Fp2::zero(), Fp2::zero(), Fp2::zero());

        t1 = self.z.fp_sqr();
        t2 = rhs.z.fp_sqr();
        t3 = self.x.fp_mul(&t2);
        t4 = rhs.x.fp_mul(&t1);

        if t3.eq(&t4) {
            return true;
        }

        t1 = t1.fp_mul(&self.z);
        t2 = t2.fp_mul(&rhs.z);

        t3 = self.y.fp_mul(&t2);
        t4 = rhs.y.fp_mul(&t1);
        t3.eq(&t4)
    }

    pub fn point_double(&self) -> Self {
        if self.z.is_zero() {
            return self.clone();
        }

        let x1 = self.x;
        let y1 = self.y;
        let z1 = self.z;

        let mut t2 = x1.fp_sqr().fp_triple();
        let mut y3 = y1.fp_double();
        let mut z3 = y3.fp_mul(&z1);
        y3 = y3.fp_sqr();
        let t3 = y3.fp_mul(&x1);
        y3 = y3.fp_sqr();
        y3 = y3.fp_div2();

        let mut x3 = t2.fp_sqr();
        let mut t1 = t3.fp_double();
        x3 = x3.fp_sub(&t1);
        t1 = t3.fp_sub(&x3);

        t1 = t1.fp_mul(&t2);
        y3 = t1.fp_sub(&y3);

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    pub fn point_add(&self, rhs: &Self) -> Self {
        let x1 = self.x;
        let y1 = self.y;
        let z1 = self.z;

        let x2 = rhs.x;
        let y2 = rhs.y;
        let z2 = rhs.z;

        if z1.is_zero() {
            return rhs.clone();
        }

        if z2.is_zero() {
            return self.clone();
        }

        let mut t1 = z1.fp_sqr();
        let mut t2 = t1.fp_mul(&z1);

        t1 = t1.fp_mul(&x2);
        t2 = t2.fp_mul(&y2);
        t1 = t1.fp_sub(&x1);
        t2 = t2.fp_sub(&y1);

        if t1.is_zero() {
            return if t2.is_zero() {
                rhs.point_double()
            } else {
                TwistPoint::zero()
            };
        }

        let mut z3 = z1.fp_mul(&t1);
        let mut t3 = t1.fp_sqr();
        let mut t4 = t3.fp_mul(&t1);
        t3 = t3.fp_mul(&x1);
        t1 = t3.fp_double();
        let mut x3 = t2.fp_sqr();
        x3 = x3.fp_sub(&t1);
        x3 = x3.fp_sub(&t4);
        t3 = t3.fp_sub(&x3);
        t3 = t3.fp_mul(&t2);
        t4 = t4.fp_mul(&y1);
        let y3 = t3.fp_sub(&t4);

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    pub fn point_sub(&self, rhs: &Self) -> Self {
        let t = rhs.point_neg();
        twist_point_add_full(self, &t)
    }

    pub fn point_neg(&self) -> Self {
        TwistPoint {
            x: self.x.clone(),
            y: self.y.fp_neg().clone(),
            z: self.z.clone(),
        }
    }

    pub fn point_mul(&self, k: &U256) -> Self {
        let bits = u256_to_bits(*k);
        let mut r = TwistPoint::zero();
        for i in 0..256 {
            r = r.point_double();
            if bits[i] == '1' {
                r = twist_point_add_full(&r, self)
            }
        }
        r
    }

    pub fn g_mul(k: &U256) -> TwistPoint {
        SM9_U256_MONT_G2.point_mul(k)
    }
}

pub(crate) fn twist_point_add_full(p1: &TwistPoint, p2: &TwistPoint) -> TwistPoint {
    let x1 = p1.x;
    let y1 = p1.y;
    let z1 = p1.z;
    let x2 = p2.x;
    let y2 = p2.y;
    let z2 = p2.z;

    if z1.is_zero() {
        return p2.clone();
    }

    if z2.is_zero() {
        return p1.clone();
    }

    let mut t1 = z1.fp_sqr();
    let mut t2 = z2.fp_sqr();
    let mut t3 = x2.fp_mul(&t1);
    let mut t4 = x1.fp_mul(&t2);
    let mut t5 = t3.fp_add(&t4);
    t3 = t3.fp_sub(&t4);
    t1 = t1.fp_mul(&z1);
    t1 = t1.fp_mul(&y2);
    t2 = t2.fp_mul(&z2);
    t2 = t2.fp_mul(&y1);
    let mut t6 = t1.fp_add(&t2);
    t1 = t1.fp_sub(&t2);

    if t1.is_zero() && t3.is_zero() {
        return p1.point_double();
    }

    if t1.is_zero() && t6.is_zero() {
        return TwistPoint::zero();
    }

    t6 = t1.fp_sqr();
    let mut t7 = t3.fp_mul(&z1);
    t7 = t7.fp_mul(&z2);
    let t8 = t3.fp_sqr();
    t5 = t5.fp_mul(&t8);
    t3 = t3.fp_mul(&t8);
    t4 = t4.fp_mul(&t8);
    t6 = t6.fp_sub(&t5);
    t4 = t4.fp_sub(&t6);
    t1 = t1.fp_mul(&t4);
    t2 = t2.fp_mul(&t3);
    t1 = t1.fp_sub(&t2);

    TwistPoint {
        x: t6,
        y: t1,
        z: t7,
    }
}

pub(crate) fn sm9_u256_pairing(q: &TwistPoint, p: &Point) -> Fp12 {
    let abits: Vec<char> = "00100000000000000000000000000000000000010000101100020200101000020"
        .chars()
        .collect();

    let mut pre: [Fp2; 5] = [Fp2::zero(); 5];
    let mut t = TwistPoint {
        x: q.x.clone(),
        y: q.y.clone(),
        z: q.z.clone(),
    };

    let mut lw: [Fp2; 3] = [Fp2::zero(); 3];

    let p_affine = p.to_affine_point();
    let mut q1 = q.point_neg();

    pre[0] = q.y.fp_sqr();
    pre[4] = q.x.fp_mul(&q.z);
    pre[4] = pre[4].fp_double();
    pre[1] = q.z.fp_sqr();
    pre[1] = q.z.fp_mul(&pre[1]);
    pre[2] = pre[1].fp_mul_fp(&p_affine.y);
    pre[2] = pre[2].fp_double();
    pre[3] = pre[1].fp_mul_fp(&p_affine.x);
    pre[3] = pre[3].fp_double();
    pre[3] = pre[3].fp_neg();
    let mut r = Fp12::one();
    for i in 0..abits.len() {
        r = r.fp_sqr();
        t = sm9_u256_eval_g_tangent(&mut lw, &t, &p_affine);
        r = r.fp_line_mul(&lw);
        if abits[i] == '1' {
            t = sm9_u256_eval_g_line(&mut lw, &pre, &t, &q, &p_affine);
            r = r.fp_line_mul(&lw);
        } else if abits[i] == '2' {
            t = sm9_u256_eval_g_line(&mut lw, &pre, &t, &q1, &p_affine);
            r = r.fp_line_mul(&lw);
        }
    }

    q1 = q.point_pi1();
    let q2 = q.point_neg_pi2();
    t = sm9_u256_eval_g_line_no_pre(&mut lw, &t, &q1, &p_affine);
    r = r.fp_line_mul(&lw);

    t = sm9_u256_eval_g_line_no_pre(&mut lw, &t, &q2, &p_affine);
    r = r.fp_line_mul(&lw);

    r = r.final_exponent();
    r
}

pub(crate) fn sm9_u256_eval_g_line_no_pre(
    lw: &mut [Fp2; 3],
    p: &TwistPoint,
    t: &TwistPoint,
    q: &Point,
) -> TwistPoint {
    let x1 = p.x;
    let y1 = p.y;
    let z1 = p.z;
    let x2 = t.x;
    let y2 = t.y;
    let z2 = t.z;

    let mut pre: [Fp2; 5] = [Fp2::zero(); 5];
    pre[0] = t.y.fp_sqr();
    pre[4] = t.x.fp_mul(&t.z);
    pre[4] = pre[4].fp_double();
    pre[1] = t.z.fp_sqr();
    pre[1] = pre[1].fp_mul(&t.z);
    pre[2] = pre[1].fp_mul_fp(&q.y);
    pre[2] = pre[2].fp_double();
    pre[3] = pre[1].fp_mul_fp(&q.x);
    pre[3] = pre[3].fp_double();
    pre[3] = pre[3].fp_neg();

    let mut t1 = z1.fp_sqr();
    let mut t2 = z2.fp_sqr();
    let mut z3 = z1.fp_add(&z2);
    z3 = z3.fp_sqr();
    z3 = z3.fp_sub(&t1);
    z3 = z3.fp_sub(&t2);

    let mut a = x1.fp_mul(&t2);
    let mut b = x2.fp_mul(&t1);
    let mut c = y1.fp_mul(&pre[1]);
    c = c.fp_double();
    let mut d = y2.fp_add(&z1);
    d = d.fp_sqr();
    d = d.fp_sub(&pre[0]);
    d = d.fp_sub(&t1);
    d = d.fp_mul(&t1);
    b = b.fp_sub(&a);

    z3 = z3.fp_mul(&b);
    t1 = b.fp_double();
    t1 = t1.fp_sqr();

    let mut x3 = b.fp_mul(&t1);
    let mut y3 = c.fp_mul(&x3);
    a = a.fp_mul(&t1);
    b = d.fp_sub(&c);
    t2 = a.fp_double();
    x3 = x3.fp_add(&t2);
    t2 = b.fp_sqr();
    x3 = t2.fp_sub(&x3);
    t2 = a.fp_sub(&x3);
    t2 = t2.fp_mul(&b);
    y3 = t2.fp_sub(&y3);

    lw[2] = z3.fp_mul(&pre[2]);
    lw[1] = b.fp_mul(&pre[3]);
    b = b.fp_mul(&pre[4]);

    lw[0] = y2.fp_mul(&z3);
    lw[0] = lw[0].fp_double();
    lw[0] = b.fp_sub(&lw[0]);
    TwistPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

pub(crate) fn sm9_u256_eval_g_line(
    lw: &mut [Fp2; 3],
    pre: &[Fp2; 5],
    p: &TwistPoint,
    t: &TwistPoint,
    q: &Point,
) -> TwistPoint {
    let x1 = p.x;
    let y1 = p.y;
    let z1 = p.z;
    let x2 = t.x;
    let y2 = t.y;
    let z2 = t.z;

    let mut t1 = z1.fp_sqr();
    let mut t2 = z2.fp_sqr();
    let mut z3 = z1.fp_add(&z2);
    z3 = z3.fp_sqr();
    z3 = z3.fp_sub(&t1);
    z3 = z3.fp_sub(&t2);

    let mut a = x1.fp_mul(&t2);
    let mut b = x2.fp_mul(&t1);
    let mut c = y1.fp_mul(&pre[1]);
    c = c.fp_double();

    let mut d = y2.fp_add(&z1);
    d = d.fp_sqr();
    d = d.fp_sub(&pre[0]);
    d = d.fp_sub(&t1);
    d = d.fp_mul(&t1);
    b = b.fp_sub(&a);
    z3 = z3.fp_mul(&b);
    t1 = b.fp_double();
    t1 = t1.fp_sqr();

    let mut x3 = b.fp_mul(&t1);
    let mut y3 = c.fp_mul(&x3);
    a = a.fp_mul(&t1);
    b = d.fp_sub(&c);
    t2 = a.fp_double();
    x3 = x3.fp_add(&t2);
    t2 = b.fp_sqr();
    x3 = t2.fp_sub(&x3);
    t2 = a.fp_sub(&x3);
    t2 = t2.fp_mul(&b);
    y3 = t2.fp_sub(&y3);

    lw[2] = z3.fp_mul(&pre[2]);
    lw[1] = b.fp_mul(&pre[3]);
    b = b.fp_mul(&pre[4]);

    lw[0] = y2.fp_mul(&z3);
    lw[0] = lw[0].fp_double();
    lw[0] = b.fp_sub(&lw[0]);

    TwistPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

pub(crate) fn sm9_u256_eval_g_tangent(lw: &mut [Fp2; 3], p: &TwistPoint, q: &Point) -> TwistPoint {
    let x = p.x;
    let y = p.y;
    let z = p.z;

    let t1 = z.fp_sqr();
    let mut a = x.fp_sqr();
    let mut b = y.fp_sqr();
    let mut c = b.fp_sqr();
    let mut d = x.fp_add(&b);
    d = d.fp_sqr();
    d = d.fp_sub(&a);
    d = d.fp_sub(&c);
    d = d.fp_double();
    let mut z3 = y.fp_add(&z);
    z3 = z3.fp_sqr();
    z3 = z3.fp_sub(&b);
    z3 = z3.fp_sub(&t1);

    lw[0] = b.fp_double();
    lw[0] = lw[0].fp_double();
    lw[0] = lw[0].fp_add(&a);
    a = a.fp_triple();
    b = a.fp_sqr();

    let mut x3 = d.fp_double();
    x3 = b.fp_sub(&x3);
    lw[0] = lw[0].fp_add(&b);

    let mut y3 = d.fp_sub(&x3);
    y3 = y3.fp_mul(&a);
    c = c.fp_double().fp_double().fp_double();
    y3 = y3.fp_sub(&c);

    lw[2] = z3.fp_mul(&t1);
    lw[2] = lw[2].fp_double();

    lw[1] = a.fp_mul(&t1);
    lw[1] = lw[1].fp_double();
    lw[1] = lw[1].fp_neg();

    a = x.fp_add(&a);
    a = a.fp_sqr();
    lw[0] = a.fp_sub(&lw[0]);
    lw[1] = lw[1].fp_mul_fp(&q.x);
    lw[2] = lw[2].fp_mul_fp(&q.y);

    TwistPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

#[cfg(test)]
mod test_point_operation {
    use crate::points::{twist_point_add_full, Point, TwistPoint, SM9_U256_MONT_G2};
    use crate::u256::u256_from_be_bytes;

    #[test]
    fn test_g_mul() {
        let k = u256_from_be_bytes(
            &hex::decode("123456789abcdef00fedcba987654321123456789abcdef00fedcba987654321")
                .unwrap(),
        );
        let r = Point::g_mul(&k);
        let ret = Point::from_hex([
            "7cf689748f3714490d7a19eae0e7bfad0e0182498b7bcd8a6998dfd00f59be51",
            "4e2e98d190e9d775e0caa943196bfb066d9c30818b2d768fb5299e7135830a6f",
        ]);
        assert_eq!(true, r.point_equals(&ret));
    }

    #[test]
    fn test_point_add() {
        let p = Point::from_hex([
            "917be49d159184fba140f4dfc5d653464e94f718fe195b226b3f715829e6e768",
            "288578d9505d462867a50acee40ee143b896e72505be10e8ce4c6b0c945b642b",
        ]);

        let q = Point::from_hex([
            "593417680f252445fd0522383e23c77a54b11fe222de4a886eabc26e16bffa3c",
            "38e8fc9a8b60f5ba0c6c411f721c117044435a833757d8fee65828511b8b245d",
        ]);

        let ret = Point::from_hex([
            "056610cb69f8d5659ea94e4a67bbf3b93fb0bd449672d7ca2525ec3b68c894d1",
            "88f3f99ce78ed3ffe6ca1cface5242570cb5d053f16a8e0baae10414babd86a7",
        ]);

        let r = p.point_add(&q);
        assert_eq!(true, r.point_equals(&ret));
    }

    #[test]
    fn test_point_dbl() {
        let p = Point::from_hex([
            "917be49d159184fba140f4dfc5d653464e94f718fe195b226b3f715829e6e768",
            "288578d9505d462867a50acee40ee143b896e72505be10e8ce4c6b0c945b642b",
        ]);

        let r = p.point_double();
        let ret = Point::from_hex([
            "268def7968f1e8c51635e277425403df88355fb2ecf16f7920f112eb2a7e50c9",
            "5c596b534bbaa85c1d3aecf436e61ff1bfd9f70856f0309c2a63d8248205d84e",
        ]);
        assert_eq!(true, r.point_equals(&ret));
    }

    #[test]
    fn test_point_sub() {
        let p = Point::from_hex([
            "917be49d159184fba140f4dfc5d653464e94f718fe195b226b3f715829e6e768",
            "288578d9505d462867a50acee40ee143b896e72505be10e8ce4c6b0c945b642b",
        ]);

        let q = Point::from_hex([
            "593417680f252445fd0522383e23c77a54b11fe222de4a886eabc26e16bffa3c",
            "38e8fc9a8b60f5ba0c6c411f721c117044435a833757d8fee65828511b8b245d",
        ]);

        let ret = Point::from_hex([
            "29e4a54cad98da9939b95f677784bff3b1dd9334c83d93e351e0f8f7c4ce2dc5",
            "4473eba3b8ff990b8456c41ec0727b76cb2b0f960495b144949f70bf95643b82",
        ]);
        let r = p.point_sub(&q);
        assert_eq!(true, r.point_equals(&ret));
    }

    #[test]
    fn test_point_neg() {
        let p = Point::from_hex([
            "917be49d159184fba140f4dfc5d653464e94f718fe195b226b3f715829e6e768",
            "288578d9505d462867a50acee40ee143b896e72505be10e8ce4c6b0c945b642b",
        ]);
        let r = p.point_neg();
        let ret = Point::from_hex([
            "917be49d159184fba140f4dfc5d653464e94f718fe195b226b3f715829e6e768",
            "8dba8726b24660c96e5ea081117fe601695bac2614bcddf31723301b4ef5e152",
        ]);
        assert_eq!(true, r.point_equals(&ret));
    }

    #[test]
    fn test_point_mul() {
        let p = Point::from_hex([
            "917be49d159184fba140f4dfc5d653464e94f718fe195b226b3f715829e6e768",
            "288578d9505d462867a50acee40ee143b896e72505be10e8ce4c6b0c945b642b",
        ]);
        let k = u256_from_be_bytes(
            &hex::decode("123456789abcdef00fedcba987654321123456789abcdef00fedcba987654321")
                .unwrap(),
        );
        let r = p.point_mul(&k);
        let ret = Point::from_hex([
            "997fcff625adbae62566f684f9e89181713f972c5a9cd9ce6764636761ba87d1",
            "8142a28d1bd109501452a649e2d68f012e265460e0c7d3da743fb036eb23b03b",
        ]);
        assert_eq!(true, r.point_equals(&ret));
    }

    #[test]
    fn test_twist_point_dbl() {
        let p = TwistPoint::from_hex(
            [
                "9a79bfd491ef1cb32d9b57f7d0590ccff6b1cfe63dd15c0823d692fafbe96dbc",
                "83f6a65d85d51ec72eacf19bc38384e0369eb22a134a725a0191faa6e4f192ef",
            ],
            [
                "849d4434eb7113fc9fb3809b51d54064fa2f20503423d256bc044905b1eba3fb",
                "9ed11c499291db0454d738555af0ce8a1df960056ee7425a6bf296eae60a5037",
            ],
        );

        let r = p.point_double();

        let ret = TwistPoint::from_hex(
            [
                "58400f0eb23000d814f5b5d0706749a72909795b7b04f26d6d58b2cf478ad9c9",
                "73cbced58a8e76ef5235b480050a74e906e4d27185bd85d7ebdcd43ad24475fd",
            ],
            [
                "19b460e09ac9ddbb380d6441e078a47bfcaa7d4c3d60b3a6c0d05f896472dc3c",
                "1d69f785f47d6f25cb901b131612c37edc5e89ee9ba2dac8c401ced40e340a39",
            ],
        );
        assert_eq!(true, r.point_equals(&ret))
    }

    #[test]
    fn test_twist_point_neg() {
        let p = TwistPoint::from_hex(
            [
                "9a79bfd491ef1cb32d9b57f7d0590ccff6b1cfe63dd15c0823d692fafbe96dbc",
                "83f6a65d85d51ec72eacf19bc38384e0369eb22a134a725a0191faa6e4f192ef",
            ],
            [
                "849d4434eb7113fc9fb3809b51d54064fa2f20503423d256bc044905b1eba3fb",
                "9ed11c499291db0454d738555af0ce8a1df960056ee7425a6bf296eae60a5037",
            ],
        );

        let r = p.point_neg();

        let ret = TwistPoint::from_hex(
            [
                "9a79bfd491ef1cb32d9b57f7d0590ccff6b1cfe63dd15c0823d692fafbe96dbc",
                "83f6a65d85d51ec72eacf19bc38384e0369eb22a134a725a0191faa6e4f192ef",
            ],
            [
                "31a2bbcb173292f536502ab4a3b986e027c372fae6571c85296b52223165a182",
                "176ee3b67011cbed812c72fa9a9df8bb03f93345ab93ac81797d043cfd46f546",
            ],
        );
        assert_eq!(true, r.point_equals(&ret))
    }

    #[test]
    fn test_twist_point_add() {
        let p = TwistPoint::from_hex(
            [
                "9a79bfd491ef1cb32d9b57f7d0590ccff6b1cfe63dd15c0823d692fafbe96dbc",
                "83f6a65d85d51ec72eacf19bc38384e0369eb22a134a725a0191faa6e4f192ef",
            ],
            [
                "849d4434eb7113fc9fb3809b51d54064fa2f20503423d256bc044905b1eba3fb",
                "9ed11c499291db0454d738555af0ce8a1df960056ee7425a6bf296eae60a5037",
            ],
        );

        let q = TwistPoint::from_hex(
            [
                "624b19114e49f00281e2aee1f1b9d4f0a081a135868f8bbdb7b7a7b7da5fd6bc",
                "a36232a9713f69157b7cdceef54aa0237b3ba0642a80dbb597af8935aea2c130",
            ],
            [
                "1be45454b6fa085a53744b22fd398238e400c3e031c8796e59e1bd6222048af0",
                "77966917ec1c5a294dd836c34691ab5e891f8c9f017443902c0a73ec54d449d8",
            ],
        );

        let r = p.point_add(&q);

        let r1 = twist_point_add_full(&p, &q);

        let ret = TwistPoint::from_hex(
            [
                "a411bbd84ee92a6ee53e5ca9cb81bacc192c6ba406f6fdcb2b04d0ab9c42ae44",
                "5f443752a19e368f404b89abae20a386d2b534c424b93ededdbfd04d4c569e6b",
            ],
            [
                "4fa25e5e6100a023d4923df385dd236749c6a7f8e68db55e0bd1e2263fc04d28",
                "6a3dadfcaac134e8353dd3abf37d487b206ca28dfab1e0a9376649df748f1605",
            ],
        );
        assert_eq!(true, r.point_equals(&ret));
        assert_eq!(true, r1.point_equals(&ret))
    }

    #[test]
    fn test_twist_point_sub() {
        let p = TwistPoint::from_hex(
            [
                "9a79bfd491ef1cb32d9b57f7d0590ccff6b1cfe63dd15c0823d692fafbe96dbc",
                "83f6a65d85d51ec72eacf19bc38384e0369eb22a134a725a0191faa6e4f192ef",
            ],
            [
                "849d4434eb7113fc9fb3809b51d54064fa2f20503423d256bc044905b1eba3fb",
                "9ed11c499291db0454d738555af0ce8a1df960056ee7425a6bf296eae60a5037",
            ],
        );

        let q = TwistPoint::from_hex(
            [
                "624b19114e49f00281e2aee1f1b9d4f0a081a135868f8bbdb7b7a7b7da5fd6bc",
                "a36232a9713f69157b7cdceef54aa0237b3ba0642a80dbb597af8935aea2c130",
            ],
            [
                "1be45454b6fa085a53744b22fd398238e400c3e031c8796e59e1bd6222048af0",
                "77966917ec1c5a294dd836c34691ab5e891f8c9f017443902c0a73ec54d449d8",
            ],
        );

        let r = p.point_sub(&q);

        let ret = TwistPoint::from_hex(
            [
                "1e9c3c99524c7867c9dbc4f52fdc938cf5aa4a980d3905cc91a5b91331235290",
                "3cbbf5fcc6c11a3579036e617bbf0b2861c53979f01e37f59fc4a10d991ccde7",
            ],
            [
                "47a4037d1d6f6d2014aa04292fa91cf07b1f4331a85d4b66a6e048226ddfc43e",
                "44027c5d814bab73ad93d14b564303aab153ad7355bcfbf8a8bed7cb577e7fd8",
            ],
        );
        assert_eq!(true, r.point_equals(&ret))
    }

    #[test]
    fn test_twist_point_mul() {
        let p = TwistPoint::from_hex(
            [
                "9a79bfd491ef1cb32d9b57f7d0590ccff6b1cfe63dd15c0823d692fafbe96dbc",
                "83f6a65d85d51ec72eacf19bc38384e0369eb22a134a725a0191faa6e4f192ef",
            ],
            [
                "849d4434eb7113fc9fb3809b51d54064fa2f20503423d256bc044905b1eba3fb",
                "9ed11c499291db0454d738555af0ce8a1df960056ee7425a6bf296eae60a5037",
            ],
        );

        let k = u256_from_be_bytes(
            &hex::decode("123456789abcdef00fedcba987654321123456789abcdef00fedcba987654321")
                .unwrap(),
        );

        let r = p.point_mul(&k);
        let ret = TwistPoint::from_hex(
            [
                "705c9ca4b5ef465c4e5db80ca4880627a6d9d6bcefd4756496baba9d5eaa3304",
                "5d704de3261290dbba39dbd14e6bc416025240fd1ed65ec982efed685ae41e8b",
            ],
            [
                "5d7ba50d7eac49a00b18fee2069afd3cc9719993fa78271e66b7a3efed46ac8b",
                "4e96eb3543aabf1e9a65cae24177b9d13b0f7fae9472145ba7ae2b14bb447aef",
            ],
        );
        assert_eq!(true, r.point_equals(&ret))
    }

    #[test]
    fn test_twist_point_g_mul() {
        let k = u256_from_be_bytes(
            &hex::decode("123456789abcdef00fedcba987654321123456789abcdef00fedcba987654321")
                .unwrap(),
        );

        let r = SM9_U256_MONT_G2.point_mul(&k);
        let ret = TwistPoint::from_hex(
            [
                "1f97dd359f2b065d63e0987f5bea2f3dc865c2cc112d7d161b46b83451716fd8",
                "920ef6fb3a2acff52aa0c004c18feca149dfd33d98086f8f402ea9e0de303c49",
            ],
            [
                "18a22e02b7d395a49f0646a79438e79cd37c32f163fe8923c13d56bab668e8a7",
                "614881d4d05fef3173a4990465876c5200f58c5015e13354b23ae401c20c4aef",
            ],
        );
        assert_eq!(true, r.point_equals(&ret))
    }
}
