use crate::fields::fp::Fp;
use crate::fields::fp2::Fp2;
use crate::fields::FieldElement;
use crate::sm9_p256_table::SM9_P256_PRECOMPUTED;
use crate::u256::{sm9_u256_get_booth, u256_to_be_bytes, SM9_ZERO, U256};

#[derive(Copy, Debug, Clone)]
pub struct Point {
    x: Fp,
    y: Fp,
    z: Fp,
}

#[derive(Copy, Debug, Clone)]
pub struct TwistPoint {
    x: Fp2,
    y: Fp2,
    z: Fp2,
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

const SM9_U256_Ppubs: TwistPoint = TwistPoint {
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
    pub fn zero() -> Self {
        Self {
            x: Fp::one(),
            y: Fp::one(),
            z: Fp::zero(),
        }
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
        for i in (0..n - 1).rev() {
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
    pub fn zero() -> Self {
        Self {
            x: Fp2::one(),
            y: Fp2::one(),
            z: Fp2::zero(),
        }
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
            if t2.is_zero() {
                return rhs.point_double();
            }
        } else {
            return TwistPoint::zero();
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
        let kbits = u256_to_be_bytes(k);
        let mut r = TwistPoint::zero();
        for i in 0..256 {
            r = r.point_double();
            if kbits[i] & 0x1 == 1 {
                r = twist_point_add_full(&r, self)
            }
        }
        r
    }

    pub fn g_mul(k: &U256) -> TwistPoint {
        SM9_U256_MONT_G2.point_mul(k)
    }
}

fn twist_point_add_full(p1: &TwistPoint, p2: &TwistPoint) -> TwistPoint {
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

#[cfg(test)]
mod test_point_operation {
    use crate::fields::fp::{fp_to_mont, Fp};
    use crate::fields::FieldElement;
    use crate::points::Point;
    use crate::u256::u256_from_be_bytes;

    #[test]
    fn test_g_mul() {
        let k = u256_from_be_bytes(
            &hex::decode("123456789abcdef00fedcba987654321123456789abcdef00fedcba987654321")
                .unwrap(),
        );
        let r = Point::g_mul(&k);
        println!("r = {:#?}", r);
    }

    #[test]
    fn test_point_add() {}

    #[test]
    fn test_point_dbl() {}

    #[test]
    fn test_point_sub() {}

    #[test]
    fn test_point_neg() {}

    #[test]
    fn test_point_mul() {
        let p = Point {
            x: fp_to_mont(&u256_from_be_bytes(
                &hex::decode("917be49d159184fba140f4dfc5d653464e94f718fe195b226b3f715829e6e768")
                    .unwrap(),
            )),
            y: fp_to_mont(&u256_from_be_bytes(
                &hex::decode("288578d9505d462867a50acee40ee143b896e72505be10e8ce4c6b0c945b642b")
                    .unwrap(),
            )),
            z: Fp::one(),
        };

        let k = u256_from_be_bytes(
            &hex::decode("123456789abcdef00fedcba987654321123456789abcdef00fedcba987654321")
                .unwrap(),
        );

        let r = p.point_mul(&k);
        println!("{:x?}", r);
    }

    fn is_alternating(list: &[f64]) -> bool {
        // 判断列表是否为空或者只有一个元素，如果是，则认为满足条件
        if list.len() <= 1 {
            return true;
        }

        // 遍历列表，检查相邻元素是否满足交替升降的条件
        let mut last_flag = -1;
        for i in 1..list.len() {
            if list[i] == list[i - 1] {
                // 如果相邻元素相等，则不满足条件，直接返回false
                return false;
            }

            let diff = list[i] - list[i - 1];

            let mut current_flag = -1;
            if diff < 0.0 {
                current_flag = 0;
            } else {
                current_flag = 1;
            }

            if last_flag == current_flag {
                return false;
            }

            last_flag = current_flag;
        }

        // 如果遍历完列表没有发现不满足条件的情况，则认为满足条件，返回true
        true
    }

    #[test]
    fn test_is_alternating() {
        let example_list = vec![1.0, 2.0, 1.5, 2.5, 1.2, 2.8];
        println!("Is the list alternating? {}", is_alternating(&example_list));

        let example_list = vec![1.0, 1.0, 1.5, 2.5, 1.2, 2.8];
        println!("Is the list alternating? {}", is_alternating(&example_list));

        let example_list = vec![1.0, 0.8, 1.5, 0.5, 1.2, 0.8];
        println!("Is the list alternating? {}", is_alternating(&example_list));

        let example_list = vec![1.0, 1.3, 1.5, 2.5, 1.2, 2.8];
        println!("Is the list alternating? {}", is_alternating(&example_list));
    }
}
