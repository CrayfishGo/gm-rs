const SM9_ZERO: [u64; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
const SM9_ONE: [u64; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
const SM9_TWO: [u64; 8] = [2, 0, 0, 0, 0, 0, 0, 0];
const SM9_FIVE: [u64; 8] = [5, 0, 0, 0, 0, 0, 0, 0];

/// 本文使用256位的BN曲线。
///
/// 椭圆曲线方程：y2 = x3 + b
///
/// 参数 t: 60000000 0058F98A
///
/// 基域特征 q(t) = 36t^4 + 36t^3 + 24t^2 + 6t + 1
///
/// p =  B6400000 02A3A6F1 D603AB4F F58EC745 21F2934B 1A7AEEDB E56F9B27 E351457D
const SM9_P: [u64; 8] = [
    0xe351457d, 0xe56f9b27, 0x1a7aeedb, 0x21f2934b, 0xf58ec745, 0xd603ab4f, 0x02a3a6f1, 0xb6400000
];

/// 群的阶 N(t) = 36t^4 + 36t^3 + 18t^2 + 6t + 1
/// n =  B6400000 02A3A6F1 D603AB4F F58EC744 49F2934B 18EA8BEE E56EE19C D69ECF25
const SM9_N: [u64; 8] = [
    0xd69ecf25, 0xe56ee19c, 0x18ea8bee, 0x49f2934b, 0xf58ec744, 0xd603ab4f, 0x02a3a6f1, 0xb6400000
];

/// P - 1
const SM9_P_MINUS_ONE: [u64; 8] = [
    0xe351457c, 0xe56f9b27, 0x1a7aeedb, 0x21f2934b, 0xf58ec745, 0xd603ab4f, 0x02a3a6f1, 0xb6400000
];

/// N - 1
const SM9_N_MINUS_ONE: [u64; 8] = [
    0xd69ecf24, 0xe56ee19c, 0x18ea8bee, 0x49f2934b, 0xf58ec744, 0xd603ab4f, 0x02a3a6f1, 0xb6400000
];

// mu_p = 2^512 // p = 167980e0beb5759a655f73aebdcd1312af2665f6d1e36081c71188f90d5c22146
const SM9_MU_P: [u64; 9] = [
    0xd5c22146, 0x71188f90, 0x1e36081c, 0xf2665f6d, 0xdcd1312a, 0x55f73aeb, 0xeb5759a6, 0x67980e0b, 0x00000001
];

// mu_n = 2^512 // n
const SM9_MU_N: [u64; 9] = [
    0xdfc97c2f, 0x74df4fd4, 0xc9c073b0, 0x9c95d85e, 0xdcd1312c, 0x55f73aeb, 0xeb5759a6, 0x67980e0b, 0x00000001
];

const SM9_MU_N_MINUS_ONE: [u64; 9] = [
    0xdfc97c31, 0x74df4fd4, 0xc9c073b0, 0x9c95d85e, 0xdcd1312c, 0x55f73aeb, 0xeb5759a6, 0x67980e0b, 0x00000001
];

#[derive(Copy, Debug, Clone)]
pub struct Point {
    x: [u64; 8],
    y: [u64; 8],
    z: [u64; 8],
}

#[derive(Copy, Debug, Clone)]
pub struct TwistPoint {
    x: [[u64; 8]; 2],
    y: [[u64; 8]; 2],
    z: [[u64; 8]; 2],
}

// 群 G1的生成元 P1 = (xP1 , yP1);
// P1.X 0x93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD
// P1.Y 0x21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616
const G1: Point = Point {
    x: [
        0x7c66dddd, 0xe8c4e481, 0x09dc3280, 0xe1e40869, 0x487d01d6, 0xf5ed0704, 0x62bf718f, 0x93de051d,
    ],
    y: [
        0x0a3ea616, 0x0c464cd7, 0xfa602435, 0x1c1c00cb, 0x5c395bbc, 0x63106512, 0x4f21e607, 0x21fe8dda,
    ],
    z: [1, 0, 0, 0, 0, 0, 0, 0],
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
    x: [
        [
            0xAF82D65B, 0xF9B7213B, 0xD19C17AB, 0xEE265948, 0xD34EC120, 0xD2AAB97F, 0x92130B08, 0x37227552
        ],
        [
            0xD8806141, 0x54806C11, 0x0F5E93C4, 0xF1DD2C19, 0xB441A01F, 0x597B6027, 0x78640C98, 0x85AEF3D0
        ],
    ],
    y: [
        [
            0xC999A7C7, 0x6215BBA5, 0xA71A0811, 0x47EFBA98, 0x3D278FF2, 0x5F317015, 0x19BE3DA6, 0xA7CF28D5
        ],
        [
            0x84EBEB96, 0x856DC76B, 0xA347C8BD, 0x0736A96F, 0x2CBEE6ED, 0x66BA0D26, 0x2E845C12, 0x17509B09
        ],
    ],
    z: [[1, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0]],
};


fn sm9_bn_equals(a: &[u64; 8], b: &[u64; 8]) -> bool {
    for i in 0..8 {
        if a[i] != b[i] {
            return false;
        }
    }
    return true;
}

fn sm9_bn_is_one(a: &[u64; 8]) -> bool {
    return *a == SM9_ONE;
}

fn sm9_bn_is_zero(a: &[u64; 8]) -> bool {
    return *a == SM9_ZERO;
}

#[inline(always)]
fn sm9_bn_add(a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
    let mut sum = [0; 8];
    sum[0] = a[0] + b[0];
    for i in 1..8 {
        sum[i] = a[i] + b[i] + (sum[i - 1] >> 32);
    }
    for i in 0..8 {
        sum[i] &= 0xffffffff;
    }
    sum
}

#[inline(always)]
fn sm9_bn_sub(a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
    let mut r = [0; 8];
    r[0] = (1u64 << 32) + a[0] - b[0];
    let mut i = 1;
    loop {
        r[i] = 0xffffffff + a[i] - b[i] + (r[i - 1] >> 32);
        r[i - 1] &= 0xffffffff;
        if i == 7 {
            break;
        }
        i += 1;
    }
    r[i] = a[i] - b[i] + (r[i - 1] >> 32);
    r[i - 1] &= 0xffffffff;
    r
}

fn sm9_fp_add(a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
    let raw_sum = sm9_bn_add(a, b);
    if raw_sum >= SM9_P {
        let sum = sm9_bn_sub(&raw_sum, &SM9_P);
        sum
    } else {
        raw_sum
    }
}

fn sm9_fp_sub(a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
    if *a >= *b {
        sm9_bn_sub(a, b)
    } else {
        let r = sm9_bn_sub(&SM9_P, b);
        sm9_bn_add(&r, a)
    }
}

fn sm9_fp_dbl(a: &[u64; 8]) -> [u64; 8] {
    return sm9_fp_add(a, a);
}

fn sm9_fp_tri(a: &[u64; 8]) -> [u64; 8] {
    let r = sm9_fp_dbl(a);
    return sm9_fp_add(&r, a);
}

fn sm9_fp_div2(a: &[u64; 8]) -> [u64; 8] {
    let mut r = a.clone();
    let mut i = 0;
    if r[0] & 0x01 == 1 {
        r = sm9_bn_add(a, &SM9_P);
    }
    loop {
        r[i] = (r[i] >> 1) | ((r[i + 1] & 0x01) << 31);
        if i == 7 {
            break;
        }
        i += 1;
    }
    r[i] >>= 1;
    r
}

fn sm9_fp_neg(a: &[u64; 8]) -> [u64; 8] {
    if sm9_bn_is_zero(a) {
        a.clone()
    } else {
        sm9_bn_sub(&SM9_P, a)
    }
}

fn sm9_barrett_bn_add(a: &[u64; 9], b: &[u64; 9]) -> [u64; 9] {
    let mut sum = [0; 9];
    sum[0] = a[0] + b[0];
    for i in 1..9 {
        sum[i] = a[i] + b[i] + (sum[i - 1] >> 32);
    }
    for i in 0..9 {
        sum[i] &= 0xffffffff;
    }
    sum
}

fn sm9_barrett_bn_sub(a: &[u64; 9], b: &[u64; 9]) -> [u64; 9] {
    let mut r = [0; 9];
    r[0] = (1u64 << 32) + a[0] - b[0];
    let mut i = 1;
    loop {
        r[i] = 0xffffffff + a[i] - b[i] + (r[i - 1] >> 32);
        r[i - 1] &= 0xffffffff;
        if i == 8 {
            break;
        }
        i += 1;
    }
    r[i] = a[i] - b[i] + (r[i - 1] >> 32);
    r[i - 1] &= 0xffffffff;
    r
}

fn sm9_fp_mul(a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
    let mut r = [0u64; 8];
    let mut s = [0u64; 18];
    let mut w = 0u64;

    for i in 0..8 {
        for j in 0..8 {
            w += s[i + j] + a[i] * b[j];
            s[i + j] = w & 0xffffffff;
            w >>= 32;
        }
        s[i + 8] = w;
    }

    let mut zh = [0u64; 9];
    let mut zl = [0u64; 9];
    let mut q = [0u64; 9];

    // zl = z mod (2^32)^9 = z[0..8]
    // zh = z // (2^32)^7 = z[7..15]
    for i in 0..9 {
        zl[i] = s[i];
        zh[i] = s[7 + i];
    }
    for i in 0..9 {
        s[i] = 0;
    }

    // q = zh * mu // (2^32)^9
    for i in 0..9 {
        w = 0;
        for j in 0..9 {
            w += s[i + j] + zh[i] * SM9_MU_P[j];
            s[i + j] = w & 0xffffffff;
            w >>= 32;
        }
        s[i + 9] = w;
    }

    //  q = q * p mod (2^32)^9
    for i in 0..8 {
        s[i] = 0;
    }
    w = 0;
    for j in 0..8 {
        w += s[j] + q[0] * SM9_P[j];
        s[j] = w & 0xffffffff;
        w >>= 32;
    }
    s[8] = w;
    for i in 1..9 {
        w = 0;
        let mut j = 0;
        while i + j < 9 {
            w += s[i + j] + q[i] * SM9_P[j];
            s[i + j] = w & 0xffffffff;
            w >>= 32;
            j += 1;
        }
    }
    for i in 0..9 {
        q[i] = s[i];
    }

    // r = zl - q (mod (2^32)^9)
    if zl > q {
        zl = sm9_barrett_bn_sub(&zl, &q);
    } else {
        let c = [0, 0, 0, 0, 0, 0, 0, 0, 0x100000000];
        q = sm9_barrett_bn_sub(&c, &q);
        zl = sm9_barrett_bn_add(&q, &zl);
    }

    for i in 0..8 {
        r[i] = zl[i];
    }
    r[7] += (zl[8] << 32);

    // while r >= p do: r = r - p
    while r >= SM9_P {
        r = sm9_bn_sub(&r, &SM9_P);
    }
    r
}

fn sm9_fp_sqr(a: &[u64; 8]) -> [u64; 8] {
    return sm9_fp_mul(a, a);
}

fn sm9_fp_pow(a: &[u64; 8], e: &[u64; 8]) -> [u64; 8] {
    assert!(e <= &SM9_ZERO);
    let mut r = [0u64; 8];
    let mut w = 0u32;
    let mut i = 7;
    let mut j = 0;
    loop {
        w = e[i] as u32;
        loop {
            r = sm9_fp_sqr(&r);
            if w & 0x80000000 == 1 {
                r = sm9_fp_mul(&r, a);
            }
            w <<= 1;
            if j == 32 {
                break;
            }
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    r
}

fn sm9_fp_inv(a: &[u64; 8]) -> [u64; 8] {
    let mut e = sm9_bn_sub(&SM9_P, &SM9_TWO);
    return sm9_fp_pow(a, &e);
}

type Sm9Fp2 = [[u64; 8]; 2];

const SM9_FP2_ZERO: Sm9Fp2 = [[0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0]];
const SM9_FP2_ONE: Sm9Fp2 = [[1, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0, 0, 0]];
const SM9_FP2_U: Sm9Fp2 = [[0, 0, 0, 0, 0, 0, 0, 0], [1, 0, 0, 0, 0, 0, 0, 0]];
const SM9_FP2_5U: Sm9Fp2 = [[0, 0, 0, 0, 0, 0, 0, 0], [5, 0, 0, 0, 0, 0, 0, 0]];

fn sm9_fp2_add(a: &Sm9Fp2, b: &Sm9Fp2) -> Sm9Fp2 {
    let mut r: Sm9Fp2 = SM9_FP2_ZERO;
    r[0] = sm9_fp_add(&a[0], &b[0]);
    r[1] = sm9_fp_add(&a[1], &b[1]);
    r
}

fn sm9_fp2_dbl(a: &Sm9Fp2) -> Sm9Fp2 {
    let mut r: Sm9Fp2 = SM9_FP2_ZERO;
    r[0] = sm9_fp_dbl(&a[0]);
    r[1] = sm9_fp_dbl(&a[1]);
    r
}

fn sm9_fp2_tri(a: &Sm9Fp2) -> Sm9Fp2 {
    let mut r: Sm9Fp2 = SM9_FP2_ZERO;
    r[0] = sm9_fp_tri(&a[0]);
    r[1] = sm9_fp_tri(&a[1]);
    r
}

fn sm9_fp2_sub(a: &Sm9Fp2, b: &Sm9Fp2) -> Sm9Fp2 {
    let mut r: Sm9Fp2 = SM9_FP2_ZERO;
    r[0] = sm9_fp_sub(&a[0], &b[0]);
    r[1] = sm9_fp_sub(&a[1], &b[1]);
    r
}

fn sm9_fp2_neg(a: &Sm9Fp2) -> Sm9Fp2 {
    let mut r: Sm9Fp2 = SM9_FP2_ZERO;
    r[0] = sm9_fp_neg(&a[0]);
    r[1] = sm9_fp_neg(&a[1]);
    r
}

fn sm9_fp2_mul(a: &Sm9Fp2, b: &Sm9Fp2) -> Sm9Fp2 {
    let mut r: Sm9Fp2 = SM9_FP2_ZERO;
    let mut r0 = SM9_ZERO;
    let mut r1 = SM9_ZERO;
    let mut t = SM9_ZERO;
    // r0 = a0 * b0 - 2 * a1 * b1
    r0 = sm9_fp_mul(&a[0], &b[0]);
    t = sm9_fp_mul(&a[1], &b[1]);
    t = sm9_fp_dbl(&t);
    r0 = sm9_fp_sub(&r0, &t);
    r[0] = r0;

    // r1 = a0 * b1 + a1 * b0
    r1 = sm9_fp_mul(&a[0], &b[1]);
    t = sm9_fp_mul(&a[1], &b[0]);
    r1 = sm9_fp_add(&r1, &t);
    r[1] = r1;
    r
}

fn sm9_fp2_mul_u(a: &Sm9Fp2, b: &Sm9Fp2) -> Sm9Fp2 {
    let mut r: Sm9Fp2 = SM9_FP2_ZERO;
    let mut r0 = SM9_ZERO;
    let mut r1 = SM9_ZERO;
    let mut t = SM9_ZERO;

    // r0 = -2 * (a0 * b1 + a1 * b0)
    r0 = sm9_fp_mul(&a[0], &b[1]);
    t = sm9_fp_mul(&a[1], &b[0]);
    r0 = sm9_fp_add(&r0, &t);
    r0 = sm9_fp_dbl(&r0);
    r0 = sm9_fp_neg(&r0);
    r[0] = r0;

    // r1 = a0 * b0 - 2 * a1 * b1
    r1 = sm9_fp_mul(&a[0], &b[0]);
    t = sm9_fp_mul(&a[1], &b[1]);
    t = sm9_fp_dbl(&t);
    r1 = sm9_fp_sub(&r1, &t);
    r[1] = r1;
    r
}

fn sm9_fp2_mul_fp(a: &Sm9Fp2, k: &[u64; 8]) -> Sm9Fp2 {
    let mut r: Sm9Fp2 = SM9_FP2_ZERO;
    r[0] = sm9_fp_mul(&a[0], k);
    r[1] = sm9_fp_mul(&a[1], k);
    r
}

fn sm9_fp2_sqr(a: &Sm9Fp2) -> Sm9Fp2 {
    let mut r: Sm9Fp2 = SM9_FP2_ZERO;
    let mut r0 = SM9_ZERO;
    let mut r1 = SM9_ZERO;
    let mut t = SM9_ZERO;

    // r0 = a0^2 - 2 * a1^2
    r0 = sm9_fp_sqr(&a[0]);
    t = sm9_fp_sqr(&a[1]);
    t = sm9_fp_dbl(&t);
    r0 = sm9_fp_sub(&r0, &t);

    // r1 = 2 * a0 * a1
    r1 = sm9_fp_mul(&a[0], &a[1]);
    r1 = sm9_fp_dbl(&r1);
    r[0] = r0;
    r[1] = r1;
    r
}


fn sm9_fp2_sqr_u(a: &Sm9Fp2) -> Sm9Fp2 {
    let mut r: Sm9Fp2 = SM9_FP2_ZERO;
    let mut r0 = SM9_ZERO;
    let mut r1 = SM9_ZERO;
    let mut t = SM9_ZERO;

    // r0 = -4 * a0 * a1
    r0 = sm9_fp_mul(&a[0], &a[1]);
    r0 = sm9_fp_dbl(&r0);
    r0 = sm9_fp_dbl(&r0);
    r0 = sm9_fp_neg(&r0);

    // r1 = a0^2 - 2 * a1^2
    r1 = sm9_fp_sqr(&a[0]);
    t = sm9_fp_sqr(&a[1]);
    t = sm9_fp_dbl(&t);
    r1 = sm9_fp_sub(&r1, &t);

    r[0] = r0;
    r[1] = r1;
    r
}


fn sm9_fp2_inv(a: &Sm9Fp2) -> Sm9Fp2 {
    let mut r: Sm9Fp2 = SM9_FP2_ZERO;

    let mut k = SM9_ZERO;
    let mut t = SM9_ZERO;

    let mut r0 = SM9_ZERO;
    let mut r1 = SM9_ZERO;

    if sm9_bn_is_zero(&a[0]) {
        // r0 = 0
        // r1 = -(2 * a1)^-1
        r1 = sm9_fp_dbl(&a[1]);
        r1 = sm9_fp_inv(&a[1]);
        r1 = sm9_fp_neg(&r1);
    } else if sm9_bn_is_zero(&a[1]) {
        // r1 = 0
        // r0 = a0^-1
        r0 = sm9_fp_inv(&a[0]);
    } else {
        // k = (a[0]^2 + 2 * a[1]^2)^-1
        k = sm9_fp_sqr(&a[0]);
        t = sm9_fp_sqr(&a[1]);
        t = sm9_fp_dbl(&t);
        k = sm9_fp_add(&k, &t);
        k = sm9_fp_inv(&k);

        // r[0] = a[0] * k
        r0 = sm9_fp_mul(&a[0], &k);

        // r[1] = -a[1] * k
        r1 = sm9_fp_mul(&a[1], &k);
        r1 = sm9_fp_neg(&r1);
    }
    r[0] = r0;
    r[1] = r1;
    r
}


fn sm9_fp2_div(a: &Sm9Fp2, b: &Sm9Fp2) -> Sm9Fp2 {
    let t: Sm9Fp2 = sm9_fp2_inv(&b);
    sm9_fp2_mul(a, &t)
}

fn sm9_fp2_div2(a: &Sm9Fp2) -> Sm9Fp2 {
    let mut r: Sm9Fp2 = SM9_FP2_ZERO;
    r[0] = sm9_fp_div2(&a[0]);
    r[1] = sm9_fp_div2(&a[1]);
    r
}