const SM9_ZERO: [u64; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
const SM9_ONE: [u64; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
const SM9_TWO: [u64; 8] = [2, 0, 0, 0, 0, 0, 0, 0];
const SM9_FIVE: [u64; 8] = [5, 0, 0, 0, 0, 0, 0, 0];


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
pub(crate) fn sm9_bn_add(a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
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
pub(crate) fn sm9_bn_sub(a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
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

#[inline(always)]
pub(crate) fn sm9_barrett_bn_add(a: &[u64; 9], b: &[u64; 9]) -> [u64; 9] {
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

#[inline(always)]
pub(crate) fn sm9_barrett_bn_sub(a: &[u64; 9], b: &[u64; 9]) -> [u64; 9] {
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


