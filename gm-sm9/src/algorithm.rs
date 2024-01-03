const SM9_ZERO: [u32; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
const SM9_ONE: [u32; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
const SM9_TWO: [u32; 8] = [2, 0, 0, 0, 0, 0, 0, 0];
const SM9_FIVE: [u32; 8] = [5, 0, 0, 0, 0, 0, 0, 0];

/// 本文使用256位的BN曲线。
///
/// 椭圆曲线方程：y2 = x3 + b
///
/// 参数 t: 60000000 0058F98A
///
/// 基域特征 q(t) = 36t^4 + 36t^3 + 24t^2 + 6t + 1
///
/// p =  B6400000 02A3A6F1 D603AB4F F58EC745 21F2934B 1A7AEEDB E56F9B27 E351457D
const SM9_P: [u32; 8] = [
    0xe351457d, 0xe56f9b27, 0x1a7aeedb, 0x21f2934b, 0xf58ec745, 0xd603ab4f, 0x02a3a6f1, 0xb6400000
];

/// 群的阶 N(t) = 36t^4 + 36t^3 + 18t^2 + 6t + 1
/// n =  B6400000 02A3A6F1 D603AB4F F58EC744 49F2934B 18EA8BEE E56EE19C D69ECF25
const SM9_N: [u32; 8] = [
    0xd69ecf25, 0xe56ee19c, 0x18ea8bee, 0x49f2934b, 0xf58ec744, 0xd603ab4f, 0x02a3a6f1, 0xb6400000
];

/// P - 1
const SM9_P_MINUS_ONE: [u32; 8] = [
    0xe351457c, 0xe56f9b27, 0x1a7aeedb, 0x21f2934b, 0xf58ec745, 0xd603ab4f, 0x02a3a6f1, 0xb6400000
];

/// N - 1
const SM9_N_MINUS_ONE: [u32; 8] = [
    0xd69ecf24, 0xe56ee19c, 0x18ea8bee, 0x49f2934b, 0xf58ec744, 0xd603ab4f, 0x02a3a6f1, 0xb6400000
];

// mu_p = 2^512 // p = 167980e0beb5759a655f73aebdcd1312af2665f6d1e36081c71188f90d5c22146
const SM9_MU_P: [u32; 9] = [
    0xd5c22146, 0x71188f90, 0x1e36081c, 0xf2665f6d, 0xdcd1312a, 0x55f73aeb, 0xeb5759a6, 0x67980e0b, 0x00000001
];

// mu_n = 2^512 // n
const SM9_MU_N: [u32; 9] = [
    0xdfc97c2f, 0x74df4fd4, 0xc9c073b0, 0x9c95d85e, 0xdcd1312c, 0x55f73aeb, 0xeb5759a6, 0x67980e0b, 0x00000001
];

const SM9_MU_N_MINUS_ONE: [u32; 9] = [
    0xdfc97c31, 0x74df4fd4, 0xc9c073b0, 0x9c95d85e, 0xdcd1312c, 0x55f73aeb, 0xeb5759a6, 0x67980e0b, 0x00000001
];

#[derive(Copy, Debug, Clone)]
pub struct Point {
    x: [u32; 8],
    y: [u32; 8],
    z: [u32; 8],
}

#[derive(Copy, Debug, Clone)]
pub struct TwistPoint {
    x: [[u32; 8]; 2],
    y: [[u32; 8]; 2],
    z: [[u32; 8]; 2],
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
