const SM9_ZERO: [u64; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
const SM9_ONE: [u64; 8] = [0, 0, 0, 0, 0, 0, 0, 1];
const SM9_TWO: [u64; 8] = [0, 0, 0, 0, 0, 0, 0, 2];
const SM9_FIVE: [u64; 8] = [0, 0, 0, 0, 0, 0, 0, 5];

// p =  b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d
const SM9_P: [u64; 8] = [
    0xb6400000, 0x02a3a6f1, 0xd603ab4f, 0xf58ec745, 0x21f2934b, 0x1a7aeedb, 0xe56f9b27, 0xe351457d,
];

// n =  b640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25
const SM9_N: [u64; 8] = [
    0xb6400000, 0x02a3a6f1, 0xd603ab4f, 0xf58ec744, 0x49f2934b, 0x18ea8bee, 0xe56ee19c, 0xd69ecf25,
];

const SM9_P_MINUS_ONE: [u64; 8] = [
    0xb6400000, 0x02a3a6f1, 0xd603ab4f, 0xf58ec745, 0x21f2934b, 0x1a7aeedb, 0xe56f9b27, 0xe351457c,
];

const SM9_N_MINUS_ONE: [u64; 8] = [
    0xb6400000, 0x02a3a6f1, 0xd603ab4f, 0xf58ec744, 0x49f2934b, 0x18ea8bee, 0xe56ee19c, 0xd69ecf24,
];

// mu_p = 2^512 // p = 167980e0beb5759a655f73aebdcd1312af2665f6d1e36081c71188f90d5c22146
const SM9_MU_P: [u64; 9] = [
    0x00000001, 0x67980e0b, 0xeb5759a6, 0x55f73aeb, 0xdcd1312a, 0xf2665f6d, 0x1e36081c, 0x71188f90,
    0xd5c22146,
];

// mu_n = 2^512 // n
const SM9_MU_N: [u64; 9] = [
    0x00000001, 0x67980e0b, 0xeb5759a6, 0x55f73aeb, 0xdcd1312c, 0x9c95d85e, 0xc9c073b0, 0x74df4fd4,
    0xdfc97c2f,
];

const SM9_MU_N_MINUS_ONE: [u64; 9] = [
    0x00000001, 0x67980e0b, 0xeb5759a6, 0x55f73aeb, 0xdcd1312c, 0x9c95d85e, 0xc9c073b0, 0x74df4fd4,
    0xdfc97c31,
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

// 群 G1的生成元 P1 = (xP1 , yP1)：
const G1: Point = Point {
    x: [
        0x7c66dddd, 0xe8c4e481, 0x09dc3280, 0xe1e40869, 0x487d01d6, 0xf5ed0704, 0x62bf718f,
        0x93de051d,
    ],
    y: [
        0x0a3ea616, 0x0c464cd7, 0xfa602435, 0x1c1c00cb, 0x5c395bbc, 0x63106512, 0x4f21e607,
        0x21fe8dda,
    ],
    z: [0, 0, 0, 0, 0, 0, 0, 1],
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
            0x37227552, 0x92130B08, 0xD2AAB97F, 0xD34EC120, 0xEE265948, 0xD19C17AB, 0xF9B7213B,
            0xAF82D65B,
        ],
        [
            0x85AEF3D0, 0x78640C98, 0x597B6027, 0xB441A01F, 0xF1DD2C19, 0x0F5E93C4, 0x54806C11,
            0xD8806141,
        ],
    ],
    y: [
        [
            0xA7CF28D5, 0x19BE3DA6, 0x5F317015, 0x3D278FF2, 0x47EFBA98, 0xA71A0811, 0x6215BBA5,
            0xC999A7C7,
        ],
        [
            0x17509B09, 0x2E845C12, 0x66BA0D26, 0x2CBEE6ED, 0x0736A96F, 0xA347C8BD, 0x856DC76B,
            0x84EBEB96,
        ],
    ],
    z: [[0, 0, 0, 0, 0, 0, 0, 1], [0, 0, 0, 0, 0, 0, 0, 0]],
};
