use crate::u256::U256;

#[derive(Copy, Debug, Clone)]
pub struct Point {
    x: U256,
    y: U256,
    z: U256,
}

#[derive(Copy, Debug, Clone)]
pub struct TwistPoint {
    x: [U256; 2],
    y: [U256; 2],
    z: [U256; 2],
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
    x: [
        [
            0xF9B7213BAF82D65B,
            0xEE265948D19C17AB,
            0xD2AAB97FD34EC120,
            0x3722755292130B08,
        ],
        [
            0x54806C11D8806141,
            0xF1DD2C190F5E93C4,
            0x597B6027B441A01F,
            0x85AEF3D078640C98,
        ],
    ],
    y: [
        [
            0x6215BBA5C999A7C7,
            0x47EFBA98A71A0811,
            0x5F3170153D278FF2,
            0xA7CF28D519BE3DA6,
        ],
        [
            0x856DC76B84EBEB96,
            0x0736A96FA347C8BD,
            0x66BA0D262CBEE6ED,
            0x17509B092E845C12,
        ],
    ],
    z: [[1, 0, 0, 0], [0, 0, 0, 0]],
};

impl Point {
    pub fn point_double(&self) -> Self {
        todo!()
    }

    pub fn point_add(&self, rhs: &Self) -> Self {
        todo!()
    }

    pub fn point_sub(&self, rhs: &Self) -> Self {
        todo!()
    }

    pub fn point_neg(&self) -> Self {
        todo!()
    }

    pub fn point_double_x5(&self) -> Self {
        let mut r = self.point_double();
        r = r.point_double();
        r = r.point_double();
        r = r.point_double();
        r = r.point_double();
        r
    }

    pub fn point_mul(&self, k: &U256) -> Self {
        todo!()
    }
}

impl TwistPoint {
    pub fn point_double(&self) -> Self {
        todo!()
    }

    pub fn point_add(&self, rhs: &Self) -> Self {
        todo!()
    }

    pub fn point_sub(&self, rhs: &Self) -> Self {
        todo!()
    }

    pub fn point_neg(&self) -> Self {
        todo!()
    }

    pub fn point_mul(&self, k: &U256) -> Self {
        todo!()
    }
}
