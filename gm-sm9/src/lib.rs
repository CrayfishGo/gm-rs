#![doc = include_str!("../README.md")]
use crate::fields::fp2::Fp2;
use crate::points::{Point, TwistPoint};
use crate::u256::U256;

pub mod error;
pub mod fields;
pub mod key;
pub mod points;
mod sm9_p256_table;
pub mod u256;

/// Example:
///
/// ### encrypt & decrypt
/// ```rust
/// use gm_sm9::key::Sm9EncMasterKey;
/// use gm_sm9::points::{Point, TwistPoint};
/// use gm_sm9::u256::u256_from_be_bytes;
///
/// fn main() {
///     let data: [u8; 21] = [
///         0x43, 0x68, 0x69, 0x6E, 0x65, 0x73, 0x65, 0x20, 0x49, 0x42, 0x53, 0x20, 0x73, 0x74,
///         0x61, 0x6E, 0x64, 0x61, 0x72, 0x64, 0x64,
///     ];
///     println!("Message =    {:?}", &data);
///     let id = [0x42, 0x6F, 0x62u8];
///     let ke = u256_from_be_bytes(
///         &hex::decode("0001EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22")
///             .unwrap(),
///     );
///
///     let msk = Sm9EncMasterKey {
///         ke,
///         ppube: Point::g_mul(&ke),
///     };
///
///     let r = msk.extract_key(&id);
///     let r_de = TwistPoint::from_hex(
///         [
///             "115BAE85F5D8BC6C3DBD9E5342979ACCCF3C2F4F28420B1CB4F8C0B59A19B158",
///             "94736ACD2C8C8796CC4785E938301A139A059D3537B6414140B2D31EECF41683",
///         ],
///         [
///             "27538A62E7F7BFB51DCE08704796D94C9D56734F119EA44732B50E31CDEB75C1",
///             "7AA5E47570DA7600CD760A0CF7BEAF71C447F3844753FE74FA7BA92CA7D3B55F",
///         ],
///     );
///     assert_eq!(true, r.unwrap().de.point_equals(&r_de));
///
///     let ret = msk.encrypt(&id, &data);
///     println!("Ciphertext = {:?}", ret);
///
///     let m = r.unwrap().decrypt(&id, &ret).expect("Decryption failed");
///     println!("Plaintext =  {:?}", &m);
///     assert_eq!(true, data == m.as_slice());
/// }
///
/// ```
///
///
/// ### sign & verify
/// ```rust
///     use gm_sm9::key::{Sm9SignMasterKey, Sm9SignKey};
///     use gm_sm9::points::{Point, TwistPoint};
///     use gm_sm9::u256::u256_from_be_bytes;
///     fn main() {
///         let data: [u8; 20] = [
///             0x43, 0x68, 0x69, 0x6E, 0x65, 0x73, 0x65, 0x20, 0x49, 0x42, 0x53, 0x20, 0x73, 0x74,
///             0x61, 0x6E, 0x64, 0x61, 0x72, 0x64,
///         ];
///
///         let ida = [0x41, 0x6C, 0x69, 0x63, 0x65u8];
///
///         let ks = u256_from_be_bytes(
///             &hex::decode("000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4")
///                 .unwrap(),
///         );
///         let msk = Sm9SignMasterKey {
///             ks,
///             ppubs: TwistPoint::g_mul(&ks),
///         };
///
///         let r_ds = Point::from_hex([
///             "A5702F05CF1315305E2D6EB64B0DEB923DB1A0BCF0CAFF90523AC8754AA69820",
///             "78559A844411F9825C109F5EE3F52D720DD01785392A727BB1556952B2B013D3",
///         ]);
///         let r = msk.extract_key(&ida);
///         let ps = r.unwrap();
///         assert_eq!(true, ps.ds.point_equals(&r_ds));
///
///         println!("Message =    {:?}", &data);
///         let (h, s) = ps.sign(&data).unwrap();
///         println!("Sign H =     {:?}", &h);
///         println!("Sign S =     {:?}", &s);
///
///         let r = msk.verify_sign(&ida, &data, &h, &s);
///         println!("VersionSign ={:?}", &r);
///     }
///
/// ```
///
///
/// ### key exchange
/// ```rust
///     use gm_sm9::key::{Sm9EncMasterKey,Sm9EncKey};
///     use gm_sm9::points::{Point, TwistPoint};
///     use gm_sm9::key::{exch_step_1a, exch_step_1b, exch_step_2a};
///     fn main() {
///         let msk: Sm9EncMasterKey = Sm9EncMasterKey::master_key_generate();
///         let klen = 20usize;
///         let ida = [0x41, 0x6C, 0x69, 0x63, 0x65u8];
///         let idb = [0x42, 0x6F, 0x62u8];
///         let key_a: Sm9EncKey = msk.extract_exch_key(&ida).unwrap();
///         let key_b: Sm9EncKey = msk.extract_exch_key(&idb).unwrap();
///
///         let (ra, ra_) = exch_step_1a(&msk, &idb);
///         let (rb, skb) = exch_step_1b(&msk, &ida, &idb, &key_b, &ra, klen).unwrap();
///         let ska = exch_step_2a(&msk, &ida, &idb, &key_a, ra_, &ra, &rb, klen).unwrap();
///         println!("SKB = {:?}", &skb);
///         println!("SKA = {:?}", &ska);
///         for i in 0..klen {
///             if ska[i] != skb[i] {
///                 println!("Exchange key different at byte index: {}", i)
///             }
///         }
///     }
///
/// ```
///
///
///




/// 本文使用256位的BN曲线。
///
/// 椭圆曲线方程：y2 = x3 + b
///
/// 参数 t: 60000000 0058F98A
///
/// 基域特征 q(t) = 36t^4 + 36t^3 + 24t^2 + 6t + 1
///
/// p =  B6400000 02A3A6F1 D603AB4F F58EC745 21F2934B 1A7AEEDB E56F9B27 E351457D
pub(crate) const SM9_P: U256 = [
    0xe56f9b27e351457d,
    0x21f2934b1a7aeedb,
    0xd603ab4ff58ec745,
    0xb640000002a3a6f1,
];

pub(crate) const SM9_P_MINUS_ONE: U256 = [
    0xe56f9b27e351457c,
    0x21f2934b1a7aeedb,
    0xd603ab4ff58ec745,
    0xb640000002a3a6f1,
];

/// e = p - 2 = b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457b
///
/// p - 2, used in a^(p-2) = a^-1
pub(crate) const SM9_P_MINUS_TWO: U256 = [
    0xe56f9b27e351457b,
    0x21f2934b1a7aeedb,
    0xd603ab4ff58ec745,
    0xb640000002a3a6f1,
];

/// p = b640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d
///
/// p' = -p^(-1) mod 2^256 = afd2bac5558a13b3966a4b291522b137181ae39613c8dbaf892bc42c2f2ee42b
///
/// sage: -(IntegerModRing(2^256)(p))^-1
pub(crate) const SM9_P_PRIME: U256 = [
    0x892bc42c2f2ee42b,
    0x181ae39613c8dbaf,
    0x966a4b291522b137,
    0xafd2bac5558a13b3,
];

// mont params (mod p)
// mu = p^-1 mod 2^64 = 0x76d43bd3d0d11bd5
// 2^512 mod p = 0x2ea795a656f62fbde479b522d6706e7b88f8105fae1a5d3f27dea312b417e2d2
// mont(1) mod p = 2^256 mod p = 0x49bffffffd5c590e29fc54b00a7138bade0d6cb4e58511241a9064d81caeba83
pub(crate) const SM9_MODP_MU: u64 = 0x76d43bd3d0d11bd5_u64;
pub(crate) const SM9_MODP_2E512: U256 = [
    0x27dea312b417e2d2,
    0x88f8105fae1a5d3f,
    0xe479b522d6706e7b,
    0x2ea795a656f62fbd,
];
pub(crate) const SM9_MODP_MONT_ONE: U256 = [
    0x1a9064d81caeba83,
    0xde0d6cb4e5851124,
    0x29fc54b00a7138ba,
    0x49bffffffd5c590e,
];
pub(crate) const SM9_MODP_MONT_FIVE: U256 = [
    0xb9f2c1e8c8c71995,
    0x125df8f246a377fc,
    0x25e650d049188d1c,
    0x43fffffed866f63,
];

pub(crate) const SM9_MONT_ALPHA1: U256 = [
    0x1a98dfbd4575299f,
    0x9ec8547b245c54fd,
    0xf51f5eac13df846c,
    0x9ef74015d5a16393,
];

pub(crate) const SM9_MONT_ALPHA2: U256 = [
    0xb626197dce4736ca,
    0x08296b3557ed0186,
    0x9c705db2fd91512a,
    0x1c753e748601c992,
];

pub(crate) const SM9_MONT_ALPHA3: U256 = [
    0x39b4ef0f3ee72529,
    0xdb043bf508582782,
    0xb8554ab054ac91e3,
    0x9848eec25498cab5,
];

pub(crate) const SM9_MONT_ALPHA4: U256 = [
    0x81054fcd94e9c1c4,
    0x4c0e91cb8ce2df3e,
    0x4877b452e8aedfb4,
    0x88f53e748b491776,
];

pub(crate) const SM9_MONT_ALPHA5: U256 = [
    0x048baa79dcc34107,
    0x5e2e7ac4fe76c161,
    0x99399754365bd4bc,
    0xaf91aeac819b0e13,
];

pub(crate) const SM9_MONT_BETA: Fp2 = Fp2 {
    c0: [
        0x39b4ef0f3ee72529,
        0xdb043bf508582782,
        0xb8554ab054ac91e3,
        0x9848eec25498cab5,
    ],
    c1: [0, 0, 0, 0],
};

pub(crate) const SM9_FP2_ZERO: [U256; 2] = [[0, 0, 0, 0], [0, 0, 0, 0]];
pub(crate) const SM9_FP2_ONE: [U256; 2] = [[1, 0, 0, 0], [0, 0, 0, 0]];
pub(crate) const SM9_FP2_U: [U256; 2] = [[0, 0, 0, 0], [1, 0, 0, 0]];
pub(crate) const SM9_FP2_5U: [U256; 2] = [[0, 0, 0, 0], [5, 0, 0, 0]];
pub(crate) const SM9_FP2_MONT_5U: [U256; 2] = [
    [0, 0, 0, 0],
    [
        0xb9f2c1e8c8c71995,
        0x125df8f246a377fc,
        0x25e650d049188d1c,
        0x43fffffed866f63,
    ],
];

pub(crate) const SM9_FP4_ZERO: [[U256; 2]; 2] =
    [[[0, 0, 0, 0], [0, 0, 0, 0]], [[0, 0, 0, 0], [0, 0, 0, 0]]];
pub(crate) const SM9_FP4_MONT_ONE: [[U256; 2]; 2] = [
    [
        [
            0x1a9064d81caeba83,
            0xde0d6cb4e5851124,
            0x29fc54b00a7138ba,
            0x49bffffffd5c590e,
        ],
        [0, 0, 0, 0],
    ],
    [[0, 0, 0, 0], [0, 0, 0, 0]],
];

/// 群的阶 N(t) = 36t^4 + 36t^3 + 18t^2 + 6t + 1
///
/// n =  B6400000 02A3A6F1 D603AB4F F58EC744 49F2934B 18EA8BEE E56EE19C D69ECF25
pub(crate) const SM9_N: U256 = [
    0xe56ee19cd69ecf25,
    0x49f2934b18ea8bee,
    0xd603ab4ff58ec744,
    0xb640000002a3a6f1,
];

/// 2^256 - n
pub(crate) const SM9_N_NEG: U256 = [
    0x1a911e63296130db,
    0xb60d6cb4e7157411,
    0x29fc54b00a7138bb,
    0x49bffffffd5c590e,
];

/// N - 1
pub(crate) const SM9_N_MINUS_ONE: U256 = [
    0xe56ee19cd69ecf24,
    0x49f2934b18ea8bee,
    0xd603ab4ff58ec744,
    0xb640000002a3a6f1,
];

/// N - 2
pub(crate) const SM9_N_MINUS_TWO: U256 = [
    0xe56ee19cd69ecf23,
    0x49f2934b18ea8bee,
    0xd603ab4ff58ec744,
    0xb640000002a3a6f1,
];

pub(crate) const SM9_N_BARRETT_MU: [u64; 5] = [
    0x74df4fd4dfc97c2f,
    0x9c95d85ec9c073b0,
    0x55f73aebdcd1312c,
    0x67980e0beb5759a6,
    0x1,
];

pub(crate) const SM9_U256_N_MINUS_ONE_BARRETT_MU: [u64; 4] = [
    0x74df4fd4dfc97c31,
    0x9c95d85ec9c073b0,
    0x55f73aebdcd1312c,
    0x67980e0beb5759a6,
];

pub(crate) const SM9_HID_ENC: u8 = 0x03;
pub(crate) const SM9_HID_EXCH: u8 = 0x02;
pub(crate) const SM9_HID_SIGN: u8 = 0x01;

pub(crate) const SM9_HASH1_PREFIX: u8 = 0x01;
pub(crate) const SM9_HASH2_PREFIX: u8 = 0x02;

pub(crate) const SM9_POINT_MONT_P1: Point = Point {
    x: [
        0x22e935e29860501b,
        0xa946fd5e0073282c,
        0xefd0cec817a649be,
        0x5129787c869140b5,
    ],
    y: [
        0xee779649eb87f7c7,
        0x15563cbdec30a576,
        0x326353912824efbf,
        0x7215717763c39828,
    ],
    z: [
        0x1a9064d81caeba83,
        0xde0d6cb4e5851124,
        0x29fc54b00a7138ba,
        0x49bffffffd5c590e,
    ],
};

pub(crate) const SM9_TWIST_POINT_MONT_P2: TwistPoint = TwistPoint {
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

