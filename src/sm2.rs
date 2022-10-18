use crate::sm2::key::{Sm2PrivateKey, Sm2PublicKey};
use num_bigint::BigUint;
use num_integer::Integer;

pub mod error;
pub mod key;
pub mod p256_ecc;
pub mod field;
mod macros;

#[macro_export]
macro_rules! format_hex {
    ($a: expr) => {
        format!("{:0width$x}", $a, width = 64)
    };

    ($a: expr, $b: expr) => {
        format!("{:0width$x}{:0width$x}", $a, $b, width = 64)
    };

    ($a: expr, $($b: tt)*) => {
        format!("{:0width$x}{}", $a, format_hex!($($b)*), width = 64)
    }
}

/// A Mod B = A-(A/B)*B
pub trait ModOperation {

    /// Returns `(self + other) % modulus`.
    ///
    /// Panics if the modulus is zero.
    fn modadd(&self, other: &Self, modulus: &Self) -> BigUint;

    /// Returns `(self - other) % modulus`.
    ///
    /// Panics if the modulus is zero.
    fn modsub(&self, other: &Self, modulus: &Self) -> BigUint;

    /// Returns `(self * other) % modulus`.
    ///
    /// Panics if the modulus is zero.
    fn modmul(&self, other: &Self, modulus: &Self) -> BigUint;
}

impl ModOperation for BigUint {
    fn modadd(&self, other: &Self, modulus: &Self) -> BigUint {
        (self + other) % modulus
    }

    fn modsub(&self, other: &Self, modulus: &Self) -> BigUint {
        if self >= other {
            (self - other) % modulus
        } else {
            // 负数取模
            let d = other - self;
            let e = d.div_ceil(modulus);
            e * modulus - d
        }
    }

    fn modmul(&self, other: &Self, modulus: &Self) -> BigUint {
        (self * other) % modulus
    }
}
