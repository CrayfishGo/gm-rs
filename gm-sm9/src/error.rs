use std::fmt::Display;
use std::fmt::Formatter;

pub type Sm9Result<T> = Result<T, Sm9Error>;

#[derive(PartialEq)]
pub enum Sm9Error {
    NotOnCurve,
    FieldSqrtError,
    InvalidDer,
    InvalidPublic,
    InvalidPrivate,
    ZeroDivisor,
    ZeroPoint,
    InvalidPoint,
    CheckPointErr,
    ZeroData,
    HashNotEqual,
    IdTooLong,
    ZeroFiled,
    InvalidFieldLen,
    ZeroSig,
    InvalidDigestLen,
    InvalidDigest,
    InvalidSecretKey,
    KdfHashError,
}

impl ::std::fmt::Debug for Sm9Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl From<Sm9Error> for &str {
    fn from(e: Sm9Error) -> Self {
        match e {
            Sm9Error::NotOnCurve => "the point not on curve",
            Sm9Error::FieldSqrtError => "field elem sqrt error",
            Sm9Error::InvalidDer => "invalid der",
            Sm9Error::InvalidPublic => "invalid public key",
            Sm9Error::InvalidPrivate => "invalid private key",
            Sm9Error::ZeroDivisor => "zero has no inversion",
            Sm9Error::ZeroPoint => "cannot convert the infinite point to affine",
            Sm9Error::InvalidPoint => "invalid jacobian point",
            Sm9Error::CheckPointErr => "check point error",
            Sm9Error::ZeroData => "the vector is zero",
            Sm9Error::HashNotEqual => "hash not equal",
            Sm9Error::IdTooLong => "ID is too long",
            Sm9Error::ZeroFiled => "zero has no inversion in filed",
            Sm9Error::InvalidFieldLen => "a SCA-256 field element must be 32-byte long",
            Sm9Error::ZeroSig => "the signature is zero, cannot sign",
            Sm9Error::InvalidDigestLen => "the length of digest must be 32-bytes",
            Sm9Error::InvalidSecretKey => "invalid secret key",
            Sm9Error::KdfHashError => "KDF hash error",
            Sm9Error::InvalidDigest => "invalid signature digest",
        }
    }
}

impl Display for Sm9Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let err_msg = match self {
            Sm9Error::NotOnCurve => "the point not on curve",
            Sm9Error::FieldSqrtError => "field elem sqrt error",
            Sm9Error::InvalidDer => "invalid der",
            Sm9Error::InvalidPublic => "invalid public key",
            Sm9Error::InvalidPrivate => "invalid private key",
            Sm9Error::ZeroDivisor => "zero has no inversion",
            Sm9Error::ZeroPoint => "cannot convert the infinite point to affine",
            Sm9Error::InvalidPoint => "invalid jacobian point",
            Sm9Error::CheckPointErr => "check point error",
            Sm9Error::ZeroData => "the vector is zero",
            Sm9Error::HashNotEqual => "hash and cipher not equal",
            Sm9Error::IdTooLong => "ID is too long",
            Sm9Error::ZeroFiled => "zero has no inversion in filed",
            Sm9Error::InvalidFieldLen => "a SCA-256 field element must be 32-byte long",
            Sm9Error::ZeroSig => "the signature is zero, cannot sign",
            Sm9Error::InvalidDigestLen => "the length of digest must be 32-bytes",
            Sm9Error::InvalidSecretKey => "invalid secret key",
            Sm9Error::KdfHashError => "KDF hash error",
            Sm9Error::InvalidDigest => "invalid signature digest",
        };
        write!(f, "{}", err_msg)
    }
}
