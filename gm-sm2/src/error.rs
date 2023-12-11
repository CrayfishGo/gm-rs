use std::fmt::Display;
use std::fmt::Formatter;

pub type Sm2Result<T> = Result<T, Sm2Error>;

#[derive(PartialEq)]
pub enum Sm2Error {
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

impl ::std::fmt::Debug for Sm2Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl From<Sm2Error> for &str {
    fn from(e: Sm2Error) -> Self {
        match e {
            Sm2Error::NotOnCurve => "the point not on curve",
            Sm2Error::FieldSqrtError => "field elem sqrt error",
            Sm2Error::InvalidDer => "invalid der",
            Sm2Error::InvalidPublic => "invalid public key",
            Sm2Error::InvalidPrivate => "invalid private key",
            Sm2Error::ZeroDivisor => "zero has no inversion",
            Sm2Error::ZeroPoint => "cannot convert the infinite point to affine",
            Sm2Error::InvalidPoint => "invalid jacobian point",
            Sm2Error::CheckPointErr => "check point error",
            Sm2Error::ZeroData => "the vector is zero",
            Sm2Error::HashNotEqual => "hash not equal",
            Sm2Error::IdTooLong => "ID is too long",
            Sm2Error::ZeroFiled => "zero has no inversion in filed",
            Sm2Error::InvalidFieldLen => "a SCA-256 field element must be 32-byte long",
            Sm2Error::ZeroSig => "the signature is zero, cannot sign",
            Sm2Error::InvalidDigestLen => "the length of digest must be 32-bytes",
            Sm2Error::InvalidSecretKey => "invalid secret key",
            Sm2Error::KdfHashError => "KDF hash error",
            Sm2Error::InvalidDigest => "invalid signature digest",
        }
    }
}

impl Display for Sm2Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let err_msg = match self {
            Sm2Error::NotOnCurve => "the point not on curve",
            Sm2Error::FieldSqrtError => "field elem sqrt error",
            Sm2Error::InvalidDer => "invalid der",
            Sm2Error::InvalidPublic => "invalid public key",
            Sm2Error::InvalidPrivate => "invalid private key",
            Sm2Error::ZeroDivisor => "zero has no inversion",
            Sm2Error::ZeroPoint => "cannot convert the infinite point to affine",
            Sm2Error::InvalidPoint => "invalid jacobian point",
            Sm2Error::CheckPointErr => "check point error",
            Sm2Error::ZeroData => "the vector is zero",
            Sm2Error::HashNotEqual => "hash and cipher not equal",
            Sm2Error::IdTooLong => "ID is too long",
            Sm2Error::ZeroFiled => "zero has no inversion in filed",
            Sm2Error::InvalidFieldLen => "a SCA-256 field element must be 32-byte long",
            Sm2Error::ZeroSig => "the signature is zero, cannot sign",
            Sm2Error::InvalidDigestLen => "the length of digest must be 32-bytes",
            Sm2Error::InvalidSecretKey => "invalid secret key",
            Sm2Error::KdfHashError => "KDF hash error",
            Sm2Error::InvalidDigest => "invalid signature digest",
        };
        write!(f, "{}", err_msg)
    }
}
