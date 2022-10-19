pub mod sm3;
pub mod sm2;

/// This Rust crate can be used to interact with the Google Authenticator mobile app for 2-factor-authentication.
/// This Rust crates can generate secrets, generate codes, validate codes and present a QR-Code for scanning the secret.
/// It implements TOTP according to RFC6238
/// # Example
/// ```rust
/// use crate::gm_rs::sm3::sm3_hash;
/// fn main(){
///     let hash = sm3_hash(b"abc");
///     let r = hex::encode(hash.as_ref().unwrap());
///     assert_eq!("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", r);
/// }
///
/// ```
///
#[cfg(test)]
mod test {
    use crate::sm3::sm3_hash;

    #[test]
    fn test_hash_1() {
        let hash = sm3_hash(b"abc");
        let r = hex::encode(hash);
        assert_eq!("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", r);
    }

    #[test]
    fn test_hash_2() {
        let hash = sm3_hash(b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");
        let r = hex::encode(hash);
        assert_eq!("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732", r);
    }
}
