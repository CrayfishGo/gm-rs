# gm-sm4

A Pure Rust High-Performance Implementation of China's Standards of Encryption Algorithms SM4


## Example

```rust
use gm_sm4::Sm4Cipher;
use hex_literal::hex;

fn main() {
    let key = hex!("0123456789abcdeffedcba9876543210");
    let plaintext = key.clone();
    let ciphertext = hex!("681edf34d206965e86b3e94f536e4246");

    let cipher = Sm4Cipher::new(&key).unwrap();

    let enc = cipher.encrypt(&plaintext).unwrap();
    assert_eq!(&ciphertext, enc.as_slice());
}

```
