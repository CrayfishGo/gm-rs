# gm-rs

A Pure Rust High-Performance Implementation of China's Standards of Encryption Algorithms SM4

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
gm-sm4 = "0.9.0"
```

## Example

```rust
use crate::Sm4Cipher;
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
