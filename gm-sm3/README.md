# gm-rs

A Pure Rust High-Performance Implementation of China's Standards of Encryption Algorithms SM3

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
gm-sm3 = "0.9.0"
```

## Example

```rust
use crate::sm3_hash;

fn main() {
    let hash = sm3_hash(b"abc");
    let r = hex::encode(hash.as_ref().unwrap());
    assert_eq!("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", r);
}

```