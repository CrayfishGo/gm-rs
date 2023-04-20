# gm-sm3

A Pure Rust High-Performance Implementation of China's Standards of Encryption Algorithms SM3



## Example

```rust
use gm_sm3::sm3_hash;

fn main() {
    let hash = sm3_hash(b"abc");
    let r = hex::encode(hash);
    assert_eq!("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", r);
}

```
