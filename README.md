# gm-rs
A Rust Implementation of China's Standards of Encryption Algorithms(SM2/SM3/SM4)

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
gm-rs = "0.3.1"
```

## Example

### SM3:

```rust
use crate::sm3::sm3_hash;

fn main() {
    let hash = sm3_hash(b"abc");
    let r = hex::encode(hash.as_ref().unwrap());
    assert_eq!("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", r);
}

```

### SM2:

#### encrypt & decrypt
```rust
 use crate::sm2::key::{gen_keypair, CompressModle};

 fn main(){
    let (pk, sk) = gen_keypair(CompressModle::Compressed).unwrap();
    let msg = "你好 world,asjdkajhdjadahkubbhj12893718927391873891,@@！！ world,1231 wo12321321313asdadadahello world，hello world".as_bytes();
    let encrypt = pk.encrypt(msg).unwrap();
    let plain = sk.decrypt(&encrypt).unwrap();
    assert_eq!(msg, plain)
}

```

