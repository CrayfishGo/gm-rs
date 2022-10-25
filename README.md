# gm-rs

A Pure Rust High-Performance Implementation of China's Standards of Encryption Algorithms(SM2/SM3/SM4)

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
gm-rs = "0.5.1"
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

fn main() {
    let (pk, sk) = gen_keypair(CompressModle::Compressed).unwrap();
    let msg = "你好 world,asjdkajhdjadahkubbhj12893718927391873891,@@！！ world,1231 wo12321321313asdadadahello world，hello world".as_bytes();
    let encrypt = pk.encrypt(msg).unwrap();
    let plain = sk.decrypt(&encrypt).unwrap();
    assert_eq!(msg, plain)
}

```

#### sign & verify

```rust
use crate::sm2::signature;

fn main() {
    let msg = b"hello";
    let (pk, sk) = gen_keypair(CompressModle::Compressed).unwrap();
    let signature = signature::sign(None, msg, &sk.d, &pk).unwrap();
    let r = signature.verify(None, msg, &pk).unwrap();
    println!("test_sign_verify = {}", r)
}

```


#### key exchange
```rust
use crate::sm2::exchange::Exchange;

fn main() {
    let id_a = "alice123@qq.com";
    let id_b = "bob456@qq.com";

    let (pk_a, sk_a) = gen_keypair(CompressModle::Compressed).unwrap();
    let (pk_b, sk_b) = gen_keypair(CompressModle::Compressed).unwrap();

    let mut user_a = Exchange::new(8, Some(id_a), &pk_a, &sk_a, Some(id_b), &pk_b).unwrap();
    let mut user_b = Exchange::new(8, Some(id_b), &pk_b, &sk_b, Some(id_a), &pk_a).unwrap();

    let ra_point = user_a.exchange_1().unwrap();
    let (rb_point, sb) = user_b.exchange_2(&ra_point).unwrap();
    let sa = user_a.exchange_3(&rb_point, sb).unwrap();
    let succ = user_b.exchange_4(sa, &ra_point).unwrap();
    println!("test_key_exchange = {}", succ);
    assert_eq!(user_a.k, user_b.k);
}

```