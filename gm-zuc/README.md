# gm-zuc

A Pure Rust High-Performance Implementation of China's Standards of Encryption Algorithms ZUC


## Example

```rust
use gm_zuc::ZUC;

fn main() {
    let key = [0u8; 16];
    let iv = [0u8; 16];
    let mut zuc = ZUC::new(&key, &iv);
    let rs = zuc.generate_keystream(2);
    for z in rs {
        println!("{:x}", z)
    }
}

```

### 128-EEA3
```rust
use crate::eea::EEA;
fn main(){
    let ck: [u8; 16] = [
        0x17, 0x3d, 0x14, 0xba, 0x50, 0x03, 0x73, 0x1d, 0x7a, 0x60, 0x04, 0x94, 0x70, 0xf0,
        0x0a, 0x29,
    ];

    let count = 0x66035492_u32;
    let bearer = 0xf_u32;
    let direction = 0_u32;
    let length = 0xc1_u32;

    let ibs: [u32; 7] = [
        0x6cf65340, 0x735552ab, 0x0c9752fa, 0x6f9025fe, 0x0bd675d9, 0x005875b2, 0x00000000,
    ];

    let obs: [u32; 7] = [
        0xa6c85fc6, 0x6afb8533, 0xaafc2518, 0xdfe78494, 0x0ee1e4b0, 0x30238cc8, 0x00000000,
    ];

    // encrypt
    let mut eea = EEA::new(&ck, count, bearer, direction);
    let rs = eea.encrypt(&ibs, length);
    assert_eq!(obs, rs.as_slice());

    // decrypt
    let mut eea = EEA::new(&ck, count, bearer, direction);
    let rs = eea.encrypt(&rs, length);
    assert_eq!(ibs, rs.as_slice());
}

```

### 123-EIA3
```rust
use crate::eia::EIA;
fn main(){
    let ik: [u8; 16] = [
        0xc9, 0xe6, 0xce, 0xc4, 0x60, 0x7c, 0x72, 0xdb, 0x00, 0x0a, 0xef, 0xa8, 0x83, 0x85,
        0xab, 0x0a,
    ];

    let count = 0xa94059da_u32;
    let bearer = 0x0a_u32;
    let direction = 0x01_u32;
    let length = 0x0241_u32;

    let m: [u32; 19] = [
        0x983b41d4, 0x7d780c9e, 0x1ad11d7e, 0xb70391b1, 0xde0b35da, 0x2dc62f83, 0xe7b78d63,
        0x06ca0ea0, 0x7e941b7b, 0xe91348f9, 0xfcb170e2, 0x217fecd9, 0x7f9f68ad, 0xb16e5d7d,
        0x21e569d2, 0x80ed775c, 0xebde3f40, 0x93c53881, 0x00000000,
    ];

    let mac = 0xfae8ff0b_u32;

    let mut eia = EIA::new(&ik, count, bearer, direction);
    let rs = eia.gen_mac(&m, length);
    assert_eq!(mac, rs);
}

```