# gm-sm9

A Pure Rust High-Performance Implementation of China's Standards of Encryption Algorithms SM9


## Example

### encrypt & decrypt
```rust
  use gm_sm9::key::Sm9EncMasterKey;
  use gm_sm9::points::{Point, TwistPoint};
  use gm_sm9::u256::u256_from_be_bytes;

fn main() {
    
    let data: [u8; 21] = [
        0x43, 0x68, 0x69, 0x6E, 0x65, 0x73, 0x65, 0x20, 0x49, 0x42, 0x53, 0x20, 0x73, 0x74,
        0x61, 0x6E, 0x64, 0x61, 0x72, 0x64, 0x64,
    ];
    println!("Message =    {:?}", &data);
    
    let id = [0x42, 0x6F, 0x62u8];
    let ke = u256_from_be_bytes(
        &hex::decode("0001EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22")
            .unwrap(),
    );

    let msk = Sm9EncMasterKey {
        ke,
        ppube: Point::g_mul(&ke),
    };

    let r = msk.extract_key(&id);
    let r_de = TwistPoint::from_hex(
        [
            "115BAE85F5D8BC6C3DBD9E5342979ACCCF3C2F4F28420B1CB4F8C0B59A19B158",
            "94736ACD2C8C8796CC4785E938301A139A059D3537B6414140B2D31EECF41683",
        ],
        [
            "27538A62E7F7BFB51DCE08704796D94C9D56734F119EA44732B50E31CDEB75C1",
            "7AA5E47570DA7600CD760A0CF7BEAF71C447F3844753FE74FA7BA92CA7D3B55F",
        ],
    );
    assert_eq!(true, r.unwrap().de.point_equals(&r_de));

    let ret = msk.encrypt(&id, &data);
    println!("Ciphertext = {:?}", ret);

    let m = r.unwrap().decrypt(&id, &ret).expect("Decryption failed");
    println!("Plaintext =  {:?}", &m);
    assert_eq!(true, data == m.as_slice());
}

```
