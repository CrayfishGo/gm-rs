use crate::error::{Sm9Error, Sm9Result};
use crate::fields::{mod_n_add, mod_n_from_hash, mod_n_inv, mod_n_mul, mod_n_sub, FieldElement};
use crate::points::{sm9_u256_pairing, twist_point_add_full, Point, TwistPoint};
use crate::u256::{sm9_random_u256, u256_cmp, xor, U256};
use crate::{
    SM9_HASH1_PREFIX, SM9_HASH2_PREFIX, SM9_HID_ENC, SM9_HID_EXCH, SM9_HID_SIGN, SM9_N_MINUS_ONE,
    SM9_POINT_MONT_P1, SM9_TWIST_POINT_MONT_P2,
};
use gm_sm3::sm3_hash;

#[derive(Copy, Debug, Clone)]
pub struct Sm9EncKey {
    pub ppube: Point,
    pub de: TwistPoint,
}

#[derive(Copy, Debug, Clone)]
pub struct Sm9EncMasterKey {
    pub ke: U256,
    pub ppube: Point,
}

pub fn generate_sign_master_key() -> Sm9SignMasterKey {
    let ks = sm9_random_u256(&SM9_N_MINUS_ONE);
    Sm9SignMasterKey {
        ks,
        ppubs: TwistPoint::g_mul(&ks),
    }
}

pub fn generate_enc_master_key() -> Sm9EncMasterKey {
    let ke = sm9_random_u256(&SM9_N_MINUS_ONE);
    Sm9EncMasterKey {
        ke,
        ppube: Point::g_mul(&ke),
    }
}

impl Sm9EncKey {
    pub fn decrypt(&self, idb: &[u8], data: &[u8]) -> Sm9Result<Vec<u8>> {
        let c1_bytes = &data[0..65];
        let c2 = &data[(65 + 32)..];
        let c3 = &data[65..(65 + 32)];
        let c1 = Point::from_bytes(c1_bytes);
        let w = sm9_u256_pairing(&self.de, &c1);
        let w_bytes = w.to_bytes_be();
        let mut k_append: Vec<u8> = vec![];
        k_append.extend_from_slice(&c1_bytes[1..65]);
        k_append.extend_from_slice(&w_bytes);
        k_append.extend_from_slice(idb);
        let k = kdf(&k_append, (255 + 32) as usize);
        fn is_zero(x: &Vec<u8>) -> bool {
            x.iter().all(|&byte| byte == 0)
        }

        if !is_zero(&k) {
            let k = k.as_slice();
            let mlen = data.len() - (65 + 32);
            let k1 = &k[0..mlen];
            let k2 = &k[mlen..];
            let u = sm3_hmac(k2, c2, 32);
            if !u.as_slice().eq(c3) {
                return Err(Sm9Error::InvalidDigest);
            }
            let m = xor(c2, &k1, k1.len());
            Ok(m)
        } else {
            Err(Sm9Error::KdfHashError)
        }
    }
}

impl Sm9EncMasterKey {
    pub fn master_key_generate() -> Sm9EncMasterKey {
        // k = rand(1, n-1)
        let ke = sm9_random_u256(&SM9_N_MINUS_ONE);
        Self {
            ke,
            ppube: Point::g_mul(&ke), // Ppube = ke * P1 in E(F_p)
        }
    }

    pub fn encrypt(&self, idb: &[u8], data: &[u8]) -> Vec<u8> {
        // A1: Q = H1(ID||hid,N) * P1 + Ppube
        let t = sm9_u256_hash1(idb, SM9_HID_ENC);
        let mut c1 = SM9_POINT_MONT_P1.point_mul(&t);
        c1 = c1.point_add(&self.ppube);

        let mut k = vec![];
        loop {
            // A2: rand r in [1, N-1]
            let r = sm9_random_u256(&SM9_N_MINUS_ONE);

            // A3: C1 = r * Q
            c1 = c1.point_mul(&r);
            let cbuf = c1.to_bytes_be();
            let cbuf = cbuf.as_slice();

            // A4: g = e(Ppube, P2)
            let mut g = sm9_u256_pairing(&SM9_TWIST_POINT_MONT_P2, &self.ppube);

            // A5: w = g^r
            g = g.pow(&r);
            let gbuf = g.to_bytes_be();
            let gbuf = gbuf.as_slice();

            // A6: K = KDF(C || w || ID_B, klen), if K == 0, goto A2
            let mut k_append: Vec<u8> = vec![];
            // k_append.push(0x04);
            k_append.extend_from_slice(&cbuf[1..cbuf.len()]);
            k_append.extend_from_slice(gbuf);
            k_append.extend_from_slice(idb);
            k = kdf(&k_append, (255 + 32) as usize);
            fn is_zero(x: &Vec<u8>) -> bool {
                x.iter().all(|&byte| byte == 0)
            }

            if !is_zero(&k) {
                break;
            }
        }

        let k1 = &k[0..data.len()];
        let k2 = &k[data.len()..];
        let c2 = xor(k1, &data, data.len());
        let c3 = sm3_hmac(k2, &c2, 32usize);
        let mut c: Vec<u8> = vec![];
        c.extend_from_slice(&c1.to_bytes_be());
        c.extend_from_slice(&c3);
        c.extend_from_slice(&c2);
        c
    }

    pub fn extract_key(&self, id: &[u8]) -> Option<Sm9EncKey> {
        // t1 = H1(ID || hid, N) + ke
        let mut t = sm9_u256_hash1(id, SM9_HID_ENC);
        t = mod_n_add(&t, &self.ke);
        if t.is_zero() {
            return None;
        }
        // t2 = ks * t1^-1
        t = mod_n_inv(&t);

        // ds = t2 * P1
        t = mod_n_mul(&t, &self.ke);
        Some(Sm9EncKey {
            ppube: self.ppube,
            de: TwistPoint::g_mul(&t),
        })
    }

    pub fn extract_exch_key(&self, id: &[u8]) -> Option<Sm9EncKey> {
        // t1 = H1(ID || hid, N) + ke
        let mut t = sm9_u256_hash1(id, SM9_HID_EXCH);
        t = mod_n_add(&t, &self.ke);
        if t.is_zero() {
            return None;
        }
        // t2 = ks * t1^-1
        t = mod_n_inv(&t);

        // ds = t2 * P1
        t = mod_n_mul(&t, &self.ke);
        Some(Sm9EncKey {
            ppube: self.ppube,
            de: TwistPoint::g_mul(&t),
        })
    }
}

const BLOCK_SIZE: usize = 64;

fn sm3_hmac(key: &[u8], message: &[u8], klen: usize) -> Vec<u8> {
    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];

    let mut key_block = [0u8; 64];

    // 如果密钥长度大于 BLOCK_SIZE，先进行哈希
    if klen > BLOCK_SIZE {
        key_block[..32].copy_from_slice(&sm3_hash(key));
    } else {
        key_block[..klen].copy_from_slice(&key[0..klen]);
    };

    // 准备 ipad 和 opad
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    // 内层哈希: H((K ^ ipad) || message)
    let mut ipad_append = vec![];
    ipad_append.extend_from_slice(&ipad);
    ipad_append.extend_from_slice(message);
    let inner_result = sm3_hash(&ipad_append);

    // 外层哈希: H((K ^ opad) || inner_result)
    let mut opad_append = vec![];
    opad_append.extend_from_slice(&opad);
    opad_append.extend_from_slice(&inner_result);
    sm3_hash(&opad_append).to_vec()
}

fn sm9_u256_hash1(id: &[u8], hid: u8) -> U256 {
    let ct1: [u8; 4] = [0x00, 0x00, 0x00, 0x01];
    let ct2: [u8; 4] = [0x00, 0x00, 0x00, 0x02];
    let mut c3_append: Vec<u8> = vec![];
    c3_append.extend_from_slice(&vec![SM9_HASH1_PREFIX]);
    c3_append.extend_from_slice(id);
    c3_append.extend_from_slice(&vec![hid]);
    c3_append.extend_from_slice(&ct1);
    let ha1 = sm3_hash(&c3_append);

    let mut c3_append2: Vec<u8> = vec![];
    c3_append2.extend_from_slice(&vec![SM9_HASH1_PREFIX]);
    c3_append2.extend_from_slice(id);
    c3_append2.extend_from_slice(&vec![hid]);
    c3_append2.extend_from_slice(&ct2);
    let ha2 = sm3_hash(&c3_append2);

    let mut ha = vec![];
    ha.extend_from_slice(&ha1);
    ha.extend_from_slice(&ha2);
    let r = mod_n_from_hash(&ha);
    r
}

fn sm9_u256_hash2(data: &[u8], wbuf: &[u8]) -> U256 {
    let ct1: [u8; 4] = [0x00, 0x00, 0x00, 0x01];
    let ct2: [u8; 4] = [0x00, 0x00, 0x00, 0x02];
    let mut c3_append: Vec<u8> = vec![];
    c3_append.extend_from_slice(&vec![SM9_HASH2_PREFIX]);
    c3_append.extend_from_slice(data);
    c3_append.extend_from_slice(wbuf);
    c3_append.extend_from_slice(&ct1);
    let ha1 = sm3_hash(&c3_append);

    let mut c3_append2: Vec<u8> = vec![];
    c3_append2.extend_from_slice(&vec![SM9_HASH2_PREFIX]);
    c3_append2.extend_from_slice(data);
    c3_append2.extend_from_slice(wbuf);
    c3_append2.extend_from_slice(&ct2);
    let ha2 = sm3_hash(&c3_append2);

    let mut ha = vec![];
    ha.extend_from_slice(&ha1);
    ha.extend_from_slice(&ha2);
    let r = mod_n_from_hash(&ha);
    r
}

fn kdf(z: &[u8], klen: usize) -> Vec<u8> {
    let mut ct = 0x00000001u32;
    let bound = ((klen as f64) / 32.0).ceil() as u32;
    let mut h_a = Vec::new();
    for _i in 1..bound {
        let mut prepend = Vec::new();
        prepend.extend_from_slice(z);
        prepend.extend_from_slice(&ct.to_be_bytes());

        let h_a_i = sm3_hash(&prepend[..]);
        h_a.extend_from_slice(&h_a_i);
        ct += 1;
    }

    let mut prepend = Vec::new();
    prepend.extend_from_slice(z);
    prepend.extend_from_slice(&ct.to_be_bytes());

    let last = sm3_hash(&prepend[..]);
    if klen % 32 == 0 {
        h_a.extend_from_slice(&last);
    } else {
        h_a.extend_from_slice(&last[0..(klen % 32)]);
    }
    h_a
}

#[derive(Copy, Debug, Clone)]
pub struct Sm9SignKey {
    pub ppubs: TwistPoint,
    pub ds: Point,
}

impl Sm9SignKey {
    /// return (h, S)
    pub fn sign(&self, data: &[u8]) -> Sm9Result<(U256, Point)> {
        // A1: g = e(P1, Ppubs)
        let g = sm9_u256_pairing(&self.ppubs, &SM9_POINT_MONT_P1);
        let mut h: U256 = [0, 0, 0, 0];
        let mut r: U256 = [0, 0, 0, 0];
        loop {
            // A2: rand r in [1, N-1]
            r = sm9_random_u256(&SM9_N_MINUS_ONE);

            // A3: w = g^r
            let w = g.pow(&r);
            let wbuf = w.to_bytes_be();
            let wbuf = wbuf.as_slice();

            // A4: h = H2(M || w, N)
            h = sm9_u256_hash2(data, wbuf);

            // A5: l = (r - h) mod N, if l = 0, goto A2
            r = mod_n_sub(&r, &h);

            if !r.is_zero() {
                break;
            }
        }

        // A6: S = l * dsA
        let s = self.ds.point_mul(&r);

        Ok((h, s))
    }
}

#[derive(Copy, Debug, Clone)]
pub struct Sm9SignMasterKey {
    pub ks: U256,
    pub ppubs: TwistPoint,
}

impl Sm9SignMasterKey {
    pub fn master_key_generate() -> Self {
        // k = rand(1, n-1)
        let ks = sm9_random_u256(&SM9_N_MINUS_ONE);
        Self {
            ks,
            ppubs: TwistPoint::g_mul(&ks), // Ppubs = k * P2 in E'(F_p^2)
        }
    }

    pub fn extract_key(&self, idb: &[u8]) -> Option<Sm9SignKey> {
        // t1 = H1(ID || hid, N) + ks
        let mut t = sm9_u256_hash1(idb, SM9_HID_SIGN);
        t = mod_n_add(&t, &self.ks);
        if t.is_zero() {
            return None;
        }
        // t2 = ks * t1^-1
        t = mod_n_inv(&t);

        // ds = t2 * P1
        t = mod_n_mul(&t, &self.ks);
        Some(Sm9SignKey {
            ppubs: self.ppubs,
            ds: Point::g_mul(&t),
        })
    }

    pub fn verify_sign(&self, id: &[u8], data: &[u8], h: &U256, s: &Point) -> Sm9Result<()> {
        let g = sm9_u256_pairing(&self.ppubs, &SM9_POINT_MONT_P1);
        let t = g.pow(h);
        // B5: h1 = H1(ID || hid, N)
        let h1 = sm9_u256_hash1(id, SM9_HID_SIGN);
        let mut p = TwistPoint::g_mul(&h1);
        p = twist_point_add_full(&self.ppubs, &p);

        let u = sm9_u256_pairing(&p, s);
        let w = u.fp_mul(&t);
        let wbuf = w.to_bytes_be();
        let wbuf = wbuf.as_slice();
        let h2 = sm9_u256_hash2(data, wbuf);
        if u256_cmp(&h2, h) != 0 {
            Err(Sm9Error::InvalidDigest)
        } else {
            Ok(())
        }
    }
}

pub fn exch_step_1a(msk: &Sm9EncMasterKey, idb: &[u8]) -> (Point, U256) {
    // A1: Q = H1(ID_B||hid,N) * P1 + Ppube
    let mut ra = sm9_u256_hash1(idb, SM9_HID_EXCH);
    let mut r = SM9_POINT_MONT_P1.point_mul(&ra);
    r = r.point_add(&msk.ppube);

    // A2: rand rA in [1, N-1]
    ra = sm9_random_u256(&SM9_N_MINUS_ONE);
    // ra = u256_from_hex("00005879DD1D51E175946F23B1B41E93BA31C584AE59A426EC1046A4D03B06C8");

    // A3: RA = rA * Q
    r = r.point_mul(&ra);

    (r, ra)
}

pub fn exch_step_1b(
    msk: &Sm9EncMasterKey,
    ida: &[u8],
    idb: &[u8],
    key: &Sm9EncKey,
    ra: &Point,
    klen: usize,
) -> Sm9Result<(Point, Vec<u8>)> {
    // B1: Q = H1(ID_A||hid,N) * P1 + Ppube
    let mut rb = sm9_u256_hash1(ida, SM9_HID_EXCH);
    let mut r = SM9_POINT_MONT_P1.point_mul(&rb);
    r = r.point_add(&msk.ppube);
    let mut sk = vec![];
    loop {
        // B2: rand rB in [1, N-1]
        rb = sm9_random_u256(&SM9_N_MINUS_ONE);

        // rb = u256_from_hex("00018B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE");

        // B3: RB = rB * Q
        r = r.point_mul(&rb);

        // B4: check RA on curve; G1 = e(RA, deB), G2 = e(Ppube, P2) ^ rB, G3 = G1 ^ rB
        if !ra.is_on_curve() {
            return Err(Sm9Error::InvalidPoint);
        }

        let g1 = sm9_u256_pairing(&key.de, &ra);
        let mut g2 = sm9_u256_pairing(&SM9_TWIST_POINT_MONT_P2, &msk.ppube);
        g2 = g2.pow(&rb);
        let g3 = g1.pow(&rb);
        let ta = ra.to_bytes_be();
        let tb = r.to_bytes_be();

        let g1 = g1.to_bytes_be();
        let g2 = g2.to_bytes_be();
        let g3 = g3.to_bytes_be();

        let mut pre_append = vec![];
        pre_append.extend_from_slice(ida);
        pre_append.extend_from_slice(idb);
        pre_append.extend_from_slice(&ta[1..]);
        pre_append.extend_from_slice(&tb[1..]);
        pre_append.extend_from_slice(&g1);
        pre_append.extend_from_slice(&g2);
        pre_append.extend_from_slice(&g3);

        sk = kdf(&pre_append, klen);

        fn is_zero(x: &Vec<u8>, klen: usize) -> bool {
            let mut ret = true;
            for i in 0..klen {
                if x[i] != 0 {
                    ret = false;
                }
            }
            ret
        }

        if !is_zero(&sk, klen) {
            break;
        }
    }
    Ok((r, sk))
}

pub fn exch_step_2a(
    msk: &Sm9EncMasterKey,
    ida: &[u8],
    idb: &[u8],
    key: &Sm9EncKey,
    ra_: U256,
    ra: &Point,
    rb: &Point,
    klen: usize,
) -> Sm9Result<Vec<u8>> {
    let mut sk = vec![];
    loop {
        if !rb.is_on_curve() {
            return Err(Sm9Error::InvalidPoint);
        }

        let mut g1 = sm9_u256_pairing(&SM9_TWIST_POINT_MONT_P2, &msk.ppube);
        g1 = g1.pow(&ra_);

        let g2 = sm9_u256_pairing(&key.de, &rb);
        let g3 = g2.pow(&ra_);

        let ta = ra.to_bytes_be();
        let tb = rb.to_bytes_be();

        let g1 = g1.to_bytes_be();
        let g2 = g2.to_bytes_be();
        let g3 = g3.to_bytes_be();

        let mut pre_append = vec![];
        pre_append.extend_from_slice(ida);
        pre_append.extend_from_slice(idb);
        pre_append.extend_from_slice(&ta[1..]);
        pre_append.extend_from_slice(&tb[1..]);
        pre_append.extend_from_slice(&g1);
        pre_append.extend_from_slice(&g2);
        pre_append.extend_from_slice(&g3);

        sk = kdf(&pre_append, klen);
        fn is_zero(x: &Vec<u8>, klen: usize) -> bool {
            let mut ret = true;
            for i in 0..klen {
                if x[i] != 0 {
                    ret = false;
                }
            }
            ret
        }

        if !is_zero(&sk, klen) {
            break;
        }
    }
    Ok(sk)
}

#[cfg(test)]
mod sm9_key_test {
    use crate::key::{
        exch_step_1a, exch_step_1b, exch_step_2a, Sm9EncKey, Sm9EncMasterKey, Sm9SignMasterKey,
    };
    use crate::points::{Point, TwistPoint};
    use crate::u256::u256_from_be_bytes;

    #[test]
    fn test_encrypt() {
        let data: [u8; 21] = [
            0x43, 0x68, 0x69, 0x6E, 0x65, 0x73, 0x65, 0x20, 0x49, 0x42, 0x53, 0x20, 0x73, 0x74,
            0x61, 0x6E, 0x64, 0x61, 0x72, 0x64, 0x64,
        ];

        let idb = [0x42, 0x6F, 0x62u8];

        let ke = u256_from_be_bytes(
            &hex::decode("0001EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22")
                .unwrap(),
        );

        let msk = Sm9EncMasterKey {
            ke,
            ppube: Point::g_mul(&ke),
        };

        let r = msk.extract_key(&idb);
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

        let ret = msk.encrypt(&idb, &data);
        println!("Message =    {:?}", &data);
        println!("Ciphertext = {:?}", ret);
        let m = r.unwrap().decrypt(&idb, &ret).expect("Decryption failed");
        println!("Plaintext =  {:?}", &m);
        assert_eq!(true, data == m.as_slice());
    }

    #[test]
    fn test_sign_verify() {
        let data: [u8; 20] = [
            0x43, 0x68, 0x69, 0x6E, 0x65, 0x73, 0x65, 0x20, 0x49, 0x42, 0x53, 0x20, 0x73, 0x74,
            0x61, 0x6E, 0x64, 0x61, 0x72, 0x64,
        ];

        let ida = [0x41, 0x6C, 0x69, 0x63, 0x65u8];

        let ks = u256_from_be_bytes(
            &hex::decode("000130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4")
                .unwrap(),
        );
        let msk = Sm9SignMasterKey {
            ks,
            ppubs: TwistPoint::g_mul(&ks),
        };

        let r_ds = Point::from_hex([
            "A5702F05CF1315305E2D6EB64B0DEB923DB1A0BCF0CAFF90523AC8754AA69820",
            "78559A844411F9825C109F5EE3F52D720DD01785392A727BB1556952B2B013D3",
        ]);
        let r = msk.extract_key(&ida);
        let ps = r.unwrap();
        assert_eq!(true, ps.ds.point_equals(&r_ds));

        println!("Message =    {:?}", &data);
        let (h, s) = ps.sign(&data).unwrap();
        println!("Sign H =     {:?}", &h);
        println!("Sign S =     {:?}", &s);

        let r = msk.verify_sign(&ida, &data, &h, &s);
        println!("VersionSign ={:?}", &r);
    }

    #[test]
    fn test_exchange_key() {
        // let ke = u256_from_be_bytes(
        //     &hex::decode("0002E65B0762D042F51F0D23542B13ED8CFA2E9A0E7206361E013A283905E31F")
        //         .unwrap(),
        // );
        // let msk = Sm9EncMasterKey {
        //     ke,
        //     ppube: Point::g_mul(&ke),
        // };
        let msk: Sm9EncMasterKey = Sm9EncMasterKey::master_key_generate();
        let klen = 20usize;
        let ida = [0x41, 0x6C, 0x69, 0x63, 0x65u8];
        let idb = [0x42, 0x6F, 0x62u8];
        let key_a: Sm9EncKey = msk.extract_exch_key(&ida).unwrap();
        let key_b: Sm9EncKey = msk.extract_exch_key(&idb).unwrap();

        let (ra, ra_) = exch_step_1a(&msk, &idb);
        let (rb, skb) = exch_step_1b(&msk, &ida, &idb, &key_b, &ra, klen).unwrap();
        let ska = exch_step_2a(&msk, &ida, &idb, &key_a, ra_, &ra, &rb, klen).unwrap();
        println!("SKB = {:?}", &skb);
        println!("SKA = {:?}", &ska);
        for i in 0..klen {
            if ska[i] != skb[i] {
                println!("Exchange key different at byte index: {}", i)
            }
        }
    }
}
