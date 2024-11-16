use crate::fields::{mod_n_add, mod_n_from_hash, mod_n_inv, mod_n_mul, FieldElement};
use crate::points::{sm9_u256_pairing, Point, TwistPoint};
use crate::u256::{sm9_random_u256, xor, U256};
use crate::{
    SM9_HASH1_PREFIX, SM9_HID_ENC, SM9_HID_SIGN, SM9_N_MINUS_ONE, SM9_POINT_MONT_P1,
    SM9_TWIST_POINT_MONT_P2,
};
use gm_sm3::sm3_hash;

#[derive(Copy, Debug, Clone)]
pub struct Sm9EncKey {
    ppube: Point,
    de: TwistPoint,
}

#[derive(Copy, Debug, Clone)]
pub struct Sm9EncMasterKey {
    ke: U256,
    ppube: Point,
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

        let mut k = [0u8; 32];
        loop {
            // A2: rand r in [1, N-1]
            let r = sm9_random_u256(&SM9_N_MINUS_ONE);

            // A3: C1 = r * Q
            c1 = c1.point_mul(&r);

            // A4: g = e(Ppube, P2)
            let mut g = sm9_u256_pairing(&SM9_TWIST_POINT_MONT_P2, &self.ppube);

            // A5: w = g^r
            g = g.pow(&r);

            // A6: K = KDF(C || w || ID_B, klen), if K == 0, goto A2
            let mut k_append: Vec<u8> = vec![];
            k_append.push(0x04);
            k_append.extend_from_slice(&c1.x.to_bytes_be());
            k_append.extend_from_slice(&c1.y.to_bytes_be());
            k_append.extend_from_slice(&g.to_bytes_be());
            k_append.extend_from_slice(idb);
            k = sm3_hash(&k_append);
            fn is_zero(x: &[u8; 32]) -> bool {
                x.iter().all(|&byte| byte == 0)
            }

            if !is_zero(&k) {
                break;
            }
        }

        let k1 = &k[0..data.len()];
        let k2 = &k[data.len()..];
        let c2 = xor(k1, &data, data.len());

        let c3 = sm3_hmac(k2, c2.as_slice());

        let mut c: Vec<u8> = vec![];
        c.extend_from_slice(&c1.x.to_bytes_be());
        c.extend_from_slice(&c1.y.to_bytes_be());
        c.extend_from_slice(&c3);
        c.extend_from_slice(&c2);
        c
    }

    pub fn extract_key(&self, idb: &[u8]) -> Option<Sm9EncKey> {
        // t1 = H1(ID || hid, N) + ke
        let mut t = sm9_u256_hash1(idb, SM9_HID_ENC);
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

fn sm3_hmac(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];

    // 如果密钥长度大于 BLOCK_SIZE，先进行哈希
    let mut key = if key.len() > BLOCK_SIZE {
        sm3_hash(key).to_vec()
    } else {
        key.to_vec()
    };

    // 如果密钥长度小于 BLOCK_SIZE，用 0x00 填充到 BLOCK_SIZE
    key.resize(BLOCK_SIZE, 0);

    // 准备 ipad 和 opad
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
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

#[derive(Copy, Debug, Clone)]
pub struct Sm9SignKey {
    ppube: TwistPoint,
    ds: Point,
}

#[derive(Copy, Debug, Clone)]
pub struct Sm9SignMasterKey {
    ks: U256,
    ppube: TwistPoint,
}

impl Sm9SignMasterKey {
    pub fn master_key_generate() -> Self {
        // k = rand(1, n-1)
        let ks = sm9_random_u256(&SM9_N_MINUS_ONE);
        Self {
            ks,
            ppube: TwistPoint::g_mul(&ks), // Ppubs = k * P2 in E'(F_p^2)
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
            ppube: self.ppube,
            ds: Point::g_mul(&t),
        })
    }
}

#[cfg(test)]
mod sm9_key_test {
    use crate::key::Sm9EncMasterKey;
    use crate::points::{Point, TwistPoint};
    use crate::u256::u256_from_be_bytes;

    #[test]
    fn test_encrypt() {
        let data: [u8; 20] = [
            0x43, 0x68, 0x69, 0x6E, 0x65, 0x73, 0x65, 0x20, 0x49, 0x42, 0x53, 0x20, 0x73, 0x74,
            0x61, 0x6E, 0x64, 0x61, 0x72, 0x64,
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

        let ret = msk.encrypt(&idb, &data);

        assert_eq!(true, r.unwrap().de.point_equals(&r_de));
    }
}
