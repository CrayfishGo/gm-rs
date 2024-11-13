use crate::fields::{mod_n_add, mod_n_from_hash, mod_n_inv, mod_n_mul, FieldElement, SM9_N_MINUS_ONE};
use crate::points::{Point, TwistPoint};
use crate::u256::{sm9_random_u256, U256};
use gm_sm3::sm3_hash;

const SM9_HID_ENC: u8 = 0x03;
const SM9_HASH1_PREFIX: u8 = 0x01;

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
        unimplemented!()
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

        assert_eq!(true, r.unwrap().de.point_equals(&r_de));
    }
}
