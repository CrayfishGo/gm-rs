use std::str::FromStr;

use pkcs8::{DecodePublicKey, der, Document, EncodePrivateKey, EncodePublicKey, PrivateKeyInfo, SecretDocument, SubjectPublicKeyInfoRef};
use pkcs8::der::{Decode, Encode};
use pkcs8::der::zeroize::Zeroizing;
use sec1::EcPrivateKey;

use crate::{ALGORITHM_IDENTIFIER, ALGORITHM_OID, OID_SM2_PKCS8};
use crate::error::Sm2Result;
use crate::key::{Sm2PrivateKey, Sm2PublicKey};
use crate::p256_ecc::Point;

impl Sm2PrivateKey {
    pub fn to_sec1_der(&self) -> der::Result<Zeroizing<Vec<u8>>> {
        let private_key_bytes = Zeroizing::new(self.d.to_bytes_be());
        let public_key_bytes = self.public_key.to_bytes(false);

        let ec_private_key = Zeroizing::new(
            EcPrivateKey {
                private_key: &private_key_bytes,
                parameters: None,
                public_key: Some(&public_key_bytes),
            }
                .to_der()?,
        );

        Ok(ec_private_key)
    }
}

impl TryFrom<EcPrivateKey<'_>> for Sm2PrivateKey {
    type Error = der::Error;

    fn try_from(sec1_private_key: EcPrivateKey<'_>) -> Result<Self, Self::Error> {
        let sk = Self::new(sec1_private_key.private_key).map_err(|_| der::Tag::Sequence.value_error())?;

        if let Some(pk_bytes) = sec1_private_key.public_key {
            let pk = Point::from_byte(pk_bytes)
                .map_err(|_| der::Tag::BitString.value_error())?;

            if validate_public_key(&sk, &pk).is_err() {
                return Err(der::Tag::BitString.value_error());
            }
        }
        Ok(sk)
    }
}

#[allow(unused_variables)]
fn validate_public_key(p0: &Sm2PrivateKey, p1: &Point) -> Sm2Result<()> {
    // Provide a default "always succeeds" implementation.
    // This is the intended default for curve implementations which
    // do not provide an arithmetic implementation, since they have no
    // way to verify this.
    //
    Ok(())
}

impl TryFrom<PrivateKeyInfo<'_>> for Sm2PrivateKey {
    type Error = pkcs8::Error;

    fn try_from(pki: PrivateKeyInfo<'_>) -> Result<Self, Self::Error> {
        pki.algorithm.assert_oids(ALGORITHM_OID, OID_SM2_PKCS8)?;
        let ec_private_key = EcPrivateKey::from_der(pki.private_key)?;
        Ok(Self::try_from(ec_private_key)?)
    }
}

impl TryFrom<SubjectPublicKeyInfoRef<'_>> for Sm2PublicKey {
    type Error = pkcs8::spki::Error;

    fn try_from(spki: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Self::Error> {
        spki.algorithm.assert_oids(ALGORITHM_OID, OID_SM2_PKCS8)?;
        let public_key_bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| der::Tag::BitString.value_error())?;
        Ok(Sm2PublicKey::new(public_key_bytes).unwrap())
    }
}

impl EncodePrivateKey for Sm2PrivateKey {
    fn to_pkcs8_der(&self) -> pkcs8::Result<SecretDocument> {
        let algorithm_identifier = pkcs8::AlgorithmIdentifierRef {
            oid: ALGORITHM_OID,
            parameters: Some((&OID_SM2_PKCS8).into()),
        };
        let ec_private_key = self.to_sec1_der()?;
        let pkcs8_key = PrivateKeyInfo::new(algorithm_identifier, &ec_private_key);
        Ok(SecretDocument::encode_msg(&pkcs8_key)?)
    }
}

impl EncodePublicKey for Sm2PublicKey {
    fn to_public_key_der(&self) -> pkcs8::spki::Result<Document> {
        let public_key_bytes = self.to_bytes(false);
        let subject_public_key = der::asn1::BitStringRef::new(0, &public_key_bytes)?;

        pkcs8::SubjectPublicKeyInfo {
            algorithm: ALGORITHM_IDENTIFIER,
            subject_public_key,
        }
            .try_into()
    }
}


impl FromStr for Sm2PublicKey {
    type Err = pkcs8::spki::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_public_key_pem(s).map_err(|e| e)
    }
}

#[cfg(test)]
mod test_pkcs {
    use pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding};

    use crate::key::{gen_keypair, Sm2Model, Sm2PrivateKey, Sm2PublicKey};

    #[test]
    fn test_pkcs8() {
        let (pk, sk) = gen_keypair().unwrap();
        let msg = "你好 world,asjdkajhdjadahkubbhj12893718927391873891,@@！！ world,1231 wo12321321313asdadadahello world，hello world".as_bytes();
        let encrypt = pk.encrypt(msg, false, Sm2Model::C1C2C3).unwrap();
        let plain = sk.decrypt(&encrypt, false, Sm2Model::C1C2C3).unwrap();
        let pub_str = pk.to_public_key_pem(LineEnding::CRLF);
        let pri_str = sk.to_pkcs8_pem(LineEnding::CRLF);
        println!("{:?}", pub_str);
        println!("{:?}", pri_str);

        println!("pub key: {:?}", pk);
        println!("pri key: {:?}", sk);

        let sk2 = Sm2PrivateKey::from_pkcs8_der(pri_str.unwrap().as_str().as_bytes());
        let pk2 = Sm2PublicKey::from_public_key_pem(pub_str.unwrap().as_str());
        println!("pub2 key: {:?}", pk2);
        println!("pri2 key: {:?}", sk2);
        assert_eq!(msg, plain)
    }
}