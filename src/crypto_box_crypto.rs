use crypto_box::{aead::{Aead, AeadCore, OsRng}, ChaChaBox, KEY_SIZE};
use crypto_box::aead::generic_array::GenericArray;
use anyhow::Result;

pub const NONCE_LEN: usize = 24;




#[derive(Clone)]
pub struct PalCryptoKeyPair{
    pub secret_key_bytes: [u8; KEY_SIZE],
    pub public_key_bytes:  [u8; KEY_SIZE],
}

impl PalCryptoKeyPair {
    pub fn secret_key(&self) -> crypto_box::SecretKey{
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&ed25519_dalek::SecretKey::from(self.secret_key_bytes));
        crypto_box::SecretKey::from(signing_key.to_scalar())
    }

    pub fn make_secret_key(secret_key_bytes: [u8; KEY_SIZE]) -> crypto_box::SecretKey {
        let signing_key = Self::make_signing_key(secret_key_bytes);
        crypto_box::SecretKey::from(signing_key.to_scalar())
    }

    pub fn public_key(&self) -> crypto_box::PublicKey{
        crypto_box::PublicKey::from(ed25519_dalek::VerifyingKey::from_bytes(&self.public_key_bytes).unwrap().to_montgomery())
    }

    pub fn make_public_key(public_key_bytes: [u8; KEY_SIZE]) -> crypto_box::PublicKey {
        crypto_box::PublicKey::from(Self::make_verifying_key(public_key_bytes).to_montgomery())
    }

    pub fn make_signing_key(secret_key_bytes: [u8; KEY_SIZE]) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&ed25519_dalek::SecretKey::from(secret_key_bytes))
    }

    pub fn make_verifying_key(public_key_bytes: [u8; KEY_SIZE]) -> ed25519_dalek::VerifyingKey {
        ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes).unwrap()
    }
}

pub fn generate_pal_key_pair() -> PalCryptoKeyPair {

    let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    PalCryptoKeyPair{
        secret_key_bytes: signing_key.to_bytes(),
        public_key_bytes: signing_key.verifying_key().to_bytes(),
    }
}

pub fn pal_cb_encrypt(public_key_bytes: &[u8], secret_key_bytes: &[u8], plain_bytes: &[u8]) -> Result<Vec<u8>>{
    let encrypt_box = ChaChaBox::new(
        &PalCryptoKeyPair::make_public_key(
            public_key_bytes.to_vec().try_into().unwrap_or_else(|v: Vec<u8>| panic!("Expected a Vec of length {} but it was {}", KEY_SIZE, v.len()))),
        &PalCryptoKeyPair::make_secret_key(
            secret_key_bytes.to_vec().try_into().unwrap_or_else(|v: Vec<u8>| panic!("Expected a Vec of length {} but it was {}", KEY_SIZE, v.len()))),
    );

    let nonce = ChaChaBox::generate_nonce(&mut OsRng);
    let mut cipher_data = encrypt_box.encrypt(&nonce, plain_bytes).unwrap();
    // println!("ciphertext: {:?}", cipher_data);
    cipher_data.extend_from_slice(&nonce);
    Ok(cipher_data)
}

pub fn pal_cb_decrypt(public_key_bytes: &[u8], secret_key_bytes: &[u8], ciphertext: &[u8], nonce_len: Option<usize>) -> Result<Vec<u8>>{
    let nonce_len = nonce_len.unwrap_or(NONCE_LEN);
    let offset = ciphertext.len() - nonce_len;
    let decrypt_box = ChaChaBox::new(
        &PalCryptoKeyPair::make_public_key(
            public_key_bytes.to_vec().try_into().unwrap_or_else(|v: Vec<u8>| panic!("Expected a Vec of length {} but it was {}", KEY_SIZE, v.len()))),
        &PalCryptoKeyPair::make_secret_key(
            secret_key_bytes.to_vec().try_into().unwrap_or_else(|v: Vec<u8>| panic!("Expected a Vec of length {} but it was {}", KEY_SIZE, v.len()))),
    );
    let nonce = ciphertext[offset..].to_vec();
    let payload_data = ciphertext[..offset].to_vec();
    let plain_bytes = decrypt_box.decrypt(GenericArray::from_slice(&nonce), payload_data.as_slice()).unwrap();
    Ok(plain_bytes)
}


#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, Verifier};
    use super::*;

    #[test]
    fn enc_dec_self_works() {
        let key_pair = generate_pal_key_pair();
        let plain_bytes = b"I am a super man.";
        let cipher_bytes = pal_cb_encrypt(key_pair.public_key_bytes.as_slice(), key_pair.secret_key_bytes.as_slice(), plain_bytes).unwrap();
        let decrypted_bytes = pal_cb_decrypt(key_pair.public_key_bytes.as_slice(), key_pair.secret_key_bytes.as_slice(), &cipher_bytes, None).unwrap();
        assert_eq!(plain_bytes, decrypted_bytes.as_slice());
    }

    #[test]
    fn enc_dec_each_works(){
        let key_pair_a = generate_pal_key_pair();
        let key_pair_b = generate_pal_key_pair();

        let a_say = b"Hi, I am a.";
        let b_say = b"Hi, I am B.";

        let a_say_encrypted = pal_cb_encrypt(key_pair_b.public_key_bytes.as_slice(), key_pair_a.secret_key_bytes.as_slice(), a_say).unwrap();
        let a_say_decrypted = pal_cb_decrypt(key_pair_a.public_key_bytes.as_slice(), key_pair_b.secret_key_bytes.as_slice(), a_say_encrypted.as_slice(), None).unwrap();
        assert_eq!(a_say, a_say_decrypted.as_slice());

        let b_say_encrypted = pal_cb_encrypt(key_pair_a.public_key_bytes.as_slice(), key_pair_b.secret_key_bytes.as_slice(), b_say).unwrap();
        let b_say_decrypted = pal_cb_decrypt(key_pair_b.public_key_bytes.as_slice(), key_pair_a.secret_key_bytes.as_slice(), b_say_encrypted.as_slice(), None).unwrap();
        assert_eq!(b_say, b_say_decrypted.as_slice());
    }

    #[test]
    fn sign_verify_self_works(){
        let key_pair = generate_pal_key_pair();

        let signing_key = ed25519_dalek::SigningKey::from_bytes(
            &ed25519_dalek::SecretKey::from(key_pair.secret_key_bytes));
        let verifying_key = signing_key.verifying_key();
        // println!("SELF verifying_key: {:?}", verifying_key);
        let msg = b"Hi, this is my signature.";
        let sign = signing_key.sign(msg);

        assert!(verifying_key.verify(msg, &sign).is_ok());
    }

    #[test]
    fn sign_verify_each_works(){
        let key_pair_a = generate_pal_key_pair();

        let signing_key_a = ed25519_dalek::SigningKey::from_bytes(&ed25519_dalek::SecretKey::from(key_pair_a.clone().secret_key_bytes));
        let verifying_key = signing_key_a.verifying_key();
        let verifying_key_of_a = ed25519_dalek::VerifyingKey::from_bytes(&key_pair_a.public_key_bytes).unwrap();
        let a_say = b"Hi, this is my signature.";
        let sign = signing_key_a.sign(a_say);

        assert!(verifying_key.verify(a_say, &sign).is_ok());
        assert!(verifying_key_of_a.verify(a_say, &sign).is_ok())
    }
}
