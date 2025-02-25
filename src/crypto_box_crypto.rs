use crypto_box::{aead::{Aead, AeadCore, OsRng}, ChaChaBox, PublicKey, SecretKey, KEY_SIZE};
use crypto_box::aead::generic_array::GenericArray;
use anyhow::Result;

pub const NONCE_LEN: usize = 24;

pub struct PalCryptoPublicKey([u8; KEY_SIZE]);
impl PalCryptoPublicKey {
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_slice(&self.0).unwrap()
    }
}
pub struct PalCryptoSecretKey([u8; KEY_SIZE]);
impl PalCryptoSecretKey {
    pub fn secret_key(&self) -> SecretKey {
        SecretKey::from_slice(&self.0).unwrap()
    }
}


pub struct PalCryptoKeyPair{
    secret_key_bytes: [u8; KEY_SIZE],
    public_key_bytes:  [u8; KEY_SIZE],
}

impl PalCryptoKeyPair {
    pub fn secret_key(&self) -> SecretKey{
        SecretKey::from_bytes(self.secret_key_bytes)
    }

    pub fn public_key(&self) -> PublicKey{
        PublicKey::from_bytes(self.public_key_bytes)
    }
}

pub fn generate_pal_key_pair() -> PalCryptoKeyPair {
    let secret_key = SecretKey::generate(&mut OsRng);
    PalCryptoKeyPair {
        secret_key_bytes: secret_key.to_bytes(),
        public_key_bytes: secret_key.public_key().as_bytes().clone(),
    }
}

pub fn pal_cb_encrypt(public_key: PublicKey, secret_key: SecretKey, plain_bytes: &[u8]) -> Result<Vec<u8>>{
    let encrypt_box = ChaChaBox::new(&public_key, &secret_key);

    let nonce = ChaChaBox::generate_nonce(&mut OsRng);
    let mut cipher_data = encrypt_box.encrypt(&nonce, plain_bytes).unwrap();
    // println!("ciphertext: {:?}", cipher_data);
    cipher_data.extend_from_slice(&nonce);
    Ok(cipher_data)
}

pub fn pal_cb_decrypt(public_key: PublicKey, secret_key: SecretKey, ciphertext: &[u8], nonce_len: Option<usize>) -> Result<Vec<u8>>{
    let nonce_len = nonce_len.unwrap_or(NONCE_LEN);
    let offset = ciphertext.len() - nonce_len;
    let decrypt_box = ChaChaBox::new(&public_key, &secret_key);
    let nonce = ciphertext[offset..].to_vec();
    let payload_data = ciphertext[..offset].to_vec();
    let plain_bytes = decrypt_box.decrypt(GenericArray::from_slice(&nonce), payload_data.as_slice()).unwrap();
    Ok(plain_bytes)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enc_dec_self_works() {
        let key_pair = generate_pal_key_pair();
        let plain_bytes = b"I am a super man.";
        let cipher_bytes = pal_cb_encrypt(key_pair.public_key(), key_pair.secret_key(), plain_bytes).unwrap();
        let decrypted_bytes = pal_cb_decrypt(key_pair.public_key(), key_pair.secret_key(), &cipher_bytes, None).unwrap();
        assert_eq!(plain_bytes, decrypted_bytes.as_slice());
    }

    #[test]
    fn enc_dec_each_works(){
        let key_pair_a = generate_pal_key_pair();
        let key_pair_b = generate_pal_key_pair();

        let a_say = b"Hi, I am a.";
        let b_say = b"Hi, I am B.";

        let a_say_encrypted = pal_cb_encrypt(key_pair_b.public_key(), key_pair_a.secret_key(), a_say).unwrap();
        let a_say_decrypted = pal_cb_decrypt(key_pair_a.public_key(), key_pair_b.secret_key(), a_say_encrypted.as_slice(), None).unwrap();
        assert_eq!(a_say, a_say_decrypted.as_slice());

        let b_say_encrypted = pal_cb_encrypt(key_pair_a.public_key(), key_pair_b.secret_key(), b_say).unwrap();
        let b_say_decrypted = pal_cb_decrypt(key_pair_b.public_key(), key_pair_a.secret_key(), b_say_encrypted.as_slice(), None).unwrap();
        assert_eq!(b_say, b_say_decrypted.as_slice());
    }
}
