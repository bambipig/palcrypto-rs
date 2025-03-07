use aes_gcm::{
    aead::{AeadCore, KeyInit, OsRng},
    Aes256Gcm,
};
use aes_gcm::aead::Aead;
use aes_gcm::aead::generic_array::GenericArray;
use anyhow::Result;


const EAS_KEY_LEN_32: usize = 32;
const EAS_NONCE_LEN_12 : usize = 12;

#[derive(Clone)]
pub struct PalAesKey(pub [u8; EAS_KEY_LEN_32]);

impl PalAesKey {
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

pub fn generate_pal_aes_key() -> PalAesKey {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    PalAesKey(key.into())
}

pub fn pal_aes_encrypt(pal_aes_key_bytes: &[u8], plain_bytes: &[u8]) -> Result<Vec<u8>>{
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&pal_aes_key_bytes));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    // let mut buffer: HlVec<u8, 128> = HlVec::new();
    // buffer.extend_from_slice(plain_bytes).unwrap();
    let mut encrypted_bytes = cipher.encrypt(&nonce, plain_bytes).unwrap();
    // buffer.extend_from_slice(&nonce).unwrap();
    encrypted_bytes.extend_from_slice(&nonce);
    Ok(encrypted_bytes)
}

pub fn pal_aes_decrypt(pal_aes_key_bytes: &[u8], encrypted_bytes: &[u8], nonce_len: Option<usize>) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&pal_aes_key_bytes));
    let nonce_len = nonce_len.unwrap_or(EAS_NONCE_LEN_12);
    let offset = encrypted_bytes.len() - nonce_len;
    let nonce = encrypted_bytes[offset..].to_vec();
    let buffer = encrypted_bytes[..offset].to_vec();
    let plain_bytes = cipher.decrypt(GenericArray::from_slice(&nonce), buffer.as_ref()).unwrap();
    Ok(plain_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pal_aes_enc_dec_works(){
        let key = generate_pal_aes_key();
        let plain_bytes = b"Hello, Pal!";
        let encrypted_bytes = pal_aes_encrypt(key.as_bytes().as_slice(), plain_bytes).unwrap();
        let decrypted_bytes = pal_aes_decrypt(key.as_bytes().as_slice(), &encrypted_bytes, None).unwrap();
        assert_eq!(plain_bytes, decrypted_bytes.as_slice());
    }

}
