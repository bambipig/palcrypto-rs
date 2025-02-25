use aes_gcm::{
    aead::{AeadCore, AeadInPlace, KeyInit, OsRng, heapless::Vec as HlVec},
    Aes256Gcm, // Or `Aes128Gcm`
};
use aes_gcm::aead::generic_array::GenericArray;
use anyhow::Result;


const EAS_KEY_LEN_32: usize = 32;
const EAS_NONCE_LEN_12 : usize = 12;

pub struct PalAesKey([u8; EAS_KEY_LEN_32]);

impl PalAesKey {
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

pub fn generate_pal_aes_key() -> PalAesKey {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    PalAesKey(key.into())
}

pub fn pal_aes_encrypt(pal_aes_key: &PalAesKey, plain_bytes: &[u8]) -> Result<Vec<u8>>{
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&pal_aes_key.as_bytes()));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let mut buffer: HlVec<u8, 128> = HlVec::new();
    buffer.extend_from_slice(plain_bytes).unwrap();
    cipher.encrypt_in_place(&nonce, b"", &mut buffer).unwrap();
    buffer.extend_from_slice(&nonce).unwrap();
    Ok(buffer.to_vec())
}

pub fn pal_aes_decrypt(pal_aes_key: &PalAesKey, encrypted_bytes: &[u8], nonce_len: Option<usize>) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&pal_aes_key.as_bytes()));
    let nonce_len = nonce_len.unwrap_or(EAS_NONCE_LEN_12);
    let offset = encrypted_bytes.len() - nonce_len;
    let nonce = encrypted_bytes[offset..].to_vec();
    let mut buffer = encrypted_bytes[..offset].to_vec();
    cipher.decrypt_in_place(GenericArray::from_slice(&nonce), b"", &mut buffer).unwrap();
    Ok(buffer.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pal_aes_enc_dec_works(){
        let key = generate_pal_aes_key();
        let plain_bytes = b"Hello, Pal!";
        let encrypted_bytes = pal_aes_encrypt(&key, plain_bytes).unwrap();
        let decrypted_bytes = pal_aes_decrypt(&key, &encrypted_bytes, None).unwrap();
        assert_eq!(plain_bytes, decrypted_bytes.as_slice());
    }

}
