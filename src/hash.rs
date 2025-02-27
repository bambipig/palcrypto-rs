use anyhow::Result;
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use sha3::{Sha3_512, Digest};

pub fn argon2_password_hash(password: &[u8]) -> Result<Vec<u8>> {
    let mut hasher = Sha3_512::new();
    hasher.update(password);
    let hash = hasher.finalize();
    let argon2_salt = SaltString::from_b64(BASE64_STANDARD.encode(hash.as_slice())[..64].trim()).unwrap();
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password, &argon2_salt).unwrap();
    let hash_output = password_hash.hash.unwrap();
    Ok(hash_output.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_password_hash_works() {
        let password = String::from("I am a password");
        let password_hash_output = argon2_password_hash(password.as_bytes());
        assert!(password_hash_output.is_ok());
        assert_eq!(password_hash_output.unwrap().len(), 32);
    }
}