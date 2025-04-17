A simple crypto lib use Aes and crypto_box.

```rust
mod tests {
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
    fn sign_verify_works(){
        let key_pair = generate_pal_key_pair();
        let msg = b"Hi, this is my signature.";
        let sign = pal_cb_sign(key_pair.secret_key_bytes.as_slice(), msg).unwrap();
        assert!(pal_cb_verify_sign(key_pair.public_key_bytes.as_slice(), msg, &sign).unwrap());
    }
```