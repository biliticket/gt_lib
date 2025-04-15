use hex_literal::hex;
use md5::Digest;

pub mod base64;

pub struct W<'a> {
    key: &'a str,
    #[allow(dead_code)]
    gt: &'a str,
    #[allow(dead_code)]
    challenge: &'a str,
    #[allow(dead_code)]
    c: &'a str,
    #[allow(dead_code)]
    s: &'a str,
    aeskey: &'a str,
}

// source: https://github.com/magiclen/rust-magiccrypt/blob/1dc700e389d46d0999409dbfd38d37d23117c03f/src/functions.rs#L17
#[inline]
fn get_aes_cipher_len(data_length: usize) -> usize {
    (data_length + 16) & !0xF
}

fn rsa(data: &[u8]) -> Vec<u8> {
    use rsa::Pkcs1v15Encrypt;

    let mut rng = rand::thread_rng();
    let k = hex!(
        "00C1E3934D1614465B33053E7F48EE4EC87B14B95EF88947713D25EECBFF7E74 \
         C7977D02DC1D9451F79DD5D1C10C29ACB6A9B4D6FB7D0A0279B6719E1772565F \
         09AF627715919221AEF91899CAE08C0D686D748B20A3603BE2318CA6BC2B5970 \
         6592A9219D0BF05C9F65023A21D2330807252AE0066D59CEEFA5F2748EA80BAB81"
    );
    let e = hex!("010001");
    let k = rsa::BigUint::from_bytes_be(&k);
    let e = rsa::BigUint::from_bytes_be(&e);
    let pub_key = rsa::RsaPublicKey::new(k, e).unwrap();
    pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, data)
        .expect("failed to encrypt")
}

impl<'a> W<'a> {
    fn aes(&self, data: &[u8]) -> Vec<u8> {
        use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

        let encode_key = &self.aeskey.as_bytes();
        let key = aes::cipher::generic_array::GenericArray::from_slice(encode_key);
        let iv = "0000000000000000".as_bytes();
        let iv = aes::cipher::generic_array::GenericArray::from_slice(iv);

        let data_len = data.len();
        let target_len = get_aes_cipher_len(data_len);
        let mut buf = vec![0; target_len];
        buf[..data_len].copy_from_slice(data);

        let ct = Aes128CbcEnc::new(key, iv)
            .encrypt_padded_mut::<Pkcs7>(&mut buf, data_len)
            .unwrap();

        ct.into()
    }

    pub fn new(
        key: &'a str,
        gt: &'a str,
        challenge: &'a str,
        c: &'a str,
        s: &'a str,
        rt: &'a str,
    ) -> Self {
        Self {
            key,
            gt,
            challenge,
            c,
            s,
            aeskey: rt,
        }
    }

    pub fn calculate(&self) -> String {
        use rand::prelude::*;
        let mut rng = rand::thread_rng();
        let passtime: u64 = 4000 + rng.gen_range(0..=500);
        let rp = format!(
            "{}{}{}",
            self.gt,
            self.challenge.split_at(self.challenge.len() - 2).0,
            passtime
        );
        let mut hasher = md5::Md5::new();
        hasher.update(rp);
        let rp = hex::encode(hasher.finalize());

        let parma = format!(
            include_str!("data.json"),
            passtime = passtime,
            e = self.key,
            rp = rp
        );

        let u = rsa(self.aeskey.as_bytes());
        let h = self.aes(parma.as_bytes());
        let w = format!("{}{}", base64::base64(&h), hex::encode(u));

        w
    }
}
