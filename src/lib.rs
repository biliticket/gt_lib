//
// lib.rs
// Copyright (C) 2024 Woshiluo Luo <woshiluo.luo@outlook.com>
// Distributed under terms of the GNU AGPLv3+ license.
//
//
use hex_literal::hex;

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

// fn gen_aes_key() -> Vec<u8> {
//     // Seems it just gen a 8 bytes-long random string
//     // use rand::prelude::*;
//     // let mut rng = rand::thread_rng();
//     // let x: u64 = rng.gen();
//     // x.to_ne_bytes().into()
//     "82253e788a7b95e9".as_bytes()
// }

#[inline]
fn _jgh(e: i32) -> char {
    const T: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789()";
    T.chars().nth(e as usize).unwrap_or('.')
}

#[inline]
fn _jiy(e: i32, t: i32) -> i32 {
    (e >> t) & 1
}

fn _jjm(e: &[u8]) -> String {
    let t = |f: i32, u: i32| -> i32 {
        let mut res = 0;
        for r in (0..24).rev() {
            if _jiy(u, r) == 1 {
                res = (res << 1) + _jiy(f, r)
            }
        }
        res
    };

    let e = e.iter().map(|x| *x as i32).collect::<Vec<i32>>();
    let mut n: String = String::new();
    let mut r = "";
    let a = e.len();
    let mut s = 0;
    while s < a {
        if s + 2 < a {
            let c: i32 = (e[s] << 16) + (e[s + 1] << 8) + e[s + 2];
            n = format!(
                "{}{}{}{}{}",
                n,
                _jgh(t(c, 7274496)),
                _jgh(t(c, 9483264)),
                _jgh(t(c, 19220)),
                _jgh(t(c, 235))
            );
        } else {
            let u = a % 3;
            if u == 2 {
                let c: i32 = (e[s] << 16) + (e[s + 1] << 8);
                n = format!(
                    "{}{}{}{}",
                    n,
                    _jgh(t(c, 7274496)),
                    _jgh(t(c, 9483264)),
                    _jgh(t(c, 19220)),
                );
                r = "."
            } else if u == 1 {
                let c: i32 = e[s] << 16;
                n = format!("{}{}{}", n, _jgh(t(c, 7274496)), _jgh(t(c, 9483264)),);
                r = ".."
            }
        }
        s += 3
    }
    format!("{}{}", n, r)
}

#[inline]
fn enc(e: &[u8]) -> String {
    _jjm(e)
}

// source: https://github.com/magiclen/rust-magiccrypt/blob/1dc700e389d46d0999409dbfd38d37d23117c03f/src/functions.rs#L17
#[inline]
fn get_aes_cipher_len(data_length: usize) -> usize {
    (data_length + 16) & !0xF
}

fn rsa(data: &[u8]) -> Vec<u8> {
    use rsa::Pkcs1v15Encrypt;

    let mut rng = rand::thread_rng();
    let k = hex!("00C1E3934D1614465B33053E7F48EE4EC87B14B95EF88947713D25EECBFF7E74C7977D02DC1D9451F79DD5D1C10C29ACB6A9B4D6FB7D0A0279B6719E1772565F09AF627715919221AEF91899CAE08C0D686D748B20A3603BE2318CA6BC2B59706592A9219D0BF05C9F65023A21D2330807252AE0066D59CEEFA5F2748EA80BAB81");
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
        let mut buf = Vec::with_capacity(target_len);

        buf.resize(target_len, 0);
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
        let x: u64 = 4000 + rng.gen_range(0..=500);
        let parma = format!(include_str!("data.json"), passtime = x, e = self.key);

        let u = rsa(self.aeskey.as_bytes());
        let h = self.aes(parma.as_bytes());
        let w = format!("{}{}", enc(&h), hex::encode(u));

        w
    }
}
