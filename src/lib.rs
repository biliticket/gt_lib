//
// lib.rs
// Copyright (C) 2024 Woshiluo Luo <woshiluo.luo@outlook.com>
// Distributed under terms of the GNU AGPLv3+ license.
//

pub struct W {
    key: String,
    #[allow(dead_code)]
    gt: String,
    #[allow(dead_code)]
    challenge: String,
    #[allow(dead_code)]
    c: String,
    #[allow(dead_code)]
    s: String,
    aeskey: Vec<u8>,
}

fn gen_aes_key() -> Vec<u8> {
    //    @logger.catch
    //    def Key(self) -> bytes:
    //        var = []
    //        for _ in range(4):
    //            random_value = int(65536 * (1 + random.random()))
    //            hex = format(random_value, "04x")[1:]
    //            var.append(hex)
    //        dist = ("".join(var)).encode()
    //        return dist

    // Seems it just gen a 8 bytes-long random string
    use rand::prelude::*;
    let mut rng = rand::thread_rng();
    let x: u64 = rng.gen();
    x.to_ne_bytes().into()
}

fn _jgh(e: i32) -> char {
    const T: &'static str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789()";
    T.chars().nth(e as usize).unwrap_or('.')
}

fn _jiy(e: i32, t: i32) -> i32 {
    (e >> t) & 1
}

struct JJMValue {
    res: String,
    end: String,
}
fn _jjm(e: &[u8]) -> JJMValue {
    let t = |f: i32, u: i32| -> i32 {
        let mut res = 0;
        for r in (0..23).rev() {
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
            let c: i32 = e[s] << 16 + (e[s + 1] << 8) + e[s + 2];
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
                let c: i32 = e[s] << 16 + (e[s + 1] << 8);
                n = format!(
                    "{}{}{}{}",
                    n,
                    _jgh(t(c, 7274496)),
                    _jgh(t(c, 9483264)),
                    _jgh(t(c, 19220)),
                );
                r = "."
            }
            if u == 2 {
                let c: i32 = e[s] << 16;
                n = format!("{}{}{}", n, _jgh(t(c, 7274496)), _jgh(t(c, 9483264)),);
                r = ".."
            }
        }
        s += 3
    }
    JJMValue {
        res: n,
        end: r.to_string(),
    }
}

fn enc(e: &[u8]) -> String {
    let t = _jjm(e);
    format!("{}{}", t.res, t.end)
}

// source: https://stackoverflow.com/questions/52987181/how-can-i-convert-a-hex-string-to-a-u8-slice
fn decode_hex(s: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

// source: https://github.com/magiclen/rust-magiccrypt/blob/1dc700e389d46d0999409dbfd38d37d23117c03f/src/functions.rs#L17
#[inline]
fn get_aes_cipher_len(data_length: usize) -> usize {
    (data_length + 16) & !0xF
}

fn rsa(data: &[u8]) -> Vec<u8> {
    use rsa::Pkcs1v15Encrypt;

    let mut rng = rand::thread_rng();
    let k = decode_hex("00C1E3934D1614465B33053E7F48EE4EC87B14B95EF88947713D25EECBFF7E74C7977D02DC1D9451F79DD5D1C10C29ACB6A9B4D6FB7D0A0279B6719E1772565F09AF627715919221AEF91899CAE08C0D686D748B20A3603BE2318CA6BC2B59706592A9219D0BF05C9F65023A21D2330807252AE0066D59CEEFA5F2748EA80BAB81").unwrap();
    let e = decode_hex("010001").unwrap();
    let k = rsa::BigUint::from_bytes_be(&k);
    let e = rsa::BigUint::from_bytes_be(&e);
    let pub_key = rsa::RsaPublicKey::new(k, e).unwrap();
    pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, data)
        .expect("failed to encrypt")
}

impl W {
    fn aes(&self, data: &[u8]) -> Vec<u8> {
        use aes::cipher::generic_array::GenericArray;
        use aes::Aes128;
        use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
        type Aes128Cbc = Cbc<Aes128, Pkcs7>;
        let key = GenericArray::from_slice(&self.aeskey[..]);
        let iv = GenericArray::from([0u8; 16]);
        let cipher = Aes128Cbc::new_fix(key, &iv);

        let data_length = data.len();

        let final_length = get_aes_cipher_len(data_length);

        let mut final_result = data.to_vec();

        final_result.reserve_exact(final_length - data_length);

        unsafe {
            final_result.set_len(final_length);
        }

        cipher.encrypt(&mut final_result, data_length).unwrap();

        final_result
    }
    pub fn new(key: String, gt: String, challenge: String, c: String, s: String) -> Self {
        Self {
            key,
            gt,
            challenge,
            c,
            s,
            aeskey: gen_aes_key(),
        }
    }
    pub fn calculate(&self) -> String {
        use rand::prelude::*;
        let mut rng = rand::thread_rng();
        let x: u64 = 4000 + rng.gen_range(0..=500);
        let parma = format!(include_str!("data.json"), passtime = x, e = self.key);

        let u = rsa(&self.aeskey);
        let h = self.aes(parma.as_bytes());
        let w = format!("{}{}", enc(&h), hex::encode(u));

        w
    }
}
