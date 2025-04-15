const BASE64_TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789()";
const MASK1: i32 = 7274496;
const MASK2: i32 = 9483264;
const MASK3: i32 = 19220;
const MASK4: i32 = 235;

#[inline(always)]
fn choose_bit(base: i32, bit: i32) -> i32 {
    (base >> bit) & 1
}

#[inline(always)]
fn get_int_by_mask(base: i32, mask: i32) -> i32 {
    let mut res = 0;
    for bit in (0..24).rev() {
        if choose_bit(mask, bit) == 1 {
            res = (res << 1) | choose_bit(base, bit)
        }
    }
    res
}

pub fn base64(input: &[u8]) -> String {
    let input = input.iter().map(|x| *x as i32).collect::<Vec<i32>>();
    let mut result: String = String::new();
    let mut padding = "";
    let len = input.len();
    let mut ptr = 0;
    while ptr < len {
        if ptr + 2 < len {
            let c: i32 = (input[ptr] << 16) + (input[ptr + 1] << 8) + input[ptr + 2];
            result = format!(
                "{}{}{}{}{}",
                result,
                BASE64_TABLE[get_int_by_mask(c, MASK1) as usize] as char,
                BASE64_TABLE[get_int_by_mask(c, MASK2) as usize] as char,
                BASE64_TABLE[get_int_by_mask(c, MASK3) as usize] as char,
                BASE64_TABLE[get_int_by_mask(c, MASK4) as usize] as char
            );
        } else {
            let u = len % 3;
            if u == 2 {
                let c: i32 = (input[ptr] << 16) + (input[ptr + 1] << 8);
                result = format!(
                    "{}{}{}{}",
                    result,
                    BASE64_TABLE[get_int_by_mask(c, MASK1) as usize] as char,
                    BASE64_TABLE[get_int_by_mask(c, MASK2) as usize] as char,
                    BASE64_TABLE[get_int_by_mask(c, MASK3) as usize] as char,
                );
                padding = "."
            } else if u == 1 {
                let c: i32 = input[ptr] << 16;
                result = format!(
                    "{}{}{}",
                    result,
                    BASE64_TABLE[get_int_by_mask(c, MASK1) as usize] as char,
                    BASE64_TABLE[get_int_by_mask(c, MASK2) as usize] as char,
                );
                padding = ".."
            }
        }
        ptr += 3
    }
    format!("{}{}", result, padding)
}
