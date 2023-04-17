use std::fmt::{Display, Formatter};

pub enum Sm3Error {
    ErrorMsgLen,
}

impl std::fmt::Debug for Sm3Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> ::std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl From<Sm3Error> for &str {
    fn from(e: Sm3Error) -> Self {
        match e {
            Sm3Error::ErrorMsgLen => "SM3 Pad error: error msg len",
        }
    }
}

impl Display for Sm3Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let err_msg = match self {
            Sm3Error::ErrorMsgLen => "SM3 Pad error: error msg len",
        };
        write!(f, "{}", err_msg)
    }
}

// 0 ≤ j ≤ 15
pub(crate) const T00: u32 = 0x79cc4519;

// 16 ≤ j ≤ 63
pub(crate) const T16: u32 = 0x7a879d8a;

pub(crate) static IV: [u32; 8] = [
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
];

/// P0(X) = X ⊕ (X ≪ 9) ⊕ (X ≪ 17)
fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)
}

/// P1(X) = X ⊕ (X ≪ 15) ⊕ (X ≪ 23)
fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)
}

fn ff(x: u32, y: u32, z: u32, j: u32) -> u32 {
    if j <= 15 {
        return x ^ y ^ z;
    } else if j >= 16 && j <= 63 {
        return (x & y) | (x & z) | (y & z);
    }
    0
}

fn gg(x: u32, y: u32, z: u32, j: u32) -> u32 {
    if j <= 15 {
        return x ^ y ^ z;
    } else if j >= 16 && j <= 63 {
        return (x & y) | (!x & z);
    }
    0
}

fn t(j: usize) -> u32 {
    if j <= 15 {
        return T00;
    } else if j >= 16 && j <= 63 {
        return T16;
    }
    0
}

/// # Example
/// ```rust
/// use crate::gm_sm3::sm3_hash;
/// fn main(){
///     let hash = sm3_hash(b"abc");
///     let r = hex::encode(hash);
///     assert_eq!("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", r);
/// }
///
/// ```
///
pub fn sm3_hash(msg: &[u8]) -> [u8; 32] {
    let msg = pad(msg).unwrap();
    let len = msg.len();
    let mut b_i: [u8; 64] = [0; 64];
    let mut count_group: usize = 0;
    let mut v_i = IV;
    while count_group * 64 != len {
        for i in (count_group * 64)..(count_group * 64 + 64) {
            b_i[i - count_group * 64] = msg[i];
        }
        cf(&mut v_i, b_i);
        count_group += 1;
    }
    let mut output: [u8; 32] = [0; 32];
    for i in 0..8 {
        output[i * 4] = (v_i[i] >> 24) as u8;
        output[i * 4 + 1] = (v_i[i] >> 16) as u8;
        output[i * 4 + 2] = (v_i[i] >> 8) as u8;
        output[i * 4 + 3] = v_i[i] as u8;
    }
    output
}

fn cf(v_i: &mut [u32; 8], b_i: [u8; 64]) {
    // expend msg
    let mut w: [u32; 68] = [0; 68];
    let mut w1: [u32; 64] = [0; 64];

    // a. 将消息分组B(i)划分为16个字W0, W1, · · · , W15。
    let mut j = 0;
    while j <= 15 {
        w[j] = u32::from(b_i[j * 4]) << 24
            | u32::from(b_i[j * 4 + 1]) << 16
            | u32::from(b_i[j * 4 + 2]) << 8
            | u32::from(b_i[j * 4 + 3]);
        j += 1;
    }

    // b. Wj ← P1(Wj−16 ⊕ Wj−9 ⊕ (Wj−3 ≪ 15)) ⊕ (Wj−13 ≪ 7) ⊕ Wj−6
    j = 16;
    while j <= 67 {
        w[j] = p1(w[j - 16] ^ w[j - 9] ^ w[j - 3].rotate_left(15))
            ^ w[j - 13].rotate_left(7)
            ^ w[j - 6];
        j += 1;
    }

    // c. Wj′ = Wj ⊕ Wj+4
    j = 0;
    while j <= 63 {
        w1[j] = w[j] ^ w[j + 4];
        j += 1;
    }

    let mut a = v_i[0];
    let mut b = v_i[1];
    let mut c = v_i[2];
    let mut d = v_i[3];
    let mut e = v_i[4];
    let mut f = v_i[5];
    let mut g = v_i[6];
    let mut h = v_i[7];

    for j in 0..64 {
        let ss1 = (a
            .rotate_left(12)
            .wrapping_add(e)
            .wrapping_add(t(j).rotate_left(j as u32)))
            .rotate_left(7);
        let ss2 = ss1 ^ (a.rotate_left(12));
        let tt1 = ff(a, b, c, j as u32)
            .wrapping_add(d)
            .wrapping_add(ss2)
            .wrapping_add(w1[j]);
        let tt2 = gg(e, f, g, j as u32)
            .wrapping_add(h)
            .wrapping_add(ss1)
            .wrapping_add(w[j]);
        d = c;
        c = b.rotate_left(9);
        b = a;
        a = tt1;
        h = g;
        g = f.rotate_left(19);
        f = e;
        e = p0(tt2);
    }
    v_i[0] ^= a;
    v_i[1] ^= b;
    v_i[2] ^= c;
    v_i[3] ^= d;
    v_i[4] ^= e;
    v_i[5] ^= f;
    v_i[6] ^= g;
    v_i[7] ^= h;
}

fn pad(msg: &[u8]) -> Result<Vec<u8>, Sm3Error> {
    let bit_length = (msg.len() << 3) as u64;
    let mut msg = msg.to_vec();
    msg.push(0x80);
    let blocksize = 64;
    while msg.len() % blocksize != 56 {
        msg.push(0x00);
    }
    msg.push((bit_length >> 56 & 0xff) as u8);
    msg.push((bit_length >> 48 & 0xff) as u8);
    msg.push((bit_length >> 40 & 0xff) as u8);
    msg.push((bit_length >> 32 & 0xff) as u8);
    msg.push((bit_length >> 24 & 0xff) as u8);
    msg.push((bit_length >> 16 & 0xff) as u8);
    msg.push((bit_length >> 8 & 0xff) as u8);
    msg.push((bit_length & 0xff) as u8);
    if msg.len() % 64 != 0 {
        return Err(Sm3Error::ErrorMsgLen);
    }
    Ok(msg)
}

#[cfg(test)]
mod test {
    use crate::sm3_hash;

    #[test]
    fn test_hash_1() {
        let hash = sm3_hash(b"abc");
        let r = hex::encode(hash);
        assert_eq!("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", r);
    }

    #[test]
    fn test_hash_2() {
        let hash = sm3_hash(b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");
        let r = hex::encode(hash);
        assert_eq!("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732", r);
    }
}
