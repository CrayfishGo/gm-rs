pub type U256 = [u64; 4];
pub type U512 = [u64; 8];

#[inline(always)]
pub const fn u256_add(a: &U256, b: &U256) -> (U256, bool) {
    let mut sum = [0; 4];
    let mut carry = false;
    let mut i = 3;
    loop {
        let (t_sum, c) = {
            let (m, c1) = a[i].overflowing_add(b[i]);
            let (r, c2) = m.overflowing_add(carry as u64);
            (r & 0xffff_ffff_ffff_ffff, c1 || c2)
        };
        sum[i] = t_sum;
        carry = c;
        if i == 0 {
            break;
        }
        i -= 1;
    }
    (sum, carry)
}

#[inline(always)]
pub const fn u512_add(a: &U512, b: &U512) -> (U512, bool) {
    let mut sum = [0; 8];
    let mut carry = false;
    let mut i = 7;
    loop {
        let (t_sum, c) = {
            let (m, c1) = a[i].overflowing_add(b[i]);
            let (r, c2) = m.overflowing_add(carry as u64);
            (r & 0xffff_ffff_ffff_ffff, c1 || c2)
        };
        sum[i] = t_sum;
        carry = c;
        if i == 0 {
            break;
        }
        i -= 1;
    }
    (sum, carry)
}

#[inline(always)]
pub const fn u256_sub(a: &U256, b: &U256) -> (U256, bool) {
    let mut r = [0; 4];
    let mut borrow = false;
    let mut j = 0;
    loop {
        let i = 3 - j;
        let (diff, bor) = {
            let (a, b1) = a[i].overflowing_sub(borrow as u64);
            let (res, b2) = a.overflowing_sub(b[i]);
            (res, b1 || b2)
        };
        r[i] = diff;
        borrow = bor;
        if j == 3 {
            break;
        }
        j += 1;
    }
    (r, borrow)
}

#[inline(always)]
pub const fn u512_sub(a: &U512, b: &U512) -> (U512, bool) {
    let mut r = [0; 8];
    let mut borrow = false;
    let mut j = 0;
    loop {
        let i = 7 - j;
        let (diff, bor) = {
            let (a, b1) = a[i].overflowing_sub(borrow as u64);
            let (res, b2) = a.overflowing_sub(b[i]);
            (res, b1 || b2)
        };
        r[i] = diff;
        borrow = bor;
        if j == 7 {
            break;
        }
        j += 1;
    }
    (r, borrow)
}

#[inline(always)]
pub const fn u256_mul(a: &U256, b: &U256) -> U512 {
    let mut local: u128 = 0;
    let mut carry: u128 = 0;
    let mut ret: [u64; 8] = [0; 8];
    let mut ret_idx = 0;
    while ret_idx < 7 {
        let index = 7 - ret_idx;
        let mut a_idx = 0;
        while a_idx < 4 {
            if a_idx > ret_idx {
                break;
            }
            let b_idx = ret_idx - a_idx;
            if b_idx < 4 {
                let (hi, lo) = {
                    let uv = (a[3 - a_idx] as u128) * (b[3 - b_idx] as u128);
                    let u = uv >> 64;
                    let v = uv & 0xffff_ffff_ffff_ffff;
                    (u, v)
                };
                local += lo;
                carry += hi;
            }
            a_idx += 1;
        }
        carry += local >> 64;
        local &= 0xffff_ffff_ffff_ffff;
        ret[index] = local as u64;
        local = carry;
        carry = 0;
        ret_idx += 1;
    }
    ret[0] = local as u64;
    ret
}

#[inline(always)]
pub const fn u512_mul(a: &U512, b: &U512) -> [u64; 16] {
    let mut local: u128 = 0;
    let mut carry: u128 = 0;
    let mut ret: [u64; 16] = [0; 16];
    let mut ret_idx = 0;
    while ret_idx < 15 {
        let index = 15 - ret_idx;
        let mut a_idx = 0;
        while a_idx < 8 {
            if a_idx > ret_idx {
                break;
            }
            let b_idx = ret_idx - a_idx;
            if b_idx < 8 {
                let (hi, lo) = {
                    let uv = (a[7 - a_idx] as u128) * (b[7 - b_idx] as u128);
                    let u = uv >> 64;
                    let v = uv & 0xffff_ffff_ffff_ffff;
                    (u, v)
                };
                local += lo;
                carry += hi;
            }
            a_idx += 1;
        }
        carry += local >> 64;
        local &= 0xffff_ffff_ffff_ffff;
        ret[index] = local as u64;
        local = carry;
        carry = 0;
        ret_idx += 1;
    }
    ret[0] = local as u64;
    ret
}

#[inline(always)]
pub const fn u256_mul_low(a: &U256, b: &U256) -> U512 {
    let ret: [u64; 8] = u256_mul(a, b);
    [ret[0], ret[1], ret[2], ret[3], 0, 0, 0, 0]
}

#[inline(always)]
pub fn sm9_u256_to_bytes(a: &U256) -> [u8; 32] {
    let mut out = [0; 32];
    out[0..8].copy_from_slice(&a[3].to_le_bytes());
    out[8..16].copy_from_slice(&a[2].to_le_bytes());
    out[16..24].copy_from_slice(&a[1].to_le_bytes());
    out[24..32].copy_from_slice(&a[0].to_le_bytes());
    out
}

#[inline(always)]
pub fn sm9_u256_from_bytes(input: &[u8; 32]) -> U256 {
    let mut r: U256 = [0_u64; 4];
    r[3] = u64::from_le_bytes(input[0..8].try_into().unwrap());
    r[2] = u64::from_le_bytes(input[8..16].try_into().unwrap());
    r[1] = u64::from_le_bytes(input[16..24].try_into().unwrap());
    r[0] = u64::from_le_bytes(input[24..32].try_into().unwrap());
    r
}
