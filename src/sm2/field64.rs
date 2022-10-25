
// ffffffff 00000001 00000000 000000000 0000000 ffffffff fffffff fffffffff
pub const MODULUS: Fe = [
    // 0xffff_fffe_ffff_ffff,
    // 0xffff_ffff_ffff_ffff,
    // 0xffff_ffff_0000_0000,
    // 0xffff_ffff_ffff_ffff,

    // 0xffffffff_ffffffff,
    // 0x00000000_ffffffff,
    // 0x00000000_00000000,
    // 0xffffffff_00000001,

    0xffffffffffffffff,
    0xffffffff00000000,
    0xffffffffffffffff,
    0xfffffffeffffffff,
];

pub const R_2: Fe = [
    // 0x40000000_20000000,
    // 0x10000000_10000000,
    // 0x2FFFFFFF_F0000000,
    // 0x200000003,

    // 0x0000000000000003,
    // 0xfffffffbffffffff,
    // 0xfffffffffffffffe,
    // 0x00000004fffffffd,

    0x0000000200000003,
    0x00000002ffffffff,
    0x0000000100000001,
    0x0400000002,

];

/// Raw field element.
pub type Fe = [u64; 4];

/// Translate a field element out of the Montgomery domain.
#[inline]
pub const fn fe_from_montgomery(w: &Fe) -> Fe {
    montgomery_reduce(&[w[0], w[1], w[2], w[3], 0, 0, 0, 0])
}

/// Translate a field element into the Montgomery domain.
#[inline]
pub const fn fe_to_montgomery(w: &Fe) -> Fe {
    fe_mul(w, &R_2)
}

/// Returns `a + b mod p`.
pub const fn fe_add(a: &Fe, b: &Fe) -> Fe {
    // Bit 256 of p is set, so addition can result in five words.
    let (w0, carry) = adc(a[0], b[0], 0);
    let (w1, carry) = adc(a[1], b[1], carry);
    let (w2, carry) = adc(a[2], b[2], carry);
    let (w3, w4) = adc(a[3], b[3], carry);

    // Attempt to subtract the modulus, to ensure the result is in the field.
    let modulus = MODULUS;
    sub_inner(
        &[w0, w1, w2, w3, w4],
        &[modulus[0], modulus[1], modulus[2], modulus[3], 0],
    )
}

/// Returns `a - b mod p`.
pub const fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    sub_inner(&[a[0], a[1], a[2], a[3], 0], &[b[0], b[1], b[2], b[3], 0])
}

/// Returns `a * b mod p`.
pub const fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let (w0, carry) = mac(0, a[0], b[0], 0);
    let (w1, carry) = mac(0, a[0], b[1], carry);
    let (w2, carry) = mac(0, a[0], b[2], carry);
    let (w3, w4) = mac(0, a[0], b[3], carry);

    let (w1, carry) = mac(w1, a[1], b[0], 0);
    let (w2, carry) = mac(w2, a[1], b[1], carry);
    let (w3, carry) = mac(w3, a[1], b[2], carry);
    let (w4, w5) = mac(w4, a[1], b[3], carry);

    let (w2, carry) = mac(w2, a[2], b[0], 0);
    let (w3, carry) = mac(w3, a[2], b[1], carry);
    let (w4, carry) = mac(w4, a[2], b[2], carry);
    let (w5, w6) = mac(w5, a[2], b[3], carry);

    let (w3, carry) = mac(w3, a[3], b[0], 0);
    let (w4, carry) = mac(w4, a[3], b[1], carry);
    let (w5, carry) = mac(w5, a[3], b[2], carry);
    let (w6, w7) = mac(w6, a[3], b[3], carry);

    montgomery_reduce(&[w0, w1, w2, w3, w4, w5, w6, w7])
}

/// Returns `-w mod p`.
pub const fn fe_neg(w: &Fe) -> Fe {
    fe_sub(&[0, 0, 0, 0], w)
}

/// Returns `w * w mod p`.
pub const fn fe_square(w: &Fe) -> Fe {
    fe_mul(w, w)
}

/// Montgomery Reduction
///
/// The general algorithm is:
/// ```text
/// A <- input (2n b-limbs)
/// for i in 0..n {
///     k <- A[i] p' mod b
///     A <- A + k p b^i
/// }
/// A <- A / b^n
/// if A >= p {
///     A <- A - p
/// }
/// ```
///
/// For secp256r1, we have the following simplifications:
///
/// - `p'` is 1, so our multiplicand is simply the first limb of the intermediate A.
///
/// - The first limb of p is 2^64 - 1; multiplications by this limb can be simplified
///   to a shift and subtraction:
///   ```text
///       a_i * (2^64 - 1) = a_i * 2^64 - a_i = (a_i << 64) - a_i
///   ```
///   However, because `p' = 1`, the first limb of p is multiplied by limb i of the
///   intermediate A and then immediately added to that same limb, so we simply
///   initialize the carry to limb i of the intermediate.
///
/// - The third limb of p is zero, so we can ignore any multiplications by it and just
///   add the carry.
///
/// References:
/// - Handbook of Applied Cryptography, Chapter 14
///   Algorithm 14.32
///   http://cacr.uwaterloo.ca/hac/about/chap14.pdf
///
/// - Efficient and Secure Elliptic Curve Cryptography Implementation of Curve P-256
///   Algorithm 7) Montgomery Word-by-Word Reduction
///   https://csrc.nist.gov/csrc/media/events/workshop-on-elliptic-curve-cryptography-standards/documents/papers/session6-adalier-mehmet.pdf
#[inline]
#[allow(clippy::too_many_arguments)]
const fn montgomery_reduce(r: &[u64; 8]) -> Fe {
    let r0 = r[0];
    let r1 = r[1];
    let r2 = r[2];
    let r3 = r[3];
    let r4 = r[4];
    let r5 = r[5];
    let r6 = r[6];
    let r7 = r[7];
    let modulus = MODULUS;

    let (r1, carry) = mac(r1, r0, modulus[1], r0);
    let (r2, carry) = adc(r2, 0, carry);
    let (r3, carry) = mac(r3, r0, modulus[3], carry);
    let (r4, carry2) = adc(r4, 0, carry);

    let (r2, carry) = mac(r2, r1, modulus[1], r1);
    let (r3, carry) = adc(r3, 0, carry);
    let (r4, carry) = mac(r4, r1, modulus[3], carry);
    let (r5, carry2) = adc(r5, carry2, carry);

    let (r3, carry) = mac(r3, r2, modulus[1], r2);
    let (r4, carry) = adc(r4, 0, carry);
    let (r5, carry) = mac(r5, r2, modulus[3], carry);
    let (r6, carry2) = adc(r6, carry2, carry);

    let (r4, carry) = mac(r4, r3, modulus[1], r3);
    let (r5, carry) = adc(r5, 0, carry);
    let (r6, carry) = mac(r6, r3, modulus[3], carry);
    let (r7, r8) = adc(r7, carry2, carry);

    // Result may be within MODULUS of the correct value
    sub_inner(
        &[r4, r5, r6, r7, r8],
        &[modulus[0], modulus[1], modulus[2], modulus[3], 0],
    )
}

#[inline]
#[allow(clippy::too_many_arguments)]
const fn sub_inner(l: &[u64; 5], r: &[u64; 5]) -> Fe {
    let (w0, borrow) = sbb(l[0], r[0], 0);
    let (w1, borrow) = sbb(l[1], r[1], borrow);
    let (w2, borrow) = sbb(l[2], r[2], borrow);
    let (w3, borrow) = sbb(l[3], r[3], borrow);
    let (_, borrow) = sbb(l[4], r[4], borrow);

    // If underflow occurred on the final limb, borrow = 0xfff...fff, otherwise
    // borrow = 0x000...000. Thus, we use it as a mask to conditionally add the
    // modulus.
    let modulus = MODULUS;
    let (w0, carry) = adc(w0, modulus[0] & borrow, 0);
    let (w1, carry) = adc(w1, modulus[1] & borrow, carry);
    let (w2, carry) = adc(w2, modulus[2] & borrow, carry);
    let (w3, _) = adc(w3, modulus[3] & borrow, carry);

    [w0, w1, w2, w3]
}

/// Computes `a + b + carry`, returning the result along with the new carry. 64-bit version.
#[inline(always)]
pub const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + (b as u128) + (carry as u128);
    (ret as u64, (ret >> 64) as u64)
}

/// Computes `a - (b + borrow)`, returning the result along with the new borrow. 64-bit version.
#[inline(always)]
pub const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let ret = (a as u128).wrapping_sub((b as u128) + ((borrow >> 63) as u128));
    (ret as u64, (ret >> 64) as u64)
}

/// Computes `a + (b * c) + carry`, returning the result along with the new carry.
#[inline(always)]
pub const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + ((b as u128) * (c as u128)) + (carry as u128);
    (ret as u64, (ret >> 64) as u64)
}


#[cfg(test)]
mod test {
    use crate::sm2::field64::{fe_from_montgomery, fe_mul, fe_to_montgomery, MODULUS};
    use num_bigint::BigUint;
    use crate::sm2::FeOperation;
    use crate::sm2::util::{fe32_to_fe64, fe64_to_fe32};

    #[test]
    fn test() {
        let one = [0, 0, 0, 1];

        let o = fe_to_montgomery(&one);
        let t = fe_from_montgomery(&o);

        let a_32 = &[
            2873047271, 2629036008, 1128014166, 1970199295, 2823665875, 2088637250, 2470587820,
            293793798,
        ];

        let b_32 = &[
            1823252243, 377009872, 3881411647, 1350830274, 1024466750, 4078541794, 1792939469,
            3992378236,
        ];

        let p = BigUint::from_slice(&fe64_to_fe32(&MODULUS));

        let a = fe32_to_fe64(a_32);
        let b = fe32_to_fe64(b_32);

        let aa = BigUint::from_slice(a_32);
        let bb = BigUint::from_slice(b_32);

        let a1 = fe_to_montgomery(&a);
        let b1 = fe_to_montgomery(&b);

        let ret = fe_mul(&a1, &b1);

        let ret2 = ( &aa * &bb) % &p;

        let t1 = fe_from_montgomery(&ret);
        println!("ret1 = {:?}", t1);
        println!("ret2 = {:?}", ret2.to_u64_digits());
        println!("ret3 = {:?}", &aa.mod_mul(&bb, &p).to_u64_digits());

        ()
    }
}
