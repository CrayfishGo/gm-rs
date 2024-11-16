use crate::fields::fp::Fp;
use crate::fields::fp2::Fp2;
use crate::fields::fp4::Fp4;
use crate::fields::FieldElement;
use crate::u256::U256;
use crate::{
    SM9_MONT_ALPHA1, SM9_MONT_ALPHA2, SM9_MONT_ALPHA3, SM9_MONT_ALPHA4, SM9_MONT_ALPHA5,
    SM9_MONT_BETA, SM9_N_MINUS_ONE,
};

#[derive(Debug, Copy, Clone)]
pub struct Fp12 {
    pub(crate) c0: Fp4,
    pub(crate) c1: Fp4,
    pub(crate) c2: Fp4,
}

impl Fp12 {
    pub(crate) fn fp_line_mul(&self, lw: &[Fp2; 3]) -> Fp12 {
        let lw4 = Fp4 {
            c0: lw[0],
            c1: lw[2],
        };

        let mut r0 = self.c0.fp_mul(&lw4);
        let mut r1 = self.c1.fp_mul(&lw4);
        let mut r2 = self.c2.fp_mul(&lw4);

        let mut t = self.c0.c0.fp_mul(&lw[1]);
        r2.c0 = r2.c0.fp_add(&t);

        t = self.c0.c1.fp_mul(&lw[1]);
        r2.c1 = r2.c1.fp_add(&t);

        t = self.c1.c0.fp_mul(&lw[1]);
        r0.c1 = r0.c1.fp_add(&t);

        t = self.c1.c1.fp_mul_u(&lw[1]);
        r0.c0 = r0.c0.fp_add(&t);

        t = self.c2.c0.fp_mul(&lw[1]);
        r1.c1 = r1.c1.fp_add(&t);

        t = self.c2.c1.fp_mul_u(&lw[1]);
        r1.c0 = r1.c0.fp_add(&t);
        Fp12 {
            c0: r0,
            c1: r1,
            c2: r2,
        }
    }

    pub(crate) fn fp12_frobenius6(&self) -> Fp12 {
        let (mut a, mut b, mut c) = (self.c0, self.c1, self.c2);
        a = a.conjugate();
        b = b.conjugate();
        b = b.fp_neg();
        c = c.conjugate();
        Fp12 {
            c0: a,
            c1: b,
            c2: c,
        }
    }

    pub(crate) fn fp12_frobenius2(&self) -> Fp12 {
        let (mut a, mut b, mut c) = (self.c0, self.c1, self.c2);
        a = a.conjugate();
        b = b.conjugate();
        b = b.fp_mul_fp(&SM9_MONT_ALPHA2);
        c = c.conjugate();
        c = c.fp_mul_fp(&SM9_MONT_ALPHA4);
        Fp12 {
            c0: a,
            c1: b,
            c2: c,
        }
    }

    pub(crate) fn final_exponent_hard_part(&self) -> Fp12 {
        // a2 = 0xd8000000019062ed0000b98b0cb27659
        // a3 = 0x2400000000215d941
        let a2: Fp = [0x0000b98b0cb27659, 0xd8000000019062ed, 0, 0];
        let a3: Fp = [0x400000000215d941, 0x2, 0, 0];
        let nine: Fp = [9, 0, 0, 0];

        let mut t0 = self.pow(&a3);
        t0 = t0.fp_inv();
        let mut t1 = t0.fp12_frobenius();
        t1 = t0.fp_mul(&t1);

        t0 = t0.fp_mul(&t1);
        let mut t2 = self.fp12_frobenius();
        let mut t3 = t2.fp_mul(self);
        t3 = t3.pow(&nine);

        t0 = t0.fp_mul(&t3);
        t3 = self.fp_sqr();
        t3 = t3.fp_sqr();
        t0 = t0.fp_mul(&t3);
        t2 = t2.fp_sqr();
        t2 = t2.fp_mul(&t1);

        t1 = self.fp12_frobenius2();
        t1 = t1.fp_mul(&t2);

        t2 = t1.pow(&a2);
        t0 = t2.fp_mul(&t0);
        t1 = self.fp12_frobenius3();
        t1 = t1.fp_mul(&t0);

        t1
    }

    pub(crate) fn final_exponent(&self) -> Fp12 {
        let mut t0 = self.fp12_frobenius6();
        let mut t1 = self.fp_inv();
        t0 = t0.fp_mul(&t1);
        t1 = t0.fp12_frobenius2();
        t0 = t0.fp_mul(&t1);
        t0 = t0.final_exponent_hard_part();
        t0
    }

    fn fp12_frobenius(&self) -> Self {
        let (a, b, c) = (self.c0, self.c1, self.c2);
        let (mut ra, mut rb, mut rc) = (Fp4::zero(), Fp4::zero(), Fp4::zero());

        ra.c0 = a.c0.conjugate();
        ra.c1 = a.c1.conjugate();
        ra.c1 = ra.c1.fp_mul_fp(&SM9_MONT_ALPHA3);

        rb.c0 = b.c0.conjugate();
        rb.c0 = rb.c0.fp_mul_fp(&SM9_MONT_ALPHA1);
        rb.c1 = b.c1.conjugate();
        rb.c1 = rb.c1.fp_mul_fp(&SM9_MONT_ALPHA4);

        rc.c0 = c.c0.conjugate();
        rc.c0 = rc.c0.fp_mul_fp(&SM9_MONT_ALPHA2);
        rc.c1 = c.c1.conjugate();
        rc.c1 = rc.c1.fp_mul_fp(&SM9_MONT_ALPHA5);

        Self {
            c0: ra,
            c1: rb,
            c2: rc,
        }
    }

    fn fp12_frobenius3(&self) -> Self {
        let (a, b, c) = (self.c0, self.c1, self.c2);
        let (mut ra, mut rb, mut rc) = (Fp4::zero(), Fp4::zero(), Fp4::zero());

        ra.c0 = a.c0.conjugate();
        ra.c1 = a.c1.conjugate();
        ra.c1 = ra.c1.fp_mul(&SM9_MONT_BETA);
        ra.c1 = ra.c1.fp_neg();

        rb.c0 = b.c0.conjugate();
        rb.c0 = rb.c0.fp_mul(&SM9_MONT_BETA);
        rb.c1 = b.c1.conjugate();

        rc.c0 = c.c0.conjugate();
        rc.c0 = rc.c0.fp_neg();
        rc.c1 = c.c1.conjugate();
        rc.c1 = rc.c1.fp_mul(&SM9_MONT_BETA);
        Self {
            c0: ra,
            c1: rb,
            c2: rc,
        }
    }
}

impl PartialEq for Fp12 {
    fn eq(&self, other: &Self) -> bool {
        self.c0.eq(&other.c0) && self.c1.eq(&other.c1) && self.c2.eq(&other.c2)
    }
}

impl Eq for Fp12 {}

impl FieldElement for Fp12 {
    fn zero() -> Self {
        Self {
            c0: Fp4::zero(),
            c1: Fp4::zero(),
            c2: Fp4::zero(),
        }
    }

    fn one() -> Self {
        Self {
            c0: Fp4::one(),
            c1: Fp4::zero(),
            c2: Fp4::zero(),
        }
    }

    fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero() && self.c2.is_zero()
    }

    fn fp_sqr(&self) -> Self {
        let mut r0 = Fp4::zero();
        let mut r1 = Fp4::zero();
        let mut r2 = Fp4::zero();
        let mut t = Fp4::zero();

        let mut s0 = Fp4::zero();
        let mut s1 = Fp4::zero();
        let mut s2 = Fp4::zero();
        let mut s3 = Fp4::zero();

        r0 = self.c0.fp_sqr();
        r1 = self.c2.fp_sqr();
        s0 = self.c2.fp_add(&self.c0);

        t = s0.fp_sub(&self.c1);
        s1 = t.fp_sqr();

        t = s0.fp_add(&self.c1);
        s0 = t.fp_sqr();

        s2 = self.c1.fp_mul(&self.c2);
        s2 = s2.fp_double();

        s3 = s0.fp_add(&s1);
        s3 = s3.fp_div2();

        t = s3.fp_sub(&r1);
        r2 = t.fp_sub(&r0);

        r1 = r1.a_mul_v();
        r1 = r1.fp_add(&s0);
        r1 = r1.fp_sub(&s2);
        r1 = r1.fp_sub(&s3);

        s2 = s2.a_mul_v();
        r0 = r0.fp_add(&s2);

        Self {
            c0: r0,
            c1: r1,
            c2: r2,
        }
    }

    fn fp_double(&self) -> Self {
        Self {
            c0: self.c0.fp_double(),
            c1: self.c1.fp_double(),
            c2: self.c2.fp_double(),
        }
    }

    fn fp_triple(&self) -> Self {
        let t = self.fp_double();
        t.fp_add(self)
    }

    fn fp_add(&self, rhs: &Self) -> Self {
        Self {
            c0: self.c0.fp_add(&rhs.c0),
            c1: self.c1.fp_add(&rhs.c1),
            c2: self.c2.fp_add(&rhs.c2),
        }
    }

    fn fp_sub(&self, rhs: &Self) -> Self {
        Self {
            c0: self.c0.fp_sub(&rhs.c0),
            c1: self.c1.fp_sub(&rhs.c1),
            c2: self.c2.fp_sub(&rhs.c2),
        }
    }

    fn fp_mul(&self, rhs: &Self) -> Self {
        let (mut r0, mut r1, mut r2) = (Fp4::zero(), Fp4::zero(), Fp4::zero());
        let (mut t, mut k0, mut k1) = (Fp4::zero(), Fp4::zero(), Fp4::zero());
        let (mut m0, mut m1, mut m2) = (Fp4::zero(), Fp4::zero(), Fp4::zero());

        m0 = self.c0.fp_mul(&rhs.c0);
        m1 = self.c1.fp_mul(&rhs.c1);
        m2 = self.c2.fp_mul(&rhs.c2);

        k0 = self.c1.fp_add(&self.c2);
        k1 = rhs.c1.fp_add(&rhs.c2);
        t = k0.fp_mul(&k1);
        t = t.fp_sub(&m1);
        t = t.fp_sub(&m2);
        t = t.a_mul_v();
        r0 = t.fp_add(&m0);

        k0 = self.c0.fp_add(&self.c2);
        k1 = rhs.c0.fp_add(&rhs.c2);
        t = k0.fp_mul(&k1);
        t = t.fp_sub(&m0);
        t = t.fp_sub(&m2);
        r2 = t.fp_add(&m1);

        k0 = self.c0.fp_add(&self.c1);
        k1 = rhs.c0.fp_add(&rhs.c1);
        t = k0.fp_mul(&k1);
        t = t.fp_sub(&m0);
        t = t.fp_sub(&m1);
        m2 = m2.a_mul_v();
        r1 = t.fp_add(&m2);

        Self {
            c0: r0,
            c1: r1,
            c2: r2,
        }
    }

    fn fp_neg(&self) -> Self {
        Self {
            c0: self.c0.fp_neg(),
            c1: self.c1.fp_neg(),
            c2: self.c2.fp_neg(),
        }
    }

    fn fp_div2(&self) -> Self {
        Self {
            c0: self.c0.fp_div2(),
            c1: self.c1.fp_div2(),
            c2: self.c2.fp_div2(),
        }
    }

    fn fp_inv(&self) -> Self {
        if self.c2.is_zero() {
            let mut r = Fp12::zero();
            let mut k = Fp4::zero();
            let mut t = Fp4::zero();

            k = self.c0.fp_sqr();
            k = k.fp_mul(&self.c0);
            t = self.c1.sqr_v();
            t = t.fp_mul(&self.c1);
            k = k.fp_add(&t);
            k = k.fp_inv();

            r.c2 = self.c1.fp_sqr();
            r.c2 = r.c2.fp_mul(&k);

            r.c1 = self.c0.fp_mul(&self.c1);
            r.c1 = r.c1.fp_mul(&k);
            r.c1 = r.c1.fp_neg();

            r.c0 = self.c0.fp_sqr();
            r.c0 = r.c0.fp_mul(&k);
            r
        } else {
            let mut r = Fp12::zero();
            let mut t0 = Fp4::zero();
            let mut t1 = Fp4::zero();
            let mut t2 = Fp4::zero();
            let mut t3 = Fp4::zero();

            t0 = self.c1.fp_sqr();
            t1 = self.c0.fp_mul(&self.c2);
            t0 = t0.fp_sub(&t1);

            t1 = self.c0.fp_mul(&self.c1);
            t2 = self.c2.sqr_v();
            t1 = t1.fp_sub(&t2);

            t2 = self.c0.fp_sqr();
            t3 = self.c1.fp_mul_v(&self.c2);
            t2 = t2.fp_sub(&t3);

            t3 = t1.fp_sqr();
            r.c0 = t0.fp_mul(&t2);
            t3 = t3.fp_sub(&r.c0);
            t3 = t3.fp_inv();
            t3 = self.c2.fp_mul(&t3);

            r.c0 = t2.fp_mul(&t3);

            r.c1 = t1.fp_mul(&t3);
            r.c1 = r.c1.fp_neg();

            r.c2 = t0.fp_mul(&t3);
            r
        }
    }

    fn to_bytes_be(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        bytes.extend_from_slice(self.c2.to_bytes_be().as_slice());
        bytes.extend_from_slice(self.c1.to_bytes_be().as_slice());
        bytes.extend_from_slice(self.c0.to_bytes_be().as_slice());
        bytes
    }
}

impl Fp12 {
    pub(crate) fn pow(&self, e: &U256) -> Self {
        assert!(*e < SM9_N_MINUS_ONE);
        let mut w = 0_u64;
        let mut t = Fp12 {
            c0: Fp4::mont_one(),
            c1: Fp4::zero(),
            c2: Fp4::zero(),
        };

        for i in (0..4).rev() {
            w = e[i];
            for j in 0..64 {
                t = t.fp_sqr();
                if w & 0x8000000000000000 == 1 {
                    t = t.fp_mul(self)
                }
                w <<= 1;
            }
        }
        t
    }
}
