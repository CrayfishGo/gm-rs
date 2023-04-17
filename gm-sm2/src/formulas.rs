use crate::p256_ecc::{Point, P256C_PARAMS};

//       Z1Z1 = Z12
//       Z2Z2 = Z22
//       U1 = X1*Z2Z2
//       U2 = X2*Z1Z1
//       S1 = Y1*Z2*Z2Z2
//       S2 = Y2*Z1*Z1Z1
//       H = U2-U1
//       HH = H2
//       HHH = H*HH
//       r = S2-S1
//       V = U1*HH
//       X3 = r2-HHH-2*V
//       Y3 = r*(V-X3)-S1*HHH
//       Z3 = Z1*Z2*H
pub(crate) fn add_1998_cmo(p1: &Point, p2: &Point) -> Point {
    let x1 = &p1.x;
    let y1 = &p1.y;
    let z1 = &p1.z;
    let x2 = &p2.x;
    let y2 = &p2.y;
    let z2 = &p2.z;

    let z1z1 = z1.square();
    let z2z2 = z2.square();
    let u1 = x1 * &z2z2;
    let u2 = x2 * &z1z1;
    let s1 = y1 * z2 * &z2z2;
    let s2 = y2 * z1 * &z1z1;
    let h = &u2 - &u1;

    let r = &s2 - &s1;
    let hh = h.square();
    let hhh = &h * &hh;
    let v = &u1 * &hh;
    let x3 = &r.square() - &hhh - &v.double();
    let y3 = &r * (&v - &x3) - &s1 * &hhh;
    let z3 = z1 * z2 * &h;

    Point {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// dbl-1998-cmo
/// Cost: 3M + 3S + 2^4 + 1*a + 4add + 2*2 + 1*3 + 1*4 + 1*8.
pub(crate) fn double_1998_cmo(p1: &Point) -> Point {
    let ecc_a = &P256C_PARAMS.a;
    let (x1, y1, z1) = (&p1.x, &p1.y, &p1.z);
    let is_z1_one = z1.is_one();
    let yy = y1.square();
    let yyyy = &yy.square();
    let xx = x1.square();
    let s = x1.double().double() * &yy;
    if !is_z1_one {
        let zz = z1.square();
        let m = &xx.double() + &xx + ecc_a * &zz.square();
        let t = &m.square() - &s.double();
        let y3 = &m * (&s - &t) - yyyy.double().double().double();
        let x3 = t;
        let z3 = (y1 + z1).square() - &yy - &zz;
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    } else {
        let m = (xx.double() + xx) + ecc_a;
        let t = &m.square() - &s.double();
        let x3 = t;
        let y3 = m * (s - &x3) - yyyy.double().double().double();
        let z3 = y1.double();
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }
}
