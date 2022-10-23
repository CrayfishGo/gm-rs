use crate::sm2::p256_ecc::{Point, P256C_PARAMS};

pub(crate) fn add_mlsm(p1: &Point, p2: &Point) -> Point {
    let x1 = &p1.x;
    let y1 = &p1.y;
    let z1 = &p1.z;
    let x2 = &p2.x;
    let y2 = &p2.y;

    let z1z1 = z1.square();
    let u2 = x2 * &z1z1;
    let z1z1z1 = &z1z1 * z1;
    let y2z1z1z1 = y2 * &z1z1z1;
    let y2z1z1z1_y1 = &y2z1z1z1 - y1;
    let y2z1z1z1_y12 = &y2z1z1z1_y1.square();
    let x2z1z1_x1 = &u2 - x1;
    let x2z1z1_x12 = &x2z1z1_x1.square();
    let x2z1z1_x13 = x2z1z1_x12 * &x2z1z1_x1;

    let x3 = y2z1z1z1_y12 - x2z1z1_x12 * (x1 + &u2);
    let y3 = &y2z1z1z1_y1 * (x1 * x2z1z1_x12 - &x3) - y1 * &x2z1z1_x13;
    let z3 = &x2z1z1_x1 * z1;

    Point {
        x: x3,
        y: y3,
        z: z3,
    }
}

//       Z1Z1 = Z12
//       Z2Z2 = Z22
//       U1 = X1*Z2Z2
//       U2 = X2*Z1Z1
//       S1 = Y1*Z2*Z2Z2
//       S2 = Y2*Z1*Z1Z1
//       H = U2-U1
//       I = (2*H)2
//       J = H*I
//       r = 2*(S2-S1)
//       V = U1*I
//       X3 = r2-J-2*V
//       Y3 = r*(V-X3)-2*S1*J
//       Z3 = ((Z1+Z2)2-Z1Z1-Z2Z2)*H
pub(crate) fn add_2007_bl(p1: &Point, p2: &Point) -> Point {
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

    let i = h.double().square();
    let j = &h * &i;
    let r = (&s2 - &s1).double();
    let v = &u1 * &i;
    let x3 = &r.square() - &j - &v.double();
    let y3 = &r * (&v - &x3) - &s1 * &j.double();
    let z3 = &h * ((z1 + z2).square() - &z1z1 - z2z2);

    Point {
        x: x3,
        y: y3,
        z: z3,
    }
}

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

pub(crate) fn double_mlsm(p1: &Point) -> Point {
    let (x1, y1, z1) = (&p1.x, &p1.y, &p1.z);
    let xx = x1.square();
    let yy = y1.square();
    let zz = z1.square();
    let yyyy = &yy.square();
    let zzzz = &zz.square();
    let xzzplus = x1 + &zz;
    let xzzsub = x1 - &zz;
    let xzzplus3 = &xzzplus + &xzzplus.double();
    let xyy = x1 * &yy;
    let xyy8 = &xyy
        .double()
        .double()
        .double()
        .double()
        .double()
        .double()
        .double();
    let xyy12 = &xyy8.double().double().double();
    let yyyy8 = &yyyy
        .double()
        .double()
        .double()
        .double()
        .double()
        .double()
        .double();
    let t = &xzzplus3 * &xzzsub;
    let tt = &t * &t;
    let xxzzzzsub = (&xx - zzzz).square();
    let xxzzzzsub9 = &xxzzzzsub
        + &xxzzzzsub
            .double()
            .double()
            .double()
            .double()
            .double()
            .double()
            .double();
    let x3 = &tt - xyy8;
    let y3 = &t * (xyy12 - &xxzzzzsub9) - yyyy8;
    let z3 = (y1 * z1).double();

    Point {
        x: x3,
        y: y3,
        z: z3,
    }
}

//       XX = X12
//       YY = Y12
//       YYYY = YY2
//       ZZ = Z12
//       S = 2*((X1+YY)2-XX-YYYY)
//       M = 3*XX+a*ZZ2
//       T = M2-2*S
//       X3 = T
//       Y3 = M*(S-T)-8*YYYY
//       Z3 = (Y1+Z1)2-YY-ZZ
pub(crate) fn double_2007_bl(p1: &Point) -> Point {
    let ecc_a = &P256C_PARAMS.a;
    let (x1, y1, z1) = (&p1.x, &p1.y, &p1.z);
    let xx = x1.square();
    let yy = y1.square();
    let zz = z1.square();

    let yyyy = &yy.square();
    let s = ((x1 + &yy).square() - &xx - yyyy).double();
    let m = &xx.double() + &xx + ecc_a * &zz.square();
    let t = &m.square() - &s.double();
    let y3 = &m * (&s - &t) - yyyy.double().double().double();
    let x3 = t;
    let z3 = (y1 + z1).square() - &yy - &zz;
    let p = Point {
        x: x3,
        y: y3,
        z: z3,
    };
    p
}
