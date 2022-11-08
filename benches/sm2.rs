use criterion::measurement::Measurement;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use num_bigint::{ModInverse, ToBigInt};
use rand::{thread_rng, Rng};

use gm_rs::sm2::key::{gen_keypair, CompressModle, Sm2PrivateKey, Sm2PublicKey};
use gm_rs::sm2::montgomery::{montgomery_mod, montgomery_mul_mod};
use gm_rs::sm2::p256_ecc::{Point, P256C_PARAMS};
use gm_rs::sm2::p256_field::FieldElement;
use gm_rs::sm2::p256_pre_table::PRE_TABLE_1;
use gm_rs::sm2::FeOperation;
use gm_rs::sm2::field64::{fe_from_montgomery, fe_mul, fe_to_montgomery};

fn test_gen_keypair() -> (Sm2PublicKey, Sm2PrivateKey) {
    gen_keypair(CompressModle::Compressed).unwrap()
}

fn test_sign() -> (Vec<u8>, Sm2PrivateKey) {
    let msg = b"hellohellohellohellohellohellohellohellohellohellohellohellohello";
    let (_pk, sk) = test_gen_keypair();
    let sig = sk.sign(None, msg).unwrap();
    (sig, sk)
}

fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("sm2");
    let msg = b"hellohellohellohellohellohellohellohellohellohellohellohellohello";
    let (_pk, sk) = test_gen_keypair();
    group.bench_function("bench_sign", |b| b.iter(|| sk.sign(None, msg).unwrap()));
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("sm2");
    let msg = b"hellohellohellohellohellohellohellohellohellohellohellohellohello";
    let (sig, sk) = test_sign();
    let pk = sk.public_key;
    group.bench_function("bench_verify", |b| {
        b.iter(|| pk.verify(None, msg, &sig).unwrap())
    });
    group.finish();
}

fn bench_point_double(c: &mut Criterion) {
    let mut group = c.benchmark_group("sm2");
    let mut rng = thread_rng();
    let n: u32 = rng.gen_range(10..256);
    let mut p = PRE_TABLE_1[n as usize];
    group.bench_function("bench_point_double", |b| {
        b.iter(|| {
            p = p.double();
        })
    });
    group.finish();
}

fn bench_point_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("sm2");
    let mut rng = thread_rng();
    let n1: u32 = rng.gen_range(10..100);
    let p1 = &PRE_TABLE_1[n1 as usize];
    let n2: u32 = rng.gen_range(100..256);
    let p2 = &PRE_TABLE_1[n2 as usize];
    group.bench_function("bench_point_add", |b| b.iter(|| p1.add(p2)));
    group.finish();
}

fn bench_mod_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("sm2");
    let a = FieldElement::new([
        764497930, 2477372445, 473039778, 1327312203, 3110691882, 1307193102, 2665428562, 967816337,
    ]);
    let b = FieldElement::new([
        2873589426, 3315627933, 3055686524, 325110103, 3264434653, 2512214348, 3018997295,
        3617546169,
    ]);
    group.bench_function("bench_mod_add", |x| x.iter(|| a + b));
    group.finish();
}

fn bench_mod_sub(c: &mut Criterion) {
    let mut group = c.benchmark_group("sm2");
    let a = FieldElement::new([
        764497930, 2477372445, 473039778, 1327312203, 3110691882, 1307193102, 2665428562, 967816337,
    ]);
    let b = FieldElement::new([
        2873589426, 3315627933, 3055686524, 325110103, 3264434653, 2512214348, 3018997295,
        3617546169,
    ]);
    group.bench_function("bench_mod_sub", |x| x.iter(|| b - a));
    group.finish();
}

fn bench_mod_mul(c: &mut Criterion) {
    let mut group = c.benchmark_group("sm2");
    let a = FieldElement::new([
        764497930, 2477372445, 473039778, 1327312203, 3110691882, 1307193102, 2665428562, 967816337,
    ]);
    let b = FieldElement::new([
        2873589426, 3315627933, 3055686524, 325110103, 3264434653, 2512214348, 3018997295,
        3617546169,
    ]);
    group.bench_function("bench_mod_mul", |x| x.iter(|| a * b));
    group.finish();
}

fn bench_mod_mul_mont(c: &mut Criterion) {
    let mut group = c.benchmark_group("sm2");
    let a = FieldElement::new([
        764497930, 2477372445, 473039778, 1327312203, 3110691882, 1307193102, 2665428562, 967816337,
    ]);
    let b = FieldElement::new([
        2873589426, 3315627933, 3055686524, 325110103, 3264434653, 2512214348, 3018997295,
        3617546169,
    ]);
    let aa = a.to_biguint().to_bigint().unwrap();
    let bb = b.to_biguint().to_bigint().unwrap();
    let p = P256C_PARAMS.p.to_biguint().to_bigint().unwrap();
    group.bench_function("bench_mod_mul_mont", |x| {
        x.iter(|| montgomery_mod(&(&aa * &bb), &p))
    });
    group.finish();
}

fn bench_mod_mul_mont_2(c: &mut Criterion) {
    let mut group = c.benchmark_group("sm2");
    let a = FieldElement::new([
        764497930, 2477372445, 473039778, 1327312203, 3110691882, 1307193102, 2665428562, 967816337,
    ]);
    let b = FieldElement::new([
        2873589426, 3315627933, 3055686524, 325110103, 3264434653, 2512214348, 3018997295,
        3617546169,
    ]);
    let aa = a.to_biguint().to_bigint().unwrap();
    let bb = b.to_biguint().to_bigint().unwrap();
    let p = P256C_PARAMS.p.to_biguint().to_bigint().unwrap();
    group.bench_function("bench_mod_mul_mont_2", |x| {
        x.iter(|| montgomery_mul_mod(&aa, &bb, &p))
    });
    group.finish();
}
//
// fn bench_mod_mul_mont_3(c: &mut Criterion) {
//     let mut group = c.benchmark_group("sm2");
//     let a: &[u64; 4] = &[
//         0xfffff8950000053b,
//         0xfffffdc600000543,
//         0xfffffb8c00000324,
//         0xfffffc4d0000064e,
//     ];
//
//     let b: &[u64; 4] = &[
//         0x16553623adc0a99a,
//         0xd3f55c3f46cdfd75,
//         0x7bdb6926ab664658,
//         0x52ab139ac09ec830,
//     ];
//     group.bench_function("bench_mod_mul_mont_3", |x| {
//         x.iter(|| {
//             let aa = fe_to_montgomery(&a);
//             let bb = fe_to_montgomery(&b);
//             let ret = fe_from_montgomery(&fe_mul(&aa, &bb));
//         })
//     });
//     group.finish();
// }

fn bench_mod_mul_bigint_2(c: &mut Criterion) {
    let mut group = c.benchmark_group("sm2");
    let a = FieldElement::new([
        764497930, 2477372445, 473039778, 1327312203, 3110691882, 1307193102, 2665428562, 967816337,
    ]);
    let b = FieldElement::new([
        2873589426, 3315627933, 3055686524, 325110103, 3264434653, 2512214348, 3018997295,
        3617546169,
    ]);
    let aa = a.to_biguint().to_bigint().unwrap();
    let bb = b.to_biguint().to_bigint().unwrap();
    let p = P256C_PARAMS.p.to_biguint().to_bigint().unwrap();
    group.bench_function("bench_mod_mul_bigint", |x| x.iter(|| (&aa * &bb) % &p));
    group.finish();
}

fn bench_mod_inv(c: &mut Criterion) {
    let mut group = c.benchmark_group("sm2");
    let a = FieldElement::new([
        764497930, 2477372445, 473039778, 1327312203, 3110691882, 1307193102, 2665428562, 967816337,
    ]);
    group.bench_function("bench_mod_inv", |x| x.iter(|| a.modinv()));
    group.finish();
}

criterion_group!(
    benches,
    // bench_sign,
    // bench_verify,
    // bench_point_double,
    // bench_point_add,
    // bench_mod_add,
    // bench_mod_sub,
    bench_mod_mul,
    bench_mod_mul_mont,
    bench_mod_mul_mont_2,
    // bench_mod_mul_mont_3,
    bench_mod_mul_bigint_2,
    bench_mod_inv,
);
criterion_main!(benches);
