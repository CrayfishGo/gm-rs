use criterion::{BenchmarkGroup, Criterion, criterion_group, criterion_main};
use criterion::measurement::Measurement;
use num_bigint::ModInverse;
use rand::{Rng, thread_rng};

use gm_rs::sm2::FeOperation;
use gm_rs::sm2::key::{CompressModle, gen_keypair, Sm2PrivateKey, Sm2PublicKey};
use gm_rs::sm2::p256_ecc::{P256C_PARAMS, Point};
use gm_rs::sm2::p256_field::FieldElement;
use gm_rs::sm2::p256_pre_table::PRE_TABLE_1;

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
    let mut group = c.benchmark_group("bench_sign");
    let msg = b"hellohellohellohellohellohellohellohellohellohellohellohellohello";
    let (_pk, sk) = test_gen_keypair();
    group.bench_function("bench_sign", |b| b.iter(|| sk.sign(None, msg).unwrap()));
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_verify");
    let msg = b"hellohellohellohellohellohellohellohellohellohellohellohellohello";
    let (sig, sk) = test_sign();
    let pk = sk.public_key;
    group.bench_function("bench_verify", |b| {
        b.iter(|| pk.verify(None, msg, &sig).unwrap())
    });
    group.finish();
}

fn bench_point_double(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_point_double");
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
    let mut group = c.benchmark_group("bench_point_add");
    let mut rng = thread_rng();
    let n1: u32 = rng.gen_range(10..100);
    let p1 = &PRE_TABLE_1[n1 as usize];
    let n2: u32 = rng.gen_range(100..256);
    let p2 = &PRE_TABLE_1[n2 as usize];
    group.bench_function("bench_point_add", |b| b.iter(|| p1.add(p2)));
    group.finish();
}

fn bench_mod_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_mod_add");
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
    let mut group = c.benchmark_group("bench_mod_sub");
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
    let mut group = c.benchmark_group("bench_mod_mul");
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

fn bench_mod_inv(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_mod_inv");
    let a = FieldElement::new([
        764497930, 2477372445, 473039778, 1327312203, 3110691882, 1307193102, 2665428562, 967816337,
    ]);
    group.bench_function("bench_mod_inv", |x| x.iter(|| a.modinv()));
    group.finish();
}


criterion_group!(
    benches,
    bench_sign,
    bench_verify,
    bench_point_double,
    bench_point_add,
    bench_mod_add,
    bench_mod_sub,
    bench_mod_mul,
    bench_mod_inv,
);
criterion_main!(benches);
