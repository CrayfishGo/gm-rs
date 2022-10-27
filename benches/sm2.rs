use criterion::measurement::Measurement;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use gm_rs::sm2::key::{gen_keypair, CompressModle, Sm2PrivateKey, Sm2PublicKey};
use gm_rs::sm2::p256_ecc::{Point, P256C_PARAMS};
use gm_rs::sm2::p256_field::FieldElement;
use gm_rs::sm2::p256_pre_table::PRE_TABLE_1;
use rand::{thread_rng, Rng};

fn test_gen_keypair() -> (Sm2PublicKey, Sm2PrivateKey) {
    gen_keypair(CompressModle::Compressed).unwrap()
}

fn test_sign() -> (Vec<u8>, Sm2PrivateKey) {
    let msg = b"hellohellohellohellohellohellohellohellohellohellohellohellohello";
    let (_pk, sk) = test_gen_keypair();
    let sig = sk.sign(None, msg).unwrap();
    (sig, sk)
}

fn bench_sign_g<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let msg = b"hellohellohellohellohellohellohellohellohellohellohellohellohello";
    let (_pk, sk) = test_gen_keypair();
    group.bench_function("bench_sign", |b| b.iter(|| sk.sign(None, msg).unwrap()));
}

fn bench_verify_g<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let msg = b"hellohellohellohellohellohellohellohellohellohellohellohellohello";
    let (sig, sk) = test_sign();
    let pk = sk.public_key;
    group.bench_function("bench_verify", |b| {
        b.iter(|| pk.verify(None, msg, &sig).unwrap())
    });
}

fn test_point_double<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let mut rng = thread_rng();
    let n: u32 = rng.gen_range(10..256);
    let mut p = PRE_TABLE_1[n as usize];
    group.bench_function("bench_point_double", |b| {
        b.iter(|| {
            p = p.double();
        })
    });
}

fn test_point_add<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let mut rng = thread_rng();
    let n1: u32 = rng.gen_range(10..100);
    let p1 = &PRE_TABLE_1[n1 as usize];
    let n2: u32 = rng.gen_range(100..256);
    let p2 = &PRE_TABLE_1[n2 as usize];
    group.bench_function("bench_point_add", |b| b.iter(|| p1.add(p2)));
}

fn test_mod_add<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let a = FieldElement::new([
        764497930, 2477372445, 473039778, 1327312203, 3110691882, 1307193102, 2665428562, 967816337,
    ]);
    let b = FieldElement::new([
        2873589426, 3315627933, 3055686524, 325110103, 3264434653, 2512214348, 3018997295,
        3617546169,
    ]);
    group.bench_function("bench_mod_add", |x| x.iter(|| a + b));
}

fn test_mod_sub<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let a = FieldElement::new([
        764497930, 2477372445, 473039778, 1327312203, 3110691882, 1307193102, 2665428562, 967816337,
    ]);
    let b = FieldElement::new([
        2873589426, 3315627933, 3055686524, 325110103, 3264434653, 2512214348, 3018997295,
        3617546169,
    ]);
    group.bench_function("bench_mod_sub", |x| x.iter(|| a - b));
}

fn test_mod_mul<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let a = FieldElement::new([
        764497930, 2477372445, 473039778, 1327312203, 3110691882, 1307193102, 2665428562, 967816337,
    ]);
    let b = FieldElement::new([
        2873589426, 3315627933, 3055686524, 325110103, 3264434653, 2512214348, 3018997295,
        3617546169,
    ]);
    group.bench_function("bench_mod_mul", |x| x.iter(|| a * b));
}

fn test_mod_inv<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let a = FieldElement::new([
        764497930, 2477372445, 473039778, 1327312203, 3110691882, 1307193102, 2665428562, 967816337,
    ]);
    group.bench_function("bench_mod_inv", |x| x.iter(|| a.modinv()));
}

fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("test sign");
    bench_sign_g(&mut group);
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("test verify");
    bench_verify_g(&mut group);
    group.finish();
}

fn bench_point_double(c: &mut Criterion) {
    let mut group = c.benchmark_group("point double");
    test_point_double(&mut group);
    group.finish();
}

fn bench_point_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("point add");
    test_point_add(&mut group);
    group.finish();
}

fn bench_mod_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("mod add");
    test_mod_add(&mut group);
    group.finish();
}

fn bench_mod_sub(c: &mut Criterion) {
    let mut group = c.benchmark_group("mod sub");
    test_mod_sub(&mut group);
    group.finish();
}

fn bench_mod_mul(c: &mut Criterion) {
    let mut group = c.benchmark_group("mod mul");
    test_mod_mul(&mut group);
    group.finish();
}

fn bench_mod_inv(c: &mut Criterion) {
    let mut group = c.benchmark_group("mod inv");
    test_mod_inv(&mut group);
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
