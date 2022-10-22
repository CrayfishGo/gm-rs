use criterion::measurement::Measurement;
use criterion::{criterion_group, criterion_main, BenchmarkGroup, Criterion};
use gm_rs::sm2::key::{gen_keypair, CompressModle, Sm2PrivateKey, Sm2PublicKey};
use gm_rs::sm2::signature;
use gm_rs::sm2::signature::Signature;

fn test_gen_keypair() -> (Sm2PublicKey, Sm2PrivateKey) {
    gen_keypair(CompressModle::Compressed).unwrap()
}

fn test_sign() -> (Sm2PublicKey, Signature) {
    let msg = b"hellohellohellohellohellohellohellohellohellohellohellohellohello";
    let (pk, sk) = test_gen_keypair();
    let sig = signature::sign(None, msg, &sk.d, &pk).unwrap();
    (pk, sig)
}

fn bench_sign_g<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let msg = b"hellohellohellohellohellohellohellohellohellohellohellohellohello";
    let (pk, sk) = test_gen_keypair();
    group.bench_function("bench_sign", |b| {
        b.iter(|| signature::sign(None, msg, &sk.d, &pk).unwrap())
    });
}

fn bench_verify_g<'a, M: Measurement>(group: &mut BenchmarkGroup<'a, M>) {
    let msg = b"hellohellohellohellohellohellohellohellohellohellohellohellohello";
    let (pk, sig) = test_sign();
    group.bench_function("bench_verify", |b| {
        b.iter(|| sig.verify(None, msg, &pk).unwrap())
    });
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

criterion_group!(benches, bench_sign, bench_verify);
criterion_main!(benches);
