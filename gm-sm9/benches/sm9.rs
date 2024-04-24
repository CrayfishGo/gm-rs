use criterion::{Criterion, criterion_group, criterion_main};

use gm_sm9::fields::FieldElement;
use gm_sm9::fields::fp::{fp_from_mont, mont_mul, fp_to_mont};

fn bench_mod_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("sm9");
    let a: [u64; 4] = [
        0x54806C11D8806141,
        0xF1DD2C190F5E93C4,
        0x597B6027B441A01F,
        0x85AEF3D078640C98,
    ];

    let b: [u64; 4] = [
        0x0E75C05FB4E3216D,
        0x1006E85F5CDFF073,
        0x1A7CE027B7A46F74,
        0x41E00A53DDA532DA,
    ];
    group.bench_function("bench_mod_add", |x| x.iter(|| a.fp_add(&b)));
    group.finish();
}

fn bench_mod_sub(c: &mut Criterion) {
    let mut group = c.benchmark_group("sm9");
    let a: [u64; 4] = [
        0x54806C11D8806141,
        0xF1DD2C190F5E93C4,
        0x597B6027B441A01F,
        0x85AEF3D078640C98,
    ];

    let b: [u64; 4] = [
        0x0E75C05FB4E3216D,
        0x1006E85F5CDFF073,
        0x1A7CE027B7A46F74,
        0x41E00A53DDA532DA,
    ];
    group.bench_function("bench_mod_sub", |x| x.iter(|| a.fp_sub(&b)));
    group.finish();
}

fn bench_mod_mul(c: &mut Criterion) {
    let mut group = c.benchmark_group("sm9");
    let mut a: [u64; 4] = [
        0x54806C11D8806141,
        0xF1DD2C190F5E93C4,
        0x597B6027B441A01F,
        0x85AEF3D078640C98,
    ];
    group.bench_function("bench_mod_mul", |x| x.iter(|| {
        a = mont_mul(&a, &a)
    }));
    group.finish();
}

fn bench_mod_inv(c: &mut Criterion) {
    let mut group = c.benchmark_group("sm9");
    let a: [u64; 4] = [
        0x54806C11D8806141,
        0xF1DD2C190F5E93C4,
        0x597B6027B441A01F,
        0x85AEF3D078640C98,
    ];
    group.bench_function("bench_mod_inv", |x| x.iter(|| a.fp_inv()));
    group.finish();
}

criterion_group!(
    benches,
    bench_mod_add,
    bench_mod_sub,
    bench_mod_mul,
    bench_mod_inv,
);
criterion_main!(benches);
