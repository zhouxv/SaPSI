// takes 2ms to run 100_000 to_bytes_le()
// take 500ns to run 100_000 plus
// take 500ns to run 100_000 mult

extern crate lambdaworks_math;
extern crate rand;

use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::traits::ByteConversion;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use rand::random;
use std::time::Instant;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub fn rand_field_element() -> FE {
    let rand_big = UnsignedInteger { limbs: random() };
    FE::new(rand_big)
}

fn main() {
    const SIZE: usize = 100000;
    let mut x = [FE::zero(); SIZE];
    for i in 0..SIZE {
        x[i] = rand_field_element();
    }

    let mut y = [[0u8; 32]; SIZE];

    let start = Instant::now();

    for i in 0..SIZE {
        y[i] = x[i].to_bytes_le();
    }

    let duration = start.elapsed();
    println!("Time taken for {} iterations: {:?}", SIZE, duration);

    let mut u = FE::zero();
    let start = Instant::now();

    for i in 0..SIZE {
        u += x[i];
    }

    let duration = start.elapsed();
    println!("Time taken for {} iterations: {:?}", SIZE, duration);

    let mut v = FE::one();
    let start = Instant::now();

    for i in 0..SIZE {
        v *= x[i];
    }

    let duration = start.elapsed();
    println!("Time taken for {} iterations: {:?}", SIZE, duration);

    let mut mem = [[FE::zero(); 16]; 600];
    for i in 0..600 {
        for j in 0..16 {
            mem[i][j] = rand_field_element();
        }
    }

    let mut dest = [FE::zero(); 16];
    let start = Instant::now();

    for i in 0..600 {
        dest.copy_from_slice(&mem[i]);
    }

    let duration = start.elapsed();
    println!("Time taken: {:?}", duration);
}
