//! A simple program that takes a number `n` and produces the n-th Fibonacci number.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use rand::Rng;

pub fn main() {
    let n: usize = sp1_zkvm::io::read::<u32>().try_into().unwrap();

    let mut a: u32 = 0;
    let mut b: u32 = 1;
    for _ in 0..n {
        (a, b) = (b, a.wrapping_add(b));
    }
    sp1_zkvm::io::commit::<u32>(&a);
}
