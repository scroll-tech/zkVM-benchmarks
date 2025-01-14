//! A simple program that takes a number `n` and counts the number of primes up to n
//! number as an output.

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use rand::Rng;

pub fn main() {
    let n: usize = sp1_zkvm::io::read::<u32>().try_into().unwrap();

    // Provide some random numbers to sort.
    let mut rng = rand::thread_rng();
    let mut scratch: Vec<u32> = (0..n).map(|_| rng.gen::<u32>()).collect::<Vec<_>>();
    scratch.sort();
}
