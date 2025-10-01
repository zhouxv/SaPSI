extern crate lambdaworks_math;
extern crate psi_vole;

use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use psi_vole::comm_channel::CommunicationChannel;
use psi_vole::socket_channel::TcpChannel;
use std::net::{TcpListener, TcpStream};
use std::time::Instant;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

fn bench_32byte<IO: CommunicationChannel>(channel: &mut IO) {
    const SIZE: usize = 10000;
    let elements = [[0u8; 32]; 4];

    let start = Instant::now();
    for i in 0..SIZE {
        let x = channel.receive_block::<32>().unwrap();
    }
    let duration = start.elapsed();

    println!("Receive {} elements in {:?}", SIZE, duration);
}

fn main() {
    let element_count = 100_000; // Number of elements to receive

    // Listen for the sender
    let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to port");
    let (stream, _) = listener.accept().expect("Failed to accept connection");
    let mut channel = TcpChannel::new(stream);

    // Benchmark receive_stark252
    let start = Instant::now();
    let elements = channel
        .receive_stark252()
        .expect("Failed to receive elements");
    let duration = start.elapsed();

    println!("Received {} elements in {:?}", elements.len(), duration);

    // Receive the bits
    let received_bits = channel.receive_bits().expect("Failed to receive bits");

    println!("Receiver: Received bits: {:?}", received_bits);
    println!("Receiver: Bits received successfully.");

    bench_32byte(&mut channel);
}
