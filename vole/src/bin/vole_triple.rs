extern crate lambdaworks_math;
extern crate psi_vole;

use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use psi_vole::socket_channel::TcpChannel;
use psi_vole::utils::rand_field_element;
use psi_vole::vole_triple::{VoleTriple, LPN17};
use std::env;
use std::net::{TcpListener, TcpStream};
use std::time::Instant;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

fn main() {
    // Get the role argument (sender or receiver)
    let role = env::args()
        .nth(1)
        .expect("Please specify 'sender' or 'receiver' as an argument");

    let mut comm: u64 = 0;

    if role == "receiver" {
        // Receiver setup
        let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to port");
        let (stream, _) = listener.accept().expect("Failed to accept connection");
        let mut channel = TcpChannel::new(stream);

        let mut vole = VoleTriple::new(1, true, &mut channel, LPN17, &mut comm);

        let start = Instant::now();
        vole.setup_receiver(&mut channel, &mut comm);
        println!("Time taken for setup: {:?}", start.elapsed());

        vole.extend_initialization();

        const SIZE: usize = 100_000;
        let mut y = [FE::zero(); SIZE];
        let mut z = [FE::zero(); SIZE];
        let start = Instant::now();
        vole.extend(&mut channel, &mut y, &mut z, SIZE, &mut comm);
        println!("Time taken for one extend: {:?}", start.elapsed());
    } else if role == "sender" {
        // Sender setup
        let stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to receiver");
        let mut channel = TcpChannel::new(stream);

        let mut vole = VoleTriple::new(0, true, &mut channel, LPN17, &mut comm);

        let delta = rand_field_element();
        vole.setup_sender(&mut channel, delta, &mut comm);

        vole.extend_initialization();

        const SIZE: usize = 100_000;
        let mut y = [FE::zero(); SIZE];
        let mut z = [FE::zero(); SIZE];
        vole.extend(&mut channel, &mut y, &mut z, SIZE, &mut comm);
    } else {
        panic!("Invalid role specified. Please specify 'sender' or 'receiver'.");
    }

    println!("Total data sent: {} bytes", comm);
}
