extern crate lambdaworks_math;
extern crate psi_vole;
extern crate rand;

use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::unsigned_integer::element::UnsignedInteger;
use psi_vole::base_cot::BaseCot;
use psi_vole::base_svole::BaseSvole;
use psi_vole::comm_channel::CommunicationChannel;
use psi_vole::mpfss_reg::MpfssReg;
use psi_vole::preot::OTPre;
use psi_vole::socket_channel::TcpChannel;
use psi_vole::spfss_sender::SpfssSenderFp;
use rand::random;
use std::env;
use std::net::{TcpListener, TcpStream};
use std::time::Instant;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub fn rand_field_element() -> FE {
    let rand_big = UnsignedInteger { limbs: random() };
    FE::new(rand_big)
}

fn main() {
    // Get the role argument (sender or receiver)
    let role = env::args()
        .nth(1)
        .expect("Please specify 'sender' or 'receiver' as an argument");

    const LOG_BIN_SZ: usize = 4;
    const T: usize = 100;
    const N: usize = T * (1 << LOG_BIN_SZ);
    const K: usize = 2;

    let mut comm: u64 = 0;

    if role == "receiver" {
        // Receiver logic
        // Listen for the sender
        let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to port");
        let (stream, _) = listener.accept().expect("Failed to accept connection");
        let mut channel = TcpChannel::new(stream);

        // Initialize BaseCot for the receiver (BOB)
        let mut receiver_cot = BaseCot::new(1, false);

        // Set up the receiver's precomputation phase
        receiver_cot.cot_gen_pre(&mut channel, None, &mut comm);
        let mut pre_ot = OTPre::new(LOG_BIN_SZ, T);
        receiver_cot.cot_gen_preot(&mut channel, &mut pre_ot, LOG_BIN_SZ * T, None, &mut comm);

        let mut mac = vec![FE::zero(); T + 1];
        let mut u = vec![FE::zero(); T + 1];

        // Base sVOLE first
        let mut svole = BaseSvole::new_receiver(&mut channel, &mut comm);
        // mac = key + delta * u
        svole.triple_gen_recv(&mut channel, &mut mac, &mut u, T + 1, &mut comm);

        let mut y = vec![FE::zero(); N];
        let mut z = vec![FE::zero(); N];
        let mut mpfss = MpfssReg::new(N, T, LOG_BIN_SZ, 1);
        mpfss.set_malicious();

        mpfss.receiver_init();
        mpfss.mpfss_receiver(
            &mut channel,
            &mut pre_ot,
            &mac,
            &u,
            &mut y,
            &mut z,
            &mut comm,
        );
    } else if role == "sender" {
        // Sender logic
        // Connect to the receiver
        let stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to receiver");
        let mut channel = TcpChannel::new(stream);

        // Initialize BaseCot for the sender (ALICE)
        let mut sender_cot = BaseCot::new(0, false);

        // Set up the sender's precomputation phase
        sender_cot.cot_gen_pre(&mut channel, None, &mut comm);
        let mut pre_ot = OTPre::new(LOG_BIN_SZ, T);
        sender_cot.cot_gen_preot(&mut channel, &mut pre_ot, LOG_BIN_SZ * T, None, &mut comm);

        let delta = rand_field_element();
        let mut key = vec![FE::zero(); T + 1];

        // Base sVOLE first
        let mut svole = BaseSvole::new_sender(&mut channel, delta, &mut comm);
        // mac = key + delta * u
        svole.triple_gen_send(&mut channel, &mut key, T + 1, &mut comm);

        let mut y = vec![FE::zero(); N];
        let mut mpfss = MpfssReg::new(N, T, LOG_BIN_SZ, 0);
        mpfss.set_malicious();

        mpfss.sender_init(delta);

        let start = Instant::now();
        mpfss.mpfss_sender(&mut channel, &mut pre_ot, &key, &mut y, &mut comm);
        let duration = start.elapsed();
        println!("Time taken to generate {} Spfss: {:?}", T, duration);
    } else {
        panic!("Invalid role specified. Please specify 'sender' or 'receiver'.");
    }

    println!("Total data sent: {} bytes", comm);
}
