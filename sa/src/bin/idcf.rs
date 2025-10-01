extern crate psi_network;
extern crate psi_ot;
extern crate psi_sa;
extern crate rand;

use psi_network::socket_channel::TcpChannel;
use psi_ot::base_cot::BaseCot;
use psi_ot::pre_ot::OTPre;
use psi_sa::idcf_receiver::IDCFReceiver;
use psi_sa::idcf_sender::IDCFSender;
use rand::prelude::*;
use std::env;
use std::net::{TcpListener, TcpStream};

fn main() {
    let role = env::args()
        .nth(1)
        .expect("Please specify 'sender' or 'receiver' as an argument");
    let mut comm: u64 = 0;

    const DEPTH: usize = 5;
    let mut idcf_sharing = [[0u8; 16]; 1 << (DEPTH + 1)];

    if role == "receiver" {
        println!("Starting as Receiver...");
        let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to port");
        let (stream, _) = listener.accept().expect("Failed to accept connection");
        let mut channel = TcpChannel::new(stream);

        // Initialize BaseCot for the receiver (BOB)
        let mut receiver_cot = BaseCot::new(1, false);

        // Set up the receiver's precomputation phase
        receiver_cot.cot_gen_pre(&mut channel, None, &mut comm);

        // Original COT generation
        let size = DEPTH + 1; // Number of COTs
        let times = 2;
        let mut choice_bits = vec![false; size * times];
        // Populate random choice bits
        for bit in &mut choice_bits {
            *bit = rand::random();
        }

        // New COT generation using OTPre
        let mut receiver_pre_ot = OTPre::<3>::new(size, times);
        receiver_cot.cot_gen_preot(
            &mut channel,
            &mut receiver_pre_ot,
            size * times,
            Some(&choice_bits),
            &mut comm,
        );

        // Now generate the IDCF
        let alpha = [13u8; 16];
        let mut idcf_receiver = IDCFReceiver::new(DEPTH, 1);

        idcf_receiver.set_alpha(alpha, 0);
        idcf_receiver.receive(&mut channel, &mut receiver_pre_ot, &mut comm);
        idcf_receiver.compute(&mut idcf_sharing, 0);

        idcf_receiver.consistency_check(&mut channel, &idcf_sharing, 0);
    } else if role == "sender" {
        // Connect to the receiver
        let stream = TcpStream::connect("127.0.0.1:8080").expect("Failed to connect to receiver");
        let mut channel = TcpChannel::new(stream);

        // Initialize BaseCot for the sender (ALICE)
        let mut sender_cot = BaseCot::new(0, false);

        // Set up the sender's precomputation phase
        sender_cot.cot_gen_pre(&mut channel, None, &mut comm);

        // Original COT generation
        let size = DEPTH + 1; // Number of COTs
        let times = 2;
        // New COT generation using OTPre
        let mut sender_pre_ot = OTPre::<3>::new(size, times);
        sender_cot.cot_gen_preot(
            &mut channel,
            &mut sender_pre_ot,
            size * times,
            None,
            &mut comm,
        );

        // Now generate the IDCF
        let beta = [5u8; 16];
        let mut key = [0u8; 16];
        let mut rng_seed = rand::thread_rng();
        rng_seed.fill(&mut key);
        let mut idcf_sender = IDCFSender::new(DEPTH, 1);

        idcf_sender.compute(&mut idcf_sharing, key, beta, 0);
        idcf_sender.send(&mut channel, &mut sender_pre_ot, &mut comm);

        idcf_sender.consistency_check(&mut channel, &idcf_sharing, 0);
    }
}
