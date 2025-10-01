use psi_aes::prg::PRG;
use psi_network::comm_channel::CommunicationChannel;
use psi_utils::gf128::{gf128mul, vector_inner_product_f2k};

use crate::cope_f2k::CopeF2k;

pub struct BaseSvoleF2k {
    party: u8,           // 0 for sender, 1 for receiver
    cope: CopeF2k,       // COPE instance
    delta: Option<u128>, // Delta for the sender
}

impl BaseSvoleF2k {
    /// Sender's constructor
    pub fn new_sender<IO: CommunicationChannel>(io: &mut IO, delta: u128, comm: &mut u64) -> Self {
        let mut cope = CopeF2k::new(0);
        cope.initialize_sender(io, delta.clone(), comm);
        Self {
            party: 0,
            cope,
            delta: Some(delta),
        }
    }

    /// Receiver's constructor
    pub fn new_receiver<IO: CommunicationChannel>(io: &mut IO, comm: &mut u64) -> Self {
        let mut cope = CopeF2k::new(1);
        cope.initialize_receiver(io, comm);
        Self {
            party: 1,
            cope,
            delta: None,
        }
    }

    pub fn triple_gen_send<IO: CommunicationChannel>(
        &mut self,
        io: &mut IO,
        share: &mut [u128],
        size: usize,
        comm: &mut u64,
    ) {
        // Generate share_recv = share_send + delta * u_recv
        self.cope.extend_sender_batch(io, share, size, comm);
        let mut b = vec![0u128; 1];
        self.cope.extend_sender_batch(io, &mut b, 1, comm);
        self.sender_check(io, share, b[0], size, comm);
    }

    pub fn triple_gen_recv<IO: CommunicationChannel>(
        &mut self,
        io: &mut IO,
        share: &mut [u128],
        u: &mut [u128],
        size: usize,
        comm: &mut u64,
    ) {
        // Generate share_recv = share_send + delta * u_recv
        let mut prg = PRG::new(None, 0);
        let mut x_bytes = vec![[0u8; 16]; 1];
        let mut u_bytes = vec![[0u8; 16]; u.len()];
        prg.random_16byte_block(&mut x_bytes);
        prg.random_16byte_block(&mut u_bytes);

        let x = x_bytes
            .iter()
            .map(|x| u128::from_le_bytes(*x))
            .collect::<Vec<u128>>();
        u.copy_from_slice(
            &u_bytes
                .iter()
                .map(|x| u128::from_le_bytes(*x))
                .collect::<Vec<u128>>(),
        );

        self.cope.extend_receiver_batch(io, share, u, size, comm);

        let mut c = vec![0u128; 1];
        self.cope.extend_receiver_batch(io, &mut c, &x, 1, comm);

        self.receiver_check(io, share, u, c[0], x[0], size, comm);
    }

    /// Sender: Consistency check
    fn sender_check<IO: CommunicationChannel>(
        &mut self,
        io: &mut IO,
        share: &[u128],
        b: u128,
        size: usize,
        comm: &mut u64,
    ) {
        // Generate check seed and send it to Receiver
        let mut seed = vec![[0u8; 16]; 1];
        let mut seed_prg = PRG::new(None, 0);
        seed_prg.random_16byte_block(&mut seed);
        *comm += io
            .send_block::<16>(&seed)
            .expect("Send seed for svole check failed");

        let chi = self.generate_hash_coeff(seed[0], size);

        let y = vector_inner_product_f2k(share, &chi) ^ b;
        let xz_bytes = io.receive_block::<16>().expect("Failed to receive xz");
        let mut xz = xz_bytes
            .iter()
            .map(|x| u128::from_le_bytes(*x))
            .collect::<Vec<u128>>();

        xz[1] = gf128mul(xz[1], self.delta.unwrap());
        let y_check = y ^ xz[1];
        if y_check != xz[0] {
            panic!("Base sVOLE check failed!");
        } else {
            // println!("Base sVOLE generated successfully!");
        }
    }

    fn receiver_check<IO: CommunicationChannel>(
        &mut self,
        io: &mut IO,
        share: &[u128],
        x: &[u128],
        c: u128,
        a: u128,
        size: usize,
        comm: &mut u64,
    ) {
        let seed = io
            .receive_block::<16>()
            .expect("Cannot receive seed for check base sVOLE");
        let chi = self.generate_hash_coeff(seed[0], size);

        let xz_0 = vector_inner_product_f2k(share, &chi) ^ c;
        let xz_1 = vector_inner_product_f2k(x, &chi) ^ a;

        *comm += io
            .send_block::<16>(&[xz_0.to_le_bytes(), xz_1.to_le_bytes()])
            .expect("Failed to send xz");
    }

    /// Generate hash coefficients based on a seed
    fn generate_hash_coeff(&self, seed: [u8; 16], size: usize) -> Vec<u128> {
        let mut coeffs_bytes = vec![[0u8; 16]; size];
        let mut prg = PRG::new(Some(&seed), 0);
        prg.random_16byte_block(&mut coeffs_bytes);
        let coeffs = coeffs_bytes
            .iter()
            .map(|x| u128::from_le_bytes(*x))
            .collect::<Vec<u128>>();
        coeffs
    }
}
