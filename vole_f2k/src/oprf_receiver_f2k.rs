use crate::vole_triple_f2k::{PrimalLPNParameterF2k, VoleTripleF2k};
use blake3;
use psi_aes::prg::PRG;
use psi_network::comm_channel::CommunicationChannel;
use psi_okvs::okvs_f2k::RbOkvsF2k;
use psi_okvs::types::Pair;
use std::collections::HashMap;
use std::time::Instant;

pub struct OprfReceiverF2k<const KEY_DIM: usize> {
    n: usize,
    vole_receiver: VoleTripleF2k,
    okvs: RbOkvsF2k<KEY_DIM>,
    P: Vec<u128>,
    outputs: HashMap<[u128; KEY_DIM], [u8; 32]>,
}

impl<const KEY_DIM: usize> OprfReceiverF2k<KEY_DIM> {
    pub fn new<IO: CommunicationChannel>(
        io: &mut IO,
        n: usize,
        param: PrimalLPNParameterF2k,
        comm: &mut u64,
    ) -> Self {
        // Setup OKVS seed
        let mut prg = PRG::new(None, 0);
        let mut r = [[0u8; 16]; 2];
        prg.random_16byte_block(&mut r);
        let r1 = r[0];
        let r2 = r[1];
        let okvs = RbOkvsF2k::<KEY_DIM>::new(n, &r1, &r2);
        io.send_block::<16>(&r);

        let mut vole_triple = VoleTripleF2k::new(1, true, io, param, comm);
        vole_triple.setup_receiver(io, comm);
        vole_triple.extend_initialization();

        OprfReceiverF2k {
            n,
            vole_receiver: vole_triple,
            okvs,
            P: vec![0; 2 * n],
            outputs: HashMap::new(),
        }
    }

    pub fn receive<IO: CommunicationChannel>(
        &mut self,
        io: &mut IO,
        values: &[[u128; KEY_DIM]],
        comm: &mut u64,
    ) {
        let hashes = values
            .iter()
            .map(|x| {
                let mut hash = blake3::Hasher::new();
                x.iter().for_each(|&x| {
                    hash.update(&x.to_le_bytes());
                });
                let mut h = [0u8; 16];
                h.copy_from_slice(&hash.finalize().as_bytes()[0..16]);
                u128::from_le_bytes(h)
            })
            .collect::<Vec<u128>>();

        let input_kv = values
            .iter()
            .zip(hashes.iter())
            .map(|(x, h)| (*x, *h))
            .collect::<Vec<Pair<[u128; KEY_DIM], u128>>>();

        let start = Instant::now();
        self.P = self
            .okvs
            .encode(&input_kv)
            .expect("Failed to encode using OKVS");
        // println!("Encoding took {:?}", start.elapsed());

        let hws = io
            .receive_block::<32>()
            .expect("Failed to receive H(ws) from the sender")[0];

        // Running Vole
        // c = b + a * delta
        // println!("Number of vole: {}", self.okvs.columns);
        let start = Instant::now();
        let mut a = vec![0u128; self.okvs.columns];
        let mut c = vec![0u128; self.okvs.columns];
        self.vole_receiver
            .extend(io, &mut c, &mut a, self.okvs.columns, comm);

        // println!("Doing VOLE took {:?}", start.elapsed());

        // Generate random coin if malicious
        let mut wr = 0u128;
        let mut ws = 0u128;
        let mut w = 0u128;
        let mut prg = PRG::new(None, 0);
        let mut wr_bytes = [[0u8; 16]; 1];
        prg.random_16byte_block(&mut wr_bytes);
        wr = u128::from_le_bytes(wr_bytes[0]);
        *comm += io
            .send_block::<16>(&wr_bytes)
            .expect("Failed to send wr to the sender");

        let ws_bytes = io
            .receive_block::<16>()
            .expect("Failed to receive ws from the sender");
        let ws = u128::from_le_bytes(ws_bytes[0]);
        let hash = blake3::hash(&ws.to_le_bytes());
        let mut h = [0u8; 32];
        h.copy_from_slice(hash.as_bytes());
        assert_eq!(h, hws, "Hash mismatch");

        w = ws ^ wr;

        let A = self
            .P
            .iter()
            .zip(a.iter())
            .map(|(x, a)| (*x) ^ (*a))
            .collect::<Vec<u128>>();
        let start = Instant::now();
        // Send A = P + a to the sender
        let A_bytes = A.iter().map(|x| x.to_le_bytes()).collect::<Vec<[u8; 16]>>();
        *comm += io
            .send_block::<16>(&A_bytes)
            .expect("Failed to send A to the sender");
        // println!("Sending A took {:?}", start.elapsed());
        // println!("Size of A: {}", A.len());

        let mut o = self.okvs.decode(&c, &values);
        o.iter_mut().enumerate().for_each(|(i, oi)| {
            *oi = *oi ^ w;
        });

        let receiver_outputs = values
            .iter()
            .zip(o.iter())
            .map(|(x, o)| {
                let mut to_be_hashed = Vec::<u8>::new();
                x.iter().for_each(|&x| {
                    to_be_hashed.extend_from_slice(&x.to_le_bytes());
                });
                to_be_hashed.extend_from_slice(&o.to_le_bytes());
                let hash = blake3::hash(&to_be_hashed);
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(hash.as_bytes());
                hash_bytes
            })
            .collect::<Vec<_>>();

        values
            .iter()
            .zip(receiver_outputs.iter())
            .for_each(|(x, o)| {
                self.outputs.insert(*x, *o);
            });
    }

    pub fn get_output(&self, x: &[u128; KEY_DIM]) -> Option<[u8; 32]> {
        self.outputs.get(x).copied()
    }
}
