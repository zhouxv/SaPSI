use crate::comm_channel::CommunicationChannel;
use crate::fri::*;
use crate::utils::{get_roots_of_unity, parallel_fft, parallel_ifft};
use crate::vole_triple::{PrimalLPNParameterFp61, VoleTriple};
use lambdaworks_crypto::fiat_shamir::is_transcript::IsTranscript;
use lambdaworks_crypto::merkle_tree::proof::Proof;
use lambdaworks_math::fft::cpu::bit_reversing::{in_place_bit_reverse_permute, reverse_index};
use lambdaworks_math::fft::cpu::roots_of_unity::get_powers_of_primitive_root_coset;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::traits::{AsBytes, ByteConversion};
use psi_aes::prg::PRG;
use psi_aes::prp::FieldPRP;
use psi_okvs::okvs::RbOkvs;
use psi_okvs::types::{Okvs, Pair};
use rand::Rng;
use rayon::prelude::*;
use sha3::{Digest, Keccak256};
use stark_platinum_prover::config::{BatchedMerkleTreeBackend, Commitment};
use stark_platinum_prover::fri::{FieldElement, Polynomial};
use stark_platinum_prover::transcript::StoneProverTranscript;
use std::collections::HashMap;
use std::convert::TryInto;
use std::time::Instant;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

const NUM_QUERIES: usize = 128;

pub struct OprfReceiver {
    n: usize,
    vole_receiver: VoleTriple,
    committed: bool,
    okvs: RbOkvs,
    P: Vec<FE>,
    Q_poly: Polynomial<FE>,
    Q_last_value: FE,
    Q_fri_layers: Vec<FriLayer>,
    P_new_poly: Polynomial<FE>,
    P_new_commit: FriLayer,
    X_new_merkle_root: [u8; 32],
    S_new_merkle_root: [u8; 32],
    fixed_points_num: usize,
    log_fixed_points_num: usize,
    roots_of_unity: Vec<FE>,
    roots_of_unity_inv: Vec<FE>,
    small_roots_of_unity_inv: Vec<FE>,
    transcript: StoneProverTranscript,
}

impl OprfReceiver {
    pub fn new<IO: CommunicationChannel>(
        io: &mut IO,
        n: usize,
        committed: bool,
        param: PrimalLPNParameterFp61,
        comm: &mut u64,
    ) -> Self {
        // Setup OKVS seed
        let mut prg = PRG::new(None, 0);
        let mut r = [[0u8; 16]; 2];
        prg.random_16byte_block(&mut r);
        let r1 = r[0];
        let r2 = r[1];
        let okvs = RbOkvs::new(n, &r1, &r2);
        io.send_block::<16>(&r);

        let fixed_points_num = 2 * n;
        let mut log_fixed_points_num = 1;
        while (1 << log_fixed_points_num) < fixed_points_num {
            log_fixed_points_num += 1;
        }
        assert_eq!(
            fixed_points_num,
            1 << log_fixed_points_num,
            "Number of values should be a power of 2"
        );

        let mut vole_triple = VoleTriple::new(1, true, io, param, comm);
        vole_triple.setup_receiver(io, comm);
        vole_triple.extend_initialization();

        let public_input_data = vec![]; // hopefully it's safe
        let transcript = StoneProverTranscript::new(&public_input_data);

        OprfReceiver {
            n: n,
            vole_receiver: vole_triple,
            committed: committed,
            okvs: okvs,
            P: vec![FE::zero(); 1],
            Q_poly: Polynomial::new(vec![FE::zero(); 1].as_slice()),
            Q_last_value: FE::zero(),
            Q_fri_layers: vec![],
            P_new_poly: Polynomial::new(vec![FE::zero(); 1].as_slice()),
            P_new_commit: FriLayer::new(
                vec![FE::zero(); 1].as_slice(),
                MerkleTree::build(vec![[FE::zero(); 2]; 1].as_slice()),
            ),
            X_new_merkle_root: [0u8; 32],
            S_new_merkle_root: [0u8; 32],
            fixed_points_num: 2 * n,
            log_fixed_points_num: log_fixed_points_num,
            roots_of_unity: vec![],
            roots_of_unity_inv: vec![],
            small_roots_of_unity_inv: vec![],
            transcript: transcript,
        }
    }

    pub fn commit_P(&mut self, values: &[FE]) {
        if self.committed {
            self.roots_of_unity = get_roots_of_unity((self.log_fixed_points_num + 2) as u64);
            self.roots_of_unity_inv = self.roots_of_unity.clone();
            self.roots_of_unity_inv[1..].reverse();
            self.small_roots_of_unity_inv = (0..self.fixed_points_num)
                .into_par_iter()
                .map(|i| self.roots_of_unity_inv[i * 4])
                .collect();
        }

        assert_eq!(
            values.len(),
            self.n,
            "Number of values received does not match the expected number of values"
        );

        // First hash all inputs
        // Takes 15ms for 1<<16 inputs
        let input_seed = [1u8; 32];
        let input_hasher = FieldPRP::new(Some(&input_seed));
        let mut hashes = vec![FE::zero(); self.n];
        hashes.copy_from_slice(values);
        input_hasher.permute_block(&mut hashes, self.n);

        // Encode input using OKVS
        // Takes 680ms for 1<<16 inputs
        let input_kv = values
            .iter()
            .zip(hashes.iter())
            .map(|(input, hash)| (*input, *hash))
            .collect::<Vec<Pair<FE, FE>>>();
        self.P = self
            .okvs
            .encode(&input_kv)
            .expect("Failed to encode using OKVS");

        if self.committed {
            // Interpolate P
            let P_poly_coeffs = parallel_ifft(
                &self.P,
                &self.small_roots_of_unity_inv,
                self.log_fixed_points_num,
                0,
            );
            let P_poly = Polynomial::new(&P_poly_coeffs);

            // Blind P
            (self.Q_poly, self.P_new_poly) = get_blind_poly(&P_poly, self.log_fixed_points_num, 1);

            // Commit P_new
            self.P_new_commit = new_fri_layer(
                &self.P_new_poly,
                1,
                self.log_fixed_points_num,
                self.log_fixed_points_num + 1,
                &self.roots_of_unity,
            );
        }
    }

    pub fn send_P_commit<IO: CommunicationChannel>(&mut self, io: &mut IO, comm: &mut u64) {
        if self.committed {
            self.transcript
                .append_bytes(&self.P_new_commit.merkle_tree.root);
            *comm += io
                .send_block::<32>(&[self.P_new_commit.merkle_tree.root])
                .expect("Failed to send merkle root of P_new");
        }
    }

    pub fn receive_X_commit<IO: CommunicationChannel>(&mut self, io: &mut IO, comm: &mut u64) {
        if self.committed {
            self.X_new_merkle_root = io
                .receive_block::<32>()
                .expect("Failed to receive merkle root of X_new")[0];
            self.transcript.append_bytes(&self.X_new_merkle_root);
        }
    }

    pub fn receive<IO: CommunicationChannel>(
        &mut self,
        io: &mut IO,
        values: &[FE],
        comm: &mut u64,
    ) {
        // Receive committed ws from Sender
        let mut hws = FE::zero();
        hws = io
            .receive_stark252()
            .expect("Failed to receive H(ws) from the sender")[0];

        // Running Vole
        // c = b + a * delta
        let start = Instant::now();
        let mut a = vec![FE::zero(); self.fixed_points_num];
        let mut c = vec![FE::zero(); self.fixed_points_num];
        self.vole_receiver
            .extend(io, &mut c, &mut a, self.fixed_points_num, comm);

        // println!("Doing VOLE took {:?}", start.elapsed());

        // Generate random coin if malicious
        let mut wr = FE::zero();
        let mut ws = FE::zero();
        let mut w = FE::zero();
        let mut prg = PRG::new(None, 0);
        let mut wr_vec = [FE::zero(); 1];

        prg.random_stark252_elements(&mut wr_vec);
        wr = wr_vec[0];
        *comm += io
            .send_stark252(&[wr])
            .expect("Failed to send wr to the sender");
        ws = io
            .receive_stark252()
            .expect("Failed to receive ws from the sender")[0];
        let hash_seed = [0u8; 32];
        let hash = FieldPRP::new(Some(&hash_seed));
        let mut ws_vec = [ws];
        hash.permute_block(&mut ws_vec, 1);
        let hws2 = ws_vec[0];
        assert_eq!(hws, hws2, "H(ws) does not match");
        w = ws + wr;

        if self.committed {
            self.transcript.append_bytes(&hws.to_bytes_le());
            self.transcript.append_bytes(&wr.to_bytes_le());
            self.transcript.append_bytes(&w.to_bytes_le());
        }

        // Compute A = P + a
        let mut A = vec![FE::zero(); self.fixed_points_num];
        for i in 0..self.fixed_points_num {
            A[i] = self.P[i] + a[i];
        }

        let start = Instant::now();
        // Send A = P + a to the sender
        *comm += io
            .send_stark252(&A)
            .expect("Failed to send A to the sender");
        // println!("Sending A took {:?}", start.elapsed());

        self.prepare_vole_consistency();

        let mut o = self.okvs.decode(&c, &values);

        for i in 0..o.len() {
            o[i] = o[i] + w;
        }

        let mut receiver_outputs = vec![[0u8; 32]; self.n];
        for i in 0..self.n {
            let mut hasher = Keccak256::new();
            hasher.update(values[i].as_bytes());
            hasher.update(o[i].as_bytes());
            receiver_outputs[i].copy_from_slice(&hasher.finalize());
        }

        self.receive_output_consistency(io, comm);
        self.send_vole_consistency(io, &c, comm);

        let sender_outputs = self.receive_output(io, comm);

        // Do intersection
        let mut sender_outputs_map = HashMap::<[u8; 32], bool>::new();
        for i in 0..self.n {
            sender_outputs_map.insert(sender_outputs[i], true);
        }

        let outputs: Vec<bool> = receiver_outputs
            .par_iter()
            .map(|x| {
                let mut is_in = false;
                if sender_outputs_map.contains_key(x) {
                    is_in = true;
                }
                is_in
            })
            .collect();

        let mut outs = Vec::new();
        for i in (0..values.len()) {
            if outputs[i] {
                outs.push(values);
            }
        }

        println!("Done intersection!");
        println!(
            "{} out of {} elements are in the intersection!",
            outs.len(),
            values.len()
        );
    }

    pub fn prepare_vole_consistency(&mut self) {
        if self.committed {
            (self.Q_last_value, self.Q_fri_layers) = commit_poly(
                &self.Q_poly,
                self.log_fixed_points_num,
                2,
                self.log_fixed_points_num,
                &self.roots_of_unity,
                &self.roots_of_unity_inv,
            );
        }
    }

    // Returns the sender hashes of PSI
    pub fn receive_output_consistency<IO: CommunicationChannel>(
        &mut self,
        io: &mut IO,
        comm: &mut u64,
    ) {
        if self.committed {
            self.S_new_merkle_root = io
                .receive_block::<32>()
                .expect("Failed to receive merkle root of S_new")[0];
            self.transcript.append_bytes(&self.S_new_merkle_root);

            let t = self.transcript.sample_field_element();

            // Receive FRI degree test of T_new
            let T_new_last_value = io
                .receive_stark252()
                .expect("Failed to receive last value of T_new")[0];
            let T_new_merkle_roots = io
                .receive_block::<32>()
                .expect("Failed to receive merkle root of T_new");
            self.transcript
                .append_bytes(&T_new_last_value.to_bytes_le());
            self.transcript.append_bytes(&T_new_merkle_roots[0]);

            // Generate iotas for the degree test
            let iotas: Vec<usize> = (0..NUM_QUERIES)
                .map(|_| {
                    let iota_bytes = self.transcript.sample(8);
                    let iota = u64::from_le_bytes(iota_bytes.clone().try_into().unwrap())
                        % ((self.fixed_points_num * 2) as u64)
                        + (self.fixed_points_num * 2) as u64;
                    self.transcript.append_bytes(&iota_bytes);
                    iota as usize
                })
                .collect();

            let T_new_evaluations = io
                .receive_stark252()
                .expect("Cannot receive evaluations of T_new");
            // Receive back the decommitments of T_new
            let T_new_decommit = receive_decommit(io, comm);
            // Verify decommitment
            iotas.par_iter().enumerate().for_each(|(i, &iota)| {
                let result = verify_fri_query(
                    T_new_last_value,
                    &T_new_merkle_roots,
                    &T_new_decommit[i],
                    iota,
                    T_new_evaluations[i],
                    T_new_decommit[i].layers_evaluations_sym[0],
                    &self.roots_of_unity,
                );
                if result == false {
                    panic!("Receiver lied about T_new");
                }
            });
            println!("T_new passed the degree test!");

            // Now test consistency between X_new and S_new
            let iotas: Vec<usize> = (0..NUM_QUERIES)
                .map(|_| {
                    let iota_bytes = self.transcript.sample(8);
                    let iota = u64::from_le_bytes(iota_bytes.clone().try_into().unwrap())
                        % ((self.fixed_points_num * 2) as u64)
                        + (self.fixed_points_num * 2) as u64;
                    self.transcript.append_bytes(&iota_bytes);
                    iota as usize
                })
                .collect();

            // Receive evaluations on roots of unity of S_new and check with commitment
            let S_new_evaluations = io
                .receive_stark252()
                .expect("Cannot receive evaluations of S_new");
            let S_new_evaluations_sym = io
                .receive_stark252()
                .expect("Cannot receive evaluations sym of S_new");
            let S_new_paths = receive_merkle_path(io, comm);
            // Verify S_new_evaluations
            iotas
                .par_iter()
                .enumerate()
                .zip(S_new_evaluations.par_iter())
                .zip(S_new_evaluations_sym.par_iter())
                .zip(S_new_paths.par_iter())
                .for_each(|((((i, &iota), evaluation), evaluation_sym), path)| {
                    let openings_ok = verify_fri_layer_openings(
                        &self.S_new_merkle_root,
                        path,
                        evaluation,
                        evaluation_sym,
                        iota,
                    );
                    if !openings_ok {
                        panic!("Lied about S_new at iota = {}", iota);
                    }
                });

            // Receive evaluations on roots of unity of X_new and check with commitment
            let X_new_evaluations = io
                .receive_stark252()
                .expect("Cannot receive evaluations of X_new");
            let X_new_evaluations_sym = io
                .receive_stark252()
                .expect("Cannot receive evaluations sym of X_new");
            let X_new_paths = receive_merkle_path(io, comm);
            // Verify X_new_evaluations
            let verify_X_openings: bool = iotas
                .iter()
                .enumerate()
                .zip(X_new_evaluations.iter())
                .zip(X_new_evaluations_sym.iter())
                .zip(X_new_paths.iter())
                .fold(
                    true,
                    |result, ((((i, &iota), evaluation), evaluation_sym), path)| {
                        let openings_ok = verify_fri_layer_openings(
                            &self.X_new_merkle_root,
                            path,
                            evaluation,
                            evaluation_sym,
                            iota,
                        );
                        if !openings_ok {
                            panic!("Lied about X_new at iota = {}", iota);
                        }
                        result & openings_ok
                    },
                );

            // Receive evaluations on roots of unity of T_new and check with commitment
            let T_new_evaluations = io
                .receive_stark252()
                .expect("Cannot receive evaluations of T_new");
            let T_new_evaluations_sym = io
                .receive_stark252()
                .expect("Cannot receive evaluations sym of T_new");
            let T_new_paths = receive_merkle_path(io, comm);
            // Verify T_new_evaluations
            let verify_T_openings: bool = iotas
                .iter()
                .enumerate()
                .zip(T_new_evaluations.iter())
                .zip(T_new_evaluations_sym.iter())
                .zip(T_new_paths.iter())
                .fold(
                    true,
                    |result, ((((i, &iota), evaluation), evaluation_sym), path)| {
                        let openings_ok = verify_fri_layer_openings(
                            &T_new_merkle_roots[0],
                            path,
                            evaluation,
                            evaluation_sym,
                            iota,
                        );
                        if !openings_ok {
                            panic!("Lied about T_new at iota = {}", iota);
                        }
                        result & openings_ok
                    },
                );

            let evaluation_points: Vec<FE> = iotas
                .iter()
                .map(|&iota| {
                    self.roots_of_unity[reverse_index(iota, self.roots_of_unity.len() as u64)]
                })
                .collect();

            // Now check for the following equation
            // (S_new(x) - X_new(x)) * (x^n + t) = (x^n - 1) * T_new(x)
            for i in 0..NUM_QUERIES {
                if (S_new_evaluations[i] - X_new_evaluations[i])
                    * (evaluation_points[i].pow(self.n) + t)
                    != T_new_evaluations[i] * (evaluation_points[i].pow(self.n) - FE::one())
                {
                    panic!("Equation does not hold at iota = {}", iotas[i]);
                }
            }
            println!("The hash outputs passed the consistency check!");
        }
    }

    pub fn send_vole_consistency<IO: CommunicationChannel>(
        &mut self,
        io: &mut IO,
        c: &[FE],
        comm: &mut u64,
    ) {
        if self.committed {
            *comm += io
                .send_stark252(&[self.Q_last_value])
                .expect("Cannot send last value of Q");
            let Q_merkle_roots: Vec<[u8; 32]> = self
                .Q_fri_layers
                .iter()
                .map(|fri_layer| fri_layer.merkle_tree.root)
                .collect();
            *comm += io
                .send_block::<32>(&Q_merkle_roots)
                .expect("Failed to send merkle root of Q");
            self.transcript
                .append_bytes(&self.Q_last_value.to_bytes_le());
            self.transcript.append_bytes(&Q_merkle_roots[0]);

            // Receives iotas from Sender
            let iotas: Vec<usize> = (0..NUM_QUERIES)
                .map(|_| {
                    let iota_bytes = self.transcript.sample(8);
                    let iota = u64::from_le_bytes(iota_bytes.clone().try_into().unwrap())
                        % ((self.fixed_points_num * 2) as u64)
                        + (self.fixed_points_num * 2) as u64;
                    self.transcript.append_bytes(&iota_bytes);
                    iota as usize
                })
                .collect();

            // Open commitments on P_blind
            let Q_evaluations: Vec<FE> = iotas
                .iter()
                .map(|&iota| self.Q_fri_layers[0].evaluation[iota])
                .collect();
            *comm += io
                .send_stark252(&Q_evaluations)
                .expect("Cannot send evaluations of Q");

            let Q_decommit = query_phase(&self.Q_fri_layers, &iotas);
            send_decommit(io, &Q_decommit, comm);

            // Now we want to prove that A(x) = P(x) + a(x)
            // Where a(x) * delta = c(x) - b(x)
            // The commitment we currently have is P_new(x), which is P(x) + P_blind(x) * (x^n-1)
            // Which is equivalent to (c(x) - b(x)) * delta_inv - (A(x) - P_new(x)) = P_blind(x) * (x^n -1)
            // First, low degree test for P_blind(x). P_blind should have the same degree as P
            let iotas_consistency: Vec<usize> = (0..NUM_QUERIES)
                .map(|_| {
                    let iota_bytes = self.transcript.sample(8);
                    let iota = u64::from_le_bytes(iota_bytes.clone().try_into().unwrap())
                        % ((self.fixed_points_num * 2) as u64)
                        + (self.fixed_points_num * 2) as u64;
                    self.transcript.append_bytes(&iota_bytes);
                    iota as usize
                })
                .collect();
            let iota_consistency_roots_of_unity: Vec<FE> = iotas_consistency
                .iter()
                .map(|&iota| {
                    self.roots_of_unity[reverse_index(iota, self.roots_of_unity.len() as u64)]
                })
                .collect();

            // Compute evaluations on c to test Wolverine
            let c_poly_coeffs = parallel_ifft(
                &c,
                &self.small_roots_of_unity_inv,
                self.log_fixed_points_num,
                0,
            );
            let c_poly = Polynomial::new(&c_poly_coeffs);
            let mut c_evaluations = vec![FE::zero(); NUM_QUERIES];
            c_evaluations
                .par_iter_mut()
                .enumerate()
                .for_each(|(i, ci)| {
                    *ci = c_poly.evaluate(&iota_consistency_roots_of_unity[i]);
                });

            // Send evaluations and merkle paths for P_new
            let P_new_evaluations: Vec<FE> = iotas_consistency
                .iter()
                .map(|&iota| self.P_new_commit.evaluation[iota])
                .collect();
            // Adjacent leaves
            let P_new_evaluations_sym: Vec<FE> = iotas_consistency
                .iter()
                .map(|&iota| self.P_new_commit.evaluation[iota ^ 1])
                .collect();
            // Paths on Merkle Tree
            let P_new_paths: Vec<Proof<Commitment>> = iotas_consistency
                .iter()
                .map(|&iota| self.P_new_commit.merkle_tree.get_proof_by_pos(iota >> 1))
                .collect();

            // Send evaluations and merkle paths for Q
            let Q_evaluations: Vec<FE> = iotas_consistency
                .iter()
                .map(|&iota| self.Q_fri_layers[0].evaluation[iota])
                .collect();
            let Q_evaluations_sym: Vec<FE> = iotas_consistency
                .iter()
                .map(|&iota| self.Q_fri_layers[0].evaluation[iota ^ 1])
                .collect();
            let Q_paths: Vec<Proof<Commitment>> = iotas_consistency
                .iter()
                .map(|&iota| self.Q_fri_layers[0].merkle_tree.get_proof_by_pos(iota >> 1))
                .collect();

            // Send everything at once
            *comm += io
                .send_stark252(&c_evaluations)
                .expect("Cannot send evaluations of c");
            *comm += io
                .send_stark252(&P_new_evaluations)
                .expect("Cannot send evaluations of P_new");
            *comm += io
                .send_stark252(&P_new_evaluations_sym)
                .expect("Cannot send sym evaluations of P_new");
            send_merkle_path(io, &P_new_paths, comm);
            *comm += io
                .send_stark252(&Q_evaluations)
                .expect("Cannot send evaluations of Q");
            *comm += io
                .send_stark252(&Q_evaluations_sym)
                .expect("Cannot send sym evaluations of Q");
            send_merkle_path(io, &Q_paths, comm);
        }
    }

    pub fn receive_output<IO: CommunicationChannel>(
        &self,
        io: &mut IO,
        comm: &mut u64,
    ) -> Vec<[u8; 32]> {
        // Receive the hashes
        let sender_outputs_byte = io
            .receive_block::<32>()
            .expect("Failed to receive sender output bytes");

        if self.committed {
            let verify_path = io
                .receive_block::<32>()
                .expect("Failed to receive verify path for sender output bytes");
            let mut sender_outputs_hash = vec![[0u8; 32]; self.n];
            sender_outputs_hash.copy_from_slice(&sender_outputs_byte);
            let mut current_size = self.n;
            for _ in 0..self.log_fixed_points_num - 1 {
                current_size >>= 1;

                let mut new_sender_outputs_hash = vec![[0u8; 32]; current_size];
                new_sender_outputs_hash
                    .par_iter_mut()
                    .enumerate()
                    .for_each(|(j, hash)| {
                        let mut hasher = Keccak256::new();
                        hasher.update(sender_outputs_hash[2 * j]);
                        hasher.update(sender_outputs_hash[2 * j + 1]);
                        hash.copy_from_slice(&hasher.finalize());
                    });
                sender_outputs_hash[..current_size].copy_from_slice(&new_sender_outputs_hash);
            }

            let mut ref_root = sender_outputs_hash[0];
            for i in 0..verify_path.len() {
                let mut hasher = Keccak256::new();
                hasher.update(ref_root);
                hasher.update(verify_path[i]);
                ref_root.copy_from_slice(&hasher.finalize());
            }

            assert_eq!(
                ref_root, self.S_new_merkle_root,
                "The hash outputs do not match the merkle root of S_new"
            );
            println!("The hash outputs are consistent with the merkle root of S_new");
        }

        sender_outputs_byte
    }
}
