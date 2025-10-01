use crate::config::*;
use crate::cuckoo::SimpleHash;
use crate::idcf_sender::IDCFSender;
use blake3;
use psi_network::comm_channel::CommunicationChannel;
use psi_ot::base_cot::BaseCot;
use psi_ot::pre_ot::OTPre;
use psi_volef2k::oprf_receiver_f2k::OprfReceiverF2k;
use psi_volef2k::vole_triple_f2k::PrimalLPNParameterF2k;
use rand::prelude::*;
use std::cmp::max;
use std::collections::HashSet;
use std::convert::TryInto;
use std::time::Instant;

pub struct SAPSIReceiver {
    n: usize,
    table_size: usize,
}

impl SAPSIReceiver {
    pub fn new(n: usize, table_size: usize) -> Self {
        SAPSIReceiver { n, table_size }
    }

    pub fn receive<IO: CommunicationChannel>(
        &self,
        io: &mut IO,
        values: &[[u128; DIMENSION]],
        param: PrimalLPNParameterF2k,
        comm: &mut u64,
    ) {
        let mut processed_points: Vec<([u128; DIMENSION], [u128; DIMENSION])> = Vec::new();
        values.iter().for_each(|point| {
            let processed_point = preprocess_point(point);
            // processed_point.iter().for_each(|(origin, transformed_point)| {
            //     println!("Origin: {:?}, Transformed Point: {:?}", origin, transformed_point);
            // });
            processed_points.extend_from_slice(processed_point.as_slice());
        });

        // println!("Origin length: {}", processed_points.len());

        // Run OPRF for the origins
        let origins = processed_points
            .iter()
            .map(|(origin, _)| *origin)
            .collect::<Vec<[u128; DIMENSION]>>();

        let start = Instant::now();
        let mut oprf_receiver = OprfReceiverF2k::<DIMENSION>::new(io, N << DIMENSION, param, comm);
        // println!("Receiver setup OPRF in {:?}", start.elapsed());
        oprf_receiver.receive(io, &origins, comm);
        // println!("Receiver computed OPRF in {:?}", start.elapsed());

        let mut simple_table =
            SimpleHash::<DIMENSION>::new(self.table_size, 100000, LOC_FUNC_COUNT);
        simple_table.generate_loc_funcs(LOC_FUNC_COUNT, Some([0u8; 16]));
        processed_points
            .iter()
            .for_each(|(origin, transformed_point)| {
                let res: bool = simple_table.insert(origin, transformed_point);
                assert!(res, "Insertion failed");
            });

        let mut idcf_table = Vec::<Vec<Vec<[u8; 16]>>>::new();

        // Prepare OTs
        let depth: usize = RANGE_BITS;
        let mut sender_cot = BaseCot::new(0, false); // Receiver has role Sender in the OTs

        // Set up the receiver's precomputation phase
        sender_cot.cot_gen_pre(io, None, comm);

        // Original COT generation
        let size = depth + 1; // Number of COTs
        let times = self.table_size * DIMENSION * 2;
        // New COT generation using OTPre
        let mut sender_pre_ot = OTPre::<3>::new(size * times, 1);
        sender_cot.cot_gen_preot(io, &mut sender_pre_ot, size * times, None, comm);

        // Sample random beta
        let mut beta = vec![[0u8; 16]; times];
        let mut key = vec![[0u8; 16]; times];
        let mut rng_seed = rand::thread_rng();
        for i in 0..times {
            rng_seed.fill(&mut beta[i]);
            rng_seed.fill(&mut key[i]);
        }

        // Generate IDCF
        let start = Instant::now();

        let mut idcf_table = Vec::<Vec<Vec<[u8; 16]>>>::new();
        let mut idcf_sender = IDCFSender::new(depth, times);
        for index in 0..self.table_size {
            idcf_table.push(Vec::new());
            for dim in 0..DIMENSION {
                let mut idcf_sharing = vec![[0u8; 16]; 1 << (RANGE_BITS + 1)];
                let idcf_time = 2 * (index * DIMENSION + dim);
                idcf_sender.compute(
                    &mut idcf_sharing,
                    key[idcf_time],
                    beta[idcf_time],
                    idcf_time,
                );
                idcf_table[index].push(idcf_sharing);

                idcf_sharing = vec![[0u8; 16]; 1 << (RANGE_BITS + 1)];
                let idcf_time = 2 * (index * DIMENSION + dim) + 1;
                idcf_sender.compute(
                    &mut idcf_sharing,
                    key[idcf_time],
                    beta[idcf_time],
                    idcf_time,
                );
                idcf_table[index].push(idcf_sharing);
            }
        }

        // println!("Receiver computed IDCF in {:?}", start.elapsed());

        let start = Instant::now();
        idcf_sender.send(io, &mut sender_pre_ot, comm);
        // println!("Receiver sent IDCF in {:?}", start.elapsed());

        // println!("Receiver communication after IDCF: {}", *comm);

        // for index in 0..self.table_size {
        //     for dim in 0..DIMENSION2 {
        //         idcf_sender.consistency_check(io, &idcf_table[index][dim], index * DIMENSION2 + dim);
        //     }
        // }

        // Send the hash values
        let start = Instant::now();

        // Delta= 16, Mini universe 32 * 32
        // m * 2^DIMENSION * 3 * (6^DIMENSION)

        let mut max_bin_size = 0;
        let mut total_size = 0;
        let mut num_hashes = 0;
        let mut to_be_hashed = Vec::<u8>::new();
        let mut prefixes_and_lengths = Vec::<([u128; DIMENSION], [usize; DIMENSION])>::new();

        let mut hash_vecs: Vec<Vec<[u8; 16]>> = Vec::new();

        for index in 0..self.table_size {
            // println!("Index: {}", index);
            let points_set = simple_table.query_table(index);
            let mut hashes = HashSet::<[u8; 16]>::new();
            points_set.iter().for_each(|(origin, transformed_point)| {
                prefixes_and_lengths.clear();
                prefixes_and_lengths = get_prefixes(transformed_point);

                // println!("Transformed Point: {:?}", transformed_point);
                // println!("Prefixes: {:?}", prefixes);

                prefixes_and_lengths.iter().for_each(|(prefix, length)| {
                    // Get the corresponding hash
                    to_be_hashed.clear();
                    to_be_hashed.extend_from_slice(&index.to_le_bytes());
                    let origin_oprf = oprf_receiver
                        .get_output(origin)
                        .expect("Failed to get oprf output for receiver");
                    for i in 0..DIMENSION {
                        to_be_hashed.extend_from_slice(&origin_oprf); // Change to OPRF later
                    }
                    for i in 0..DIMENSION {
                        to_be_hashed.extend_from_slice(&prefix[i].to_le_bytes());
                        to_be_hashed
                            .extend_from_slice(&((1 << length[i]) - 1 - prefix[i]).to_le_bytes());
                    }
                    for i in 0..DIMENSION {
                        to_be_hashed.extend_from_slice(
                            idcf_table[index][2 * i][(1 << length[i]) - 1 + prefix[i] as usize]
                                .as_slice(),
                        );
                        to_be_hashed.extend_from_slice(
                            idcf_table[index][2 * i + 1]
                                [(1 << length[i]) - 1 + (1 << length[i]) - 1 - prefix[i] as usize]
                                .as_slice(),
                        ); // check prefix length
                    }
                    let hash1 = blake3::hash(&to_be_hashed);
                    let mut hsh = [0u8; 16];
                    hsh.copy_from_slice(&hash1.as_bytes()[0..16]);

                    if *length == [RANGE_BITS; DIMENSION] {
                        // println!("Origin: {:?}, Point: {:?}", origin, prefix);
                        // println!("Hash: {:?}", hsh);
                    }

                    hashes.insert(hsh);
                });
            });
            num_hashes += hashes.len();
            let mut hash_vec = Vec::<[u8; 16]>::new();
            hashes.iter().for_each(|h| {
                hash_vec.push(*h);
            });
            hash_vecs.push(hash_vec);
            hashes.clear();
            max_bin_size = max(max_bin_size, points_set.len());
        }

        // println!("Max bin size: {}", max_bin_size);
        // println!("Total size: {}", total_size);
        // println!("Num hashes: {}", num_hashes);

        // println!("Receiver computed hashes in {:?}", start.elapsed());

        // for dim in 0..DIMENSION2 {
        //     for layer in 1..(depth + 1) {
        //         println!("Layer {}", layer);
        //         for x in 0..(1 << layer) {
        //             println!("IDCF: {:?}", idcf_table[27][dim][(1 << layer) - 1 + x]);
        //         }
        //     }
        // }

        for index in 0..self.table_size {
            *comm += io
                .send_block::<16>(&hash_vecs[index])
                .expect("Failed to send intersection hash");
            hash_vecs[index].clear();
        }
    }
}

fn preprocess_point(point: &[u128; DIMENSION]) -> Vec<([u128; DIMENSION], [u128; DIMENSION])> {
    let mut result = Vec::<([u128; DIMENSION], [u128; DIMENSION])>::new();
    let mut grid_origin = [0u128; DIMENSION];
    for i in 0..DIMENSION {
        grid_origin[i] = (point[i] >> (RANGE_BITS - 1)) << (RANGE_BITS - 1);
    }

    for mask in 0..(1 << DIMENSION) {
        let mut universe_origin = grid_origin.clone();
        for i in 0..DIMENSION {
            if (mask >> i) & 1 == 1 {
                universe_origin[i] -= (1 << (RANGE_BITS - 1));
            }
        }
        let mut transformed_point = [0u128; DIMENSION];
        for i in 0..DIMENSION {
            transformed_point[i] = point[i] - universe_origin[i];
        }

        result.push((universe_origin, transformed_point));
    }
    result
}

fn get_prefixes(point: &[u128; DIMENSION]) -> Vec<([u128; DIMENSION], [usize; DIMENSION])> {
    // println!("Point: {:?}", point);
    let mut prefixes_and_lengths = vec![(*point, [RANGE_BITS; DIMENSION])];
    for i in 0..DIMENSION {
        let mut new_prefixes_and_lengths = Vec::<([u128; DIMENSION], [usize; DIMENSION])>::new();
        prefixes_and_lengths.iter().for_each(|(prefix, length)| {
            let mut new_prefix = prefix.clone();
            let mut new_length = length.clone();
            for j in (0..RANGE_BITS).rev() {
                if PREF_LENGTH.contains(&(j + 1)) {
                    new_prefixes_and_lengths.push((new_prefix, new_length));
                }
                new_prefix[i] >>= 1;
                new_length[i] -= 1;
            }
        });

        prefixes_and_lengths = new_prefixes_and_lengths;
    }

    // if point == &[39, 24, 16, 47] {
    //     println!("Point: {:?}", point);
    //     prefixes_and_lengths.iter().for_each(|(prefix, length)| {
    //         println!("Prefix: {:?}, Length: {:?}", prefix, length);
    //     });
    // }

    // println!("Prefixes and lengths: {:?}", prefixes_and_lengths);

    // println!("Prefixes and lengths: {:?}", prefixes_and_lengths);

    prefixes_and_lengths
}
