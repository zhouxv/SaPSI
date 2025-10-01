extern crate psi_sa;
extern crate rand;

use psi_sa::cuckoo::CuckooHash;
use rand::Rng;
use std::convert::TryInto;

const NUM_LIMBS: usize = 2;
const SIZE: usize = 10;
const LOC_FUNC_COUNT: usize = 3;
const MAX_PROBE: usize = 10;
const TABLE_SIZE: usize = 16;

fn main() {
    let mut items = [[0u128; NUM_LIMBS]; SIZE];
    let mut rng = rand::thread_rng();
    for i in 0..SIZE {
        let mut rand_bytes = [0u8; 16 * NUM_LIMBS];
        rng.fill(&mut rand_bytes);
        for j in 0..NUM_LIMBS {
            items[i][j] = u128::from_le_bytes(rand_bytes[j * 16..(j + 1) * 16].try_into().unwrap());
        }
    }

    let mut cuckoo = CuckooHash::new(TABLE_SIZE, MAX_PROBE);
    cuckoo.generate_loc_funcs(LOC_FUNC_COUNT, None);
    for item in items.iter() {
        let res: bool = cuckoo.insert(item, &[0u128; NUM_LIMBS]);
        println!("Insertion result: {}", res);
    }

    cuckoo.print_table();
}
