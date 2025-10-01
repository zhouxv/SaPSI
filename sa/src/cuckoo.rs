use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use rand::Rng;
use sha3::{Digest, Sha3_256};

// Cuckoo hash table implementation
// I do not use stash here. If the insert operation fails, the item will not be put into a stash
// Here, NUM_LIMBS is the number of u128 in the serialized data
// For example, a 256-bit number would have M = 2
// A 512-bit number would have M = 4
pub struct CuckooHash<const NUM_LIMBS: usize> {
    table: Vec<([u128; NUM_LIMBS], [u128; NUM_LIMBS])>,
    loc_funcs: Vec<[u8; 16]>,
    table_size: usize,
    max_probe: usize,
}

impl<const NUM_LIMBS: usize> CuckooHash<NUM_LIMBS> {
    // Here, we default an empty item to be 0
    // Which means we hope that the data is random, with small probability of having 0 in the dataset
    pub fn new(table_size: usize, max_probe: usize) -> Self {
        Self {
            table: vec![([0u128; NUM_LIMBS], [0u128; NUM_LIMBS]); table_size],
            loc_funcs: vec![],
            table_size: table_size,
            max_probe: max_probe,
        }
    }

    // Generate H_1, H_2, ... for the cuckoo hash table
    pub fn generate_loc_funcs(&mut self, loc_func_count: usize, seed: Option<[u8; 16]>) {
        self.loc_funcs = vec![[0u8; 16]; loc_func_count];
        let mut sd = [0u8; 16];
        if let Some(s) = seed {
            sd.copy_from_slice(&s);
        } else {
            let mut rng = rand::thread_rng();
            rng.fill(&mut sd);
        }

        let mut aes = Aes128::new(GenericArray::from_slice(&sd));
        let mut aes_blocks: Vec<_> = (0..loc_func_count)
            .map(|i| {
                let mut block = [0u8; 16];
                block[8..].copy_from_slice(&i.to_le_bytes());
                GenericArray::clone_from_slice(&block)
            })
            .collect();

        aes.encrypt_blocks(&mut aes_blocks);
        for (i, block) in aes_blocks.iter().enumerate() {
            self.loc_funcs[i].copy_from_slice(block.as_slice());
        }

        // println!("loc_funcs: {:?}", self.loc_funcs);
    }

    pub fn location(&self, item: &[u128; NUM_LIMBS], loc_func_index: usize) -> usize {
        let mut hasher = Sha3_256::new();
        for i in 0..NUM_LIMBS {
            hasher.update(&item[i].to_le_bytes());
        }
        hasher.update(self.loc_funcs[loc_func_index]);
        let mut res = [0u8; 8];
        res.copy_from_slice(&hasher.finalize()[..8]);
        usize::from_le_bytes(res) % self.table_size
    }

    // Currently, all hashes are performed by the SHA3-256 hash function
    // Given x, returns H_1(x), H_2(x), ...
    pub fn all_locations(&self, item: &[u128; NUM_LIMBS]) -> Vec<usize> {
        let mut locations = vec![];
        for loc_func in self.loc_funcs.iter() {
            let mut hasher = Sha3_256::new();
            for i in 0..NUM_LIMBS {
                hasher.update(&item[i].to_le_bytes());
            }
            hasher.update(loc_func);
            let mut res = [0u8; 8];
            res.copy_from_slice(&hasher.finalize()[..8]);
            let location = usize::from_le_bytes(res) % self.table_size;
            locations.push(location);
        }

        locations
    }

    pub fn query(&self, item: &[u128; NUM_LIMBS]) -> bool {
        let locations = self.all_locations(item);
        for location in locations.iter() {
            if self.table[*location].0 == *item {
                println!("Item found in the table at location {}", location);
                return true;
            }
        }

        false
    }

    pub fn insert(&mut self, key: &[u128; NUM_LIMBS], value: &[u128; NUM_LIMBS]) -> bool {
        if self.query(key) {
            println!("Item already exists in the table");
            return false;
        }

        let mut level: usize = self.max_probe;
        let (mut curr_key, mut curr_value) = (key.clone(), value.clone());

        while level > 0 {
            // Loop over all posible locations
            for location in self.all_locations(&curr_key).iter() {
                if self.table[*location] == ([0u128; NUM_LIMBS], [0u128; NUM_LIMBS]) {
                    self.table[*location] = (curr_key, curr_value);
                    return true;
                }
            }

            // Sample a random location to push out the current item in the table
            let mut loc_bytes = [0u8; 8];
            let mut rng = rand::thread_rng();
            rng.fill(&mut loc_bytes);
            let mut rand_loc_func_index = usize::from_le_bytes(loc_bytes) % self.loc_funcs.len();
            let swap_location = self.location(&curr_key, rand_loc_func_index);

            let mut temp = self.table[swap_location];
            self.table[swap_location] = (curr_key, curr_value);
            (curr_key, curr_value) = temp;
            level -= 1;
        }

        return false;
    }

    pub fn print_table(&self) {
        for (i, item) in self.table.iter().enumerate() {
            println!("Location {}: {:?}", i, item);
        }
    }

    pub fn query_table(&self, index: usize) -> ([u128; NUM_LIMBS], [u128; NUM_LIMBS]) {
        self.table[index]
    }
}

pub struct SimpleHash<const NUM_LIMBS: usize> {
    // The table will have multiple bins (locations) where each key-value pair can be inserted
    table: Vec<Vec<([u128; NUM_LIMBS], [u128; NUM_LIMBS])>>,
    loc_funcs: Vec<[u8; 16]>,
    table_size: usize,
    max_bin_size: usize,
}

impl<const NUM_LIMBS: usize> SimpleHash<NUM_LIMBS> {
    // Constructor to initialize the hash table with a given size and number of locations
    pub fn new(table_size: usize, max_bin_size: usize, loc_func_count: usize) -> Self {
        Self {
            table: vec![vec![]; table_size],
            loc_funcs: vec![],
            table_size: table_size,
            max_bin_size: max_bin_size,
        }
    }

    // Generate H_1, H_2, ... for the cuckoo hash table
    pub fn generate_loc_funcs(&mut self, loc_func_count: usize, seed: Option<[u8; 16]>) {
        self.loc_funcs = vec![[0u8; 16]; loc_func_count];
        let mut sd = [0u8; 16];
        if let Some(s) = seed {
            sd.copy_from_slice(&s);
        } else {
            let mut rng = rand::thread_rng();
            rng.fill(&mut sd);
        }

        let mut aes = Aes128::new(GenericArray::from_slice(&sd));
        let mut aes_blocks: Vec<_> = (0..loc_func_count)
            .map(|i| {
                let mut block = [0u8; 16];
                block[8..].copy_from_slice(&i.to_le_bytes());
                GenericArray::clone_from_slice(&block)
            })
            .collect();

        aes.encrypt_blocks(&mut aes_blocks);
        for (i, block) in aes_blocks.iter().enumerate() {
            self.loc_funcs[i].copy_from_slice(block.as_slice());
        }

        // println!("loc_funcs: {:?}", self.loc_funcs);
    }

    pub fn location(&self, item: &[u128; NUM_LIMBS], loc_func_index: usize) -> usize {
        let mut hasher = Sha3_256::new();
        for i in 0..NUM_LIMBS {
            hasher.update(&item[i].to_le_bytes());
        }
        hasher.update(self.loc_funcs[loc_func_index]);
        let mut res = [0u8; 8];
        res.copy_from_slice(&hasher.finalize()[..8]);
        usize::from_le_bytes(res) % self.table_size
    }

    // Currently, all hashes are performed by the SHA3-256 hash function
    // Given x, returns H_1(x), H_2(x), ...
    pub fn all_locations(&self, item: &[u128; NUM_LIMBS]) -> Vec<usize> {
        let mut locations = vec![];
        for loc_func in self.loc_funcs.iter() {
            let mut hasher = Sha3_256::new();
            for i in 0..NUM_LIMBS {
                hasher.update(&item[i].to_le_bytes());
            }
            hasher.update(loc_func);
            let mut res = [0u8; 8];
            res.copy_from_slice(&hasher.finalize()[..8]);
            let location = usize::from_le_bytes(res) % self.table_size;
            locations.push(location);
        }

        locations
    }

    pub fn insert(&mut self, key: &[u128; NUM_LIMBS], value: &[u128; NUM_LIMBS]) -> bool {
        for location in self.all_locations(&key).iter() {
            self.table[*location].push((key.clone(), value.clone()));
            if self.table[*location].len() > self.max_bin_size {
                return false;
            }
        }

        true
    }

    pub fn fill_dummies(&mut self) {
        for i in 0..self.table_size {
            while self.table[i].len() < self.max_bin_size {
                self.table[i].push(([0u128; NUM_LIMBS], [0u128; NUM_LIMBS]));
            }
        }
    }

    pub fn query_table(&self, index: usize) -> Vec<([u128; NUM_LIMBS], [u128; NUM_LIMBS])> {
        self.table[index].clone()
    }
}
