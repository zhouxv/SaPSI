pub const RADIUS_PARAM: [(usize, usize, &[usize]); 5] = [
    (10, 6, &[2, 4, 6]),
    (30, 7, &[1, 3, 5, 7]),
    (60, 8, &[2, 4, 6, 8]),
    (120, 9, &[1, 3, 5, 7, 9]),
    (250, 10, &[2, 4, 6, 8, 10]),
];

// pub const DIMENSION: usize = 2;
// pub const DIMENSION2: usize = DIMENSION * 2; // As we need 2 range checks for each dimension
// pub const RADIUS_PARAM_CHOOSE: usize = 0;
// pub const RADIUS: usize = RADIUS_PARAM[RADIUS_PARAM_CHOOSE].0;
// pub const RANGE_BITS: usize = RADIUS_PARAM[RADIUS_PARAM_CHOOSE].1; // RANGE = 2^RANGE_BITS
// pub const PREF_LENGTH: &[usize] = RADIUS_PARAM[RADIUS_PARAM_CHOOSE].2;
// pub const N: usize = 1 << 8;

pub const LOC_FUNC_COUNT: usize = 3;
