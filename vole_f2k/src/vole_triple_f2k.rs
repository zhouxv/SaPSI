use crate::base_svole_f2k::BaseSvoleF2k;
use crate::lpn_f2k::LpnF2k;
use crate::mpfss_reg_f2k::MpfssRegF2k;
use psi_network::comm_channel::CommunicationChannel;
use psi_ot::base_cot::BaseCot;
use psi_ot::pre_ot::OTPre;
use psi_utils::gf128::gf128mul;
use std::time::Instant;

pub struct PrimalLPNParameterF2k {
    n: usize,
    t: usize,
    k: usize,
    log_bin_sz: usize,
    n_pre: usize,
    t_pre: usize,
    k_pre: usize,
    log_bin_sz_pre: usize,
    n_pre0: usize,
    t_pre0: usize,
    k_pre0: usize,
    log_bin_sz_pre0: usize,
}

impl PrimalLPNParameterF2k {
    // Default constructor
    pub fn new() -> Self {
        Self {
            n: 0,
            t: 0,
            k: 0,
            log_bin_sz: 0,
            n_pre: 0,
            t_pre: 0,
            k_pre: 0,
            log_bin_sz_pre: 0,
            n_pre0: 0,
            t_pre0: 0,
            k_pre0: 0,
            log_bin_sz_pre0: 0,
        }
    }

    // Parameterized constructor
    pub fn with_params(
        n: usize,
        t: usize,
        k: usize,
        log_bin_sz: usize,
        n_pre: usize,
        t_pre: usize,
        k_pre: usize,
        log_bin_sz_pre: usize,
        n_pre0: usize,
        t_pre0: usize,
        k_pre0: usize,
        log_bin_sz_pre0: usize,
    ) -> Self {
        // Ensure parameters are valid
        if n != t * (1 << log_bin_sz) || n_pre != t_pre * (1 << log_bin_sz_pre) || n_pre < k + t + 1
        {
            panic!("LPN parameter not matched");
        }

        Self {
            n,
            t,
            k,
            log_bin_sz,
            n_pre,
            t_pre,
            k_pre,
            log_bin_sz_pre,
            n_pre0,
            t_pre0,
            k_pre0,
            log_bin_sz_pre0,
        }
    }

    // Compute buffer size
    pub fn buf_sz(&self) -> usize {
        self.n - self.t - self.k - 1
    }
}

pub const LPN12: PrimalLPNParameterF2k = PrimalLPNParameterF2k {
    n: 5600,
    t: 700,
    k: 600,
    log_bin_sz: 3,
    n_pre: 1400,
    t_pre: 350,
    k_pre: 300,
    log_bin_sz_pre: 2,
    n_pre0: 800,
    t_pre0: 200,
    k_pre0: 250,
    log_bin_sz_pre0: 2,
};

pub const LPN16: PrimalLPNParameterF2k = PrimalLPNParameterF2k {
    n: 76800,
    t: 1200,
    k: 5000,
    log_bin_sz: 6,
    n_pre: 6400,
    t_pre: 800,
    k_pre: 650,
    log_bin_sz_pre: 3,
    n_pre0: 1500,
    t_pre0: 375,
    k_pre0: 300,
    log_bin_sz_pre0: 2,
};

pub const LPN20: PrimalLPNParameterF2k = PrimalLPNParameterF2k {
    n: 1088000,
    t: 8500,
    k: 30500,
    log_bin_sz: 7,
    n_pre: 40000,
    t_pre: 1250,
    k_pre: 3000,
    log_bin_sz_pre: 5,
    n_pre0: 4400,
    t_pre0: 550,
    k_pre0: 600,
    log_bin_sz_pre0: 3,
};

pub struct VoleTripleF2k {
    party: usize,
    param: PrimalLPNParameterF2k,
    m: usize,
    ot_used: usize,
    ot_limit: usize,
    is_malicious: bool,
    extend_initialized: bool,
    pre_ot_inplace: bool,

    pre_y: Vec<u128>,
    pre_z: Vec<u128>,
    pre_x: Vec<u128>,
    vole_y: Vec<u128>,
    vole_z: Vec<u128>,
    vole_x: Vec<u128>,

    cot: BaseCot,
    pre_ot: Option<OTPre<1>>,

    delta: u128,
}

impl VoleTripleF2k {
    pub fn new<IO: CommunicationChannel>(
        party: usize,
        malicious: bool,
        io: &mut IO,
        param: PrimalLPNParameterF2k,
        comm: &mut u64,
    ) -> Self {
        let n_pre = param.n_pre;
        let t_pre = param.t_pre;
        let n = param.n;
        let t = param.t;
        let mut cot = BaseCot::new(party, malicious);
        cot.cot_gen_pre(io, None, comm);

        VoleTripleF2k {
            party: party,
            param: param,
            m: 0,
            ot_used: 0,
            ot_limit: 0,
            is_malicious: malicious,
            extend_initialized: false,
            pre_ot_inplace: false,

            pre_y: vec![0u128; n_pre],
            pre_z: vec![0u128; n_pre],
            pre_x: vec![0u128; t_pre + 1],
            vole_y: vec![0u128; n],
            vole_z: vec![0u128; n],
            vole_x: vec![0u128; t + 1],

            cot: cot,
            pre_ot: None,

            delta: 0u128,
        }
    }

    pub fn extend_send<IO: CommunicationChannel>(
        &mut self,
        io: &mut IO,
        y: &mut [u128],
        mpfss: &mut MpfssRegF2k,
        pre_ot: &mut OTPre<1>,
        lpn: &mut LpnF2k,
        key: &[u128],
        t: usize,
        comm: &mut u64,
    ) {
        mpfss.sender_init(self.delta);
        mpfss.mpfss_sender(io, pre_ot, key, y, comm);
        pre_ot.reset();

        // // y is already a regular vector (concat of n/t unit vectors), which corresponses to the noise in LPN
        lpn.compute_send(y, &key[t + 1..]);
    }

    pub fn extend_recv<IO: CommunicationChannel>(
        &mut self,
        io: &mut IO,
        y: &mut [u128],
        z: &mut [u128],
        mpfss: &mut MpfssRegF2k,
        pre_ot: &mut OTPre<1>,
        lpn: &mut LpnF2k,
        mac: &[u128],
        u: &[u128],
        t: usize,
        comm: &mut u64,
    ) {
        mpfss.receiver_init();
        mpfss.mpfss_receiver(io, pre_ot, mac, u, y, z, comm);
        pre_ot.reset();
        lpn.compute_recv(y, z, &mac[t + 1..], &u[t + 1..]);
    }

    pub fn setup_sender<IO: CommunicationChannel>(
        &mut self,
        io: &mut IO,
        delta: u128,
        comm: &mut u64,
    ) {
        self.delta = delta;
        let delta_bytes = delta.to_le_bytes();
        *comm += io
            .send_block::<16>(&[delta_bytes])
            .expect("Cannot send test delta"); //debug only

        let seed_pre0 = [0u8; 16];
        // let seed_field_pre0 = [[0u8; 16]; 4];
        let mut seed_field_pre0 = [0u8; 16];
        seed_field_pre0[0] = 1;
        let mut lpn_pre0 = LpnF2k::new(
            self.param.k_pre0,
            self.param.n_pre0,
            &seed_pre0,
            &seed_field_pre0,
        );
        let mut mpfss_pre0 = MpfssRegF2k::new(
            self.param.n_pre0,
            self.param.t_pre0,
            self.param.log_bin_sz_pre0,
            self.party,
        );
        mpfss_pre0.set_malicious();
        let mut pre_ot_ini0 = OTPre::<1>::new(self.param.log_bin_sz_pre0, self.param.t_pre0);

        let m_pre0 = self.param.log_bin_sz_pre0 * self.param.t_pre0;
        self.cot
            .cot_gen_preot(io, &mut pre_ot_ini0, m_pre0, None, comm);

        // mac = key + delta * u
        let triple_n0 = 1 + self.param.t_pre0 + self.param.k_pre0;
        let mut key = vec![0u128; triple_n0];
        let mut svole0 = BaseSvoleF2k::new_sender(io, self.delta, comm);
        svole0.triple_gen_send(io, &mut key, triple_n0, comm);

        // println!("Test base svole: {:?}", key[0]);

        io.flush();

        let mut pre_y0 = vec![0u128; self.param.n_pre0];
        self.extend_send(
            io,
            &mut pre_y0,
            &mut mpfss_pre0,
            &mut pre_ot_ini0,
            &mut lpn_pre0,
            &key,
            self.param.t_pre0,
            comm,
        );

        // println!("Test LPN: {:?}", pre_y0[0]);

        let seed_pre = [0u8; 16];
        // let seed_field_pre = [[0u8; 16]; 4];
        let mut seed_field_pre = [0u8; 16];
        seed_field_pre[0] = 1;
        let mut lpn_pre = LpnF2k::new(
            self.param.k_pre,
            self.param.n_pre,
            &seed_pre,
            &seed_field_pre,
        );
        let mut mpfss_pre = MpfssRegF2k::new(
            self.param.n_pre,
            self.param.t_pre,
            self.param.log_bin_sz_pre,
            self.party,
        );
        mpfss_pre.set_malicious();
        let mut pre_ot_ini = OTPre::new(self.param.log_bin_sz_pre, self.param.t_pre);

        let m_pre = self.param.log_bin_sz_pre * self.param.t_pre;
        self.cot
            .cot_gen_preot(io, &mut pre_ot_ini, m_pre, None, comm);

        //
        let triple_n = 1 + self.param.t_pre + self.param.k_pre;
        let mut pre_y = vec![0u128; self.param.n_pre];
        self.extend_send(
            io,
            &mut pre_y,
            &mut mpfss_pre,
            &mut pre_ot_ini,
            &mut lpn_pre,
            &pre_y0[..triple_n],
            self.param.t_pre,
            comm,
        );
        self.pre_y.copy_from_slice(&pre_y);

        self.pre_ot_inplace = true;
    }

    pub fn setup_receiver<IO: CommunicationChannel>(&mut self, io: &mut IO, comm: &mut u64) {
        let start = Instant::now();
        let delta_bytes = io
            .receive_block::<16>()
            .expect("Failed to receive test delta");
        self.delta = u128::from_le_bytes(delta_bytes[0]);

        let seed_pre0 = [0u8; 16];
        let mut seed_field_pre0 = [0u8; 16];
        seed_field_pre0[0] = 1;
        let mut lpn_pre0 = LpnF2k::new(
            self.param.k_pre0,
            self.param.n_pre0,
            &seed_pre0,
            &seed_field_pre0,
        );
        let mut mpfss_pre0 = MpfssRegF2k::new(
            self.param.n_pre0,
            self.param.t_pre0,
            self.param.log_bin_sz_pre0,
            self.party,
        );
        mpfss_pre0.set_malicious();
        let mut pre_ot_ini0 = OTPre::new(self.param.log_bin_sz_pre0, self.param.t_pre0);

        let m_pre0 = self.param.log_bin_sz_pre0 * self.param.t_pre0;
        self.cot
            .cot_gen_preot(io, &mut pre_ot_ini0, m_pre0, None, comm);

        // mac = key + delta * u
        let triple_n0 = 1 + self.param.t_pre0 + self.param.k_pre0;
        let mut mac = vec![0u128; triple_n0];
        let mut u = vec![0u128; triple_n0];

        // println!("Time for cot gen preot: {:?}", start.elapsed());

        let mut svole0 = BaseSvoleF2k::new_receiver(io, comm);
        svole0.triple_gen_recv(io, &mut mac, &mut u, triple_n0, comm);

        // println!("Time for svole0: {:?}", start.elapsed());

        // println!("Test base svole: {:?}", mac[0] - u[0] * self.delta);

        io.flush();

        let mut pre_y0 = vec![0u128; self.param.n_pre0];
        let mut pre_z0 = vec![0u128; self.param.n_pre0];
        self.extend_recv(
            io,
            &mut pre_y0,
            &mut pre_z0,
            &mut mpfss_pre0,
            &mut pre_ot_ini0,
            &mut lpn_pre0,
            &mac,
            &u,
            self.param.t_pre0,
            comm,
        );

        let seed_pre = [0u8; 16];
        let mut seed_field_pre = [0u8; 16];
        seed_field_pre[0] = 1;
        let mut lpn_pre = LpnF2k::new(
            self.param.k_pre,
            self.param.n_pre,
            &seed_pre,
            &seed_field_pre,
        );
        let mut mpfss_pre = MpfssRegF2k::new(
            self.param.n_pre,
            self.param.t_pre,
            self.param.log_bin_sz_pre,
            self.party,
        );
        mpfss_pre.set_malicious();
        let mut pre_ot_ini = OTPre::new(self.param.log_bin_sz_pre, self.param.t_pre);

        let m_pre = self.param.log_bin_sz_pre * self.param.t_pre;
        self.cot
            .cot_gen_preot(io, &mut pre_ot_ini, m_pre, None, comm);

        // println!("Time for cot gen preot: {:?}", start.elapsed());

        //
        let triple_n = 1 + self.param.t_pre + self.param.k_pre;
        let mut pre_y = vec![0u128; self.param.n_pre];
        let mut pre_z = vec![0u128; self.param.n_pre];
        self.extend_recv(
            io,
            &mut pre_y,
            &mut pre_z,
            &mut mpfss_pre,
            &mut pre_ot_ini,
            &mut lpn_pre,
            &pre_y0[..triple_n],
            &pre_z0[..triple_n],
            self.param.t_pre,
            comm,
        );
        self.pre_y.copy_from_slice(&pre_y);
        self.pre_z.copy_from_slice(&pre_z);

        self.pre_ot_inplace = true;
    }

    pub fn extend_initialization(&mut self) {
        self.m = self.param.k + self.param.t + 1;
        self.ot_limit = self.param.n - self.m;
        self.ot_used = self.ot_limit;
        self.extend_initialized = true;
    }

    pub fn extend_once<IO: CommunicationChannel>(
        &mut self,
        io: &mut IO,
        data_y: &mut [u128],
        data_z: &mut [u128],
        mpfss: &mut MpfssRegF2k,
        pre_ot: &mut OTPre<1>,
        lpn: &mut LpnF2k,
        comm: &mut u64,
    ) {
        self.cot
            .cot_gen_preot(io, pre_ot, self.param.t * self.param.log_bin_sz, None, comm);
        let mut pre_y = vec![0u128; self.m];
        pre_y.copy_from_slice(&self.pre_y[..self.m]);
        let mut pre_z = vec![0u128; self.m];
        pre_z.copy_from_slice(&self.pre_z[..self.m]);
        if self.party == 0 {
            self.extend_send(io, data_y, mpfss, pre_ot, lpn, &pre_y, self.param.t, comm);
        } else {
            self.extend_recv(
                io,
                data_y,
                data_z,
                mpfss,
                pre_ot,
                lpn,
                &pre_y,
                &pre_z,
                self.param.t,
                comm,
            );
        }
        self.pre_y[..self.m].copy_from_slice(&data_y[self.ot_limit..]);
        self.pre_z[..self.m].copy_from_slice(&data_z[self.ot_limit..]);
    }

    pub fn extend<IO: CommunicationChannel>(
        &mut self,
        io: &mut IO,
        data_y: &mut [u128],
        data_z: &mut [u128],
        num: usize,
        comm: &mut u64,
    ) {
        if self.extend_initialized == false {
            panic!("Run extend_initialization first!");
        }

        if num <= self.silent_ot_left() {
            data_y.copy_from_slice(&self.vole_y[self.ot_used..self.ot_used + num]);
            data_z.copy_from_slice(&self.vole_z[self.ot_used..self.ot_used + num]);
            return;
        }

        let gened = self.silent_ot_left();
        let mut copied = 0;
        if gened > 0 {
            data_y.copy_from_slice(&self.vole_y[self.ot_used..self.ot_used + gened]);
            data_z.copy_from_slice(&self.vole_z[self.ot_used..self.ot_used + gened]);
            copied += gened;
        }

        self.m = self.param.k + self.param.t + 1;
        let mut round_inplace = 0;
        if num > gened + self.m {
            round_inplace = (num - gened - self.m) / self.ot_limit;
        }
        let mut last_round_ot = num - gened - round_inplace * self.ot_limit; // m + something
        let round_memcpy = (last_round_ot > self.ot_limit) as bool;
        if round_memcpy {
            last_round_ot -= self.ot_limit;
        }

        let mut pre_ot = OTPre::new(self.param.log_bin_sz, self.param.t);
        let seed = [0u8; 16];
        let mut seed_field = [0u8; 16];
        seed_field[0] = 1;
        let mut lpn = LpnF2k::new(self.param.k, self.param.n, &seed, &seed_field);
        let mut mpfss = MpfssRegF2k::new(
            self.param.n,
            self.param.t,
            self.param.log_bin_sz,
            self.party,
        );
        mpfss.set_malicious();

        for i in 0..round_inplace {
            self.extend_once(
                io,
                &mut data_y[copied..copied + self.param.n],
                &mut data_z[copied..copied + self.param.n],
                &mut mpfss,
                &mut pre_ot,
                &mut lpn,
                comm,
            );
            self.ot_used = self.ot_limit;
            copied += self.ot_limit;
        }

        if round_memcpy {
            let mut tmp_y = vec![0u128; self.param.n];
            let mut tmp_z = vec![0u128; self.param.n];
            self.extend_once(
                io,
                &mut tmp_y,
                &mut tmp_z,
                &mut mpfss,
                &mut pre_ot,
                &mut lpn,
                comm,
            );
            self.vole_y.copy_from_slice(&tmp_y);
            self.vole_z.copy_from_slice(&tmp_z);
            data_y[copied..copied + self.ot_limit].copy_from_slice(&tmp_y[..self.ot_limit]);
            data_z[copied..copied + self.ot_limit].copy_from_slice(&tmp_z[..self.ot_limit]);
            self.ot_used = self.ot_limit;
            copied += self.ot_limit;
        }

        if last_round_ot > 0 {
            let mut tmp_y = vec![0u128; self.param.n];
            let mut tmp_z = vec![0u128; self.param.n];
            self.extend_once(
                io,
                &mut tmp_y,
                &mut tmp_z,
                &mut mpfss,
                &mut pre_ot,
                &mut lpn,
                comm,
            );
            self.vole_y.copy_from_slice(&tmp_y);
            self.vole_z.copy_from_slice(&tmp_z);
            data_y[copied..].copy_from_slice(&tmp_y[..last_round_ot]);
            data_z[copied..].copy_from_slice(&tmp_z[..last_round_ot]);
            self.ot_used = last_round_ot;
        }
    }

    pub fn silent_ot_left(&self) -> usize {
        self.ot_limit - self.ot_used
    }

    // debug only
    pub fn check_triple<IO: CommunicationChannel>(
        &self,
        io: &mut IO,
        x: u128,
        y: &[u128],
        z: &[u128],
        size: usize,
    ) {
        if self.party == 0 {
            let x_bytes = x.to_le_bytes();
            let y_bytes = y.iter().map(|&v| v.to_le_bytes()).collect::<Vec<_>>();
            io.send_block::<16>(&[x_bytes])
                .expect("Failed to send delta test.");
            io.send_block::<16>(&y_bytes)
                .expect("Failed to send k test.");
        } else {
            // want y = k + delta * z
            let delta_bytes = io
                .receive_block::<16>()
                .expect("Failed to receive delta test.")[0];
            let k_bytes = io.receive_block::<16>().expect("Failed to receive k test");
            let delta = u128::from_le_bytes(delta_bytes);
            let k = k_bytes
                .iter()
                .map(|&v| u128::from_le_bytes(v))
                .collect::<Vec<_>>();
            for i in 0..size {
                if y[i] != k[i] ^ gf128mul(delta, z[i]) {
                    panic!("tripple error at index {}", i);
                }
            }
        }
    }
}
