extern crate clap;
extern crate psi_network;
extern crate psi_sa;
extern crate psi_volef2k;
extern crate rand;
extern crate rand_chacha;

use clap::Parser;
use psi_network::comm_channel::CommunicationChannel;
use psi_network::socket_channel::TcpChannel;
use psi_sa::config::*;
use psi_sa::psi_receiver::SAPSIReceiver;
use psi_sa::psi_sender::SAPSISender;
use psi_volef2k::vole_triple_f2k::{LPN12, LPN16, LPN20};
use rand::prelude::*;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use std::collections::HashSet;
use std::net::{TcpListener, TcpStream};
use std::sync::{mpsc as std_mpsc, Arc}; // 引入标准多生产者-单消费者通道
use std::time::Instant;
use std::{env, thread};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// 维度
    #[arg(long, default_value_t = 2)]
    dim: usize,

    /// 半径
    #[arg(long, default_value_t = 10)]
    delta: usize,

    ///
    #[arg(long, short, default_value_t = 0)]
    metric: usize,

    /// sender方集合大小 log
    #[arg(short, long, default_value_t = 8)]
    num: usize,

    /// 运行次数
    #[arg(short, long, default_value_t = 1)]
    times: usize,

    /// 端口
    ///     #[arg(short, long, default_value_t = 8080)]
    port: usize,
}

fn gen_input(rng: &mut ChaCha12Rng) -> [u128; DIMENSION] {
    let mut res = [0u128; DIMENSION];
    for i in 0..DIMENSION {
        res[i] = (rng.next_u64() as u128) << 64 | (rng.next_u64() as u128);
    }
    res
}

fn gen_origins(rng: &mut ChaCha12Rng, size: usize) -> Vec<[u128; DIMENSION]> {
    // Generate random origins first
    let pre_origin = (0..size)
        .map(|_| gen_input(rng))
        .collect::<Vec<[u128; DIMENSION]>>();
    let mut origins_set: HashSet<[u128; DIMENSION]> = HashSet::new();
    pre_origin.iter().for_each(|point| {
        origins_set.insert(get_origin(point));
    });
    let mut origins: Vec<[u128; DIMENSION]> = Vec::new();
    origins_set.iter().for_each(|point| {
        origins.push(*point);
    });
    origins.sort();
    origins
}

fn get_origin(point: &[u128; DIMENSION]) -> [u128; DIMENSION] {
    let mut origin = [0u128; DIMENSION];
    for i in 0..DIMENSION {
        origin[i] = point[i];
        origin[i] = (origin[i] >> RANGE_BITS) << RANGE_BITS;
    }
    origin
}

fn main() {
    let cli = Cli::parse();

    let num = cli.num;
    let pt_num = 1 << num; // 点数量
    let dim = cli.dim;
    let delta = cli.delta;
    let metric = cli.metric;
    let port = cli.port;

    const SIZE: usize = N;
    const TABLE_SIZE: usize = ((SIZE as f32) * 1.5) as usize;

    if RADIUS == 10 {
        if RANGE_BITS != 6 {
            panic!("RADIUS = 10, but RANGE_BITS != 6");
        }
        if PREF_LENGTH != [2, 4, 6] {
            panic!("RADIUS = 10, but PREF_LENGTH != [2, 4, 6]");
        }
    } else if RADIUS == 30 {
        if RANGE_BITS != 7 {
            panic!("RADIUS = 30, but RANGE_BITS != 7");
        }
        if PREF_LENGTH != [1, 3, 5, 7] {
            panic!("RADIUS = 30, but PREF_LENGTH != [1, 3, 5, 7]");
        }
    } else if RADIUS == 60 {
        if RANGE_BITS != 8 {
            panic!("RADIUS = 60, but RANGE_BITS != 8");
        }
        if PREF_LENGTH != [2, 4, 6, 8] {
            panic!("RADIUS = 60, but PREF_LENGTH != [2, 4, 6, 8]");
        }
    } else if RADIUS == 120 {
        if RANGE_BITS != 9 {
            panic!("RADIUS = 120, but RANGE_BITS != 9");
        }
        if PREF_LENGTH != [1, 3, 5, 7, 9] {
            panic!("RADIUS = 120, but PREF_LENGTH != [1, 3, 5, 7, 9]");
        }
    } else if RADIUS == 250 {
        if RANGE_BITS != 10 {
            panic!("RADIUS = 250, but RANGE_BITS != 10");
        }
        if PREF_LENGTH != [2, 4, 6, 8, 10] {
            panic!("RADIUS = 250, but PREF_LENGTH != [2, 4, 6, 8, 10]");
        }
    } else {
        panic!("Invalid RADIUS");
    }

    println!(
        "Running PSI with size: {}, radius: {}, dimension: {}",
        SIZE, RADIUS, DIMENSION
    );

    let (done_tx, done_rx) = std_mpsc::channel::<()>(); // 创建完成信号通道

    // 线程间通信通道
    // let (tx, rx) = std_mpsc::channel();
    thread::spawn(move || {
        let mut comm: u64 = 0;
        let mut param = LPN12;
        if SIZE == 1 << 8 {
            param = LPN12;
        } else if SIZE == 1 << 12 {
            param = LPN16;
        } else if SIZE == 1 << 16 {
            param = LPN20;
        } else {
            panic!("Invalid size, only accept 2^8, 2^12, or 2^16");
        }

        // println!("Starting as Receiver...");
        let listener: TcpListener =
            TcpListener::bind(format!("127.0.0.1:{}", port)).expect("Failed to bind to port");
        let (stream, _) = listener.accept().expect("Failed to accept connection");
        let mut channel = TcpChannel::new(stream);

        let seed = channel
            .receive_block::<32>()
            .expect("Failed to receive seed from receiver");
        let mut rng = ChaCha12Rng::from_seed(seed[0]);
        let origins = gen_origins(&mut rng, SIZE);
        let mut data: Vec<[u128; DIMENSION]> = Vec::new();

        origins.iter().for_each(|origin| {
            let mut point = gen_input(&mut rng);
            for j in 0..DIMENSION {
                point[j] = point[j] % (1 << RANGE_BITS);
            }
            // println!("Origin: {:?}, Point: {:?}", origin, point);
            for j in 0..DIMENSION {
                point[j] = (point[j] % (1 << RANGE_BITS)) + origin[j];
            }
            data.push(point);

            for dim in 0..DIMENSION {
                let mut x_bytes = [0u8; 16];
                x_bytes.copy_from_slice(&point[dim].to_le_bytes());
                channel
                    .send_block::<16>(&[x_bytes])
                    .expect("Failed to send x bytes");
            }

            // println!("Point 1: {:?}", point);
            // println!("Point 2: {:?}", point2);
        });

        let start = Instant::now();

        let mut receiver_psi = SAPSIReceiver::new(SIZE, TABLE_SIZE);
        receiver_psi.receive(&mut channel, &data, param, &mut comm);

        println!("Receiver finished in {:?}", start.elapsed());
        println!("Total communication: {} bytes", comm);
    });

    thread::spawn(move || {
        let mut comm: u64 = 0;
        let mut param = LPN12;
        if SIZE == 1 << 8 {
            param = LPN12;
        } else if SIZE == 1 << 12 {
            param = LPN16;
        } else if SIZE == 1 << 16 {
            param = LPN20;
        } else {
            panic!("Invalid size, only accept 2^8, 2^12, or 2^16");
        }

        let stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .expect("Failed to connect to receiver");
        let mut channel = TcpChannel::new(stream);

        let mut seed = [2u8; 32]; // debugging with seed 0 first
        let mut rng_seed = rand::thread_rng();
        rng_seed.fill(&mut seed);
        let mut rng = ChaCha12Rng::from_seed(seed);
        channel
            .send_block::<32>(&[seed])
            .expect("Failed to send seed to sender");

        let origin = gen_origins(&mut rng, SIZE);
        let mut data: Vec<[u128; DIMENSION]> = Vec::new();

        seed = [1u8; 32];
        rng_seed.fill(&mut seed);
        rng = ChaCha12Rng::from_seed(seed);

        let mut intersection_size = 0;

        origin.iter().for_each(|origin| {
            let mut point = gen_input(&mut rng);
            point = gen_input(&mut rng);
            for j in 0..DIMENSION {
                point[j] = point[j] % (1 << RANGE_BITS);
            }
            // println!("Origin: {:?}, Point: {:?}", origin, point);
            for j in 0..DIMENSION {
                point[j] = (point[j] % (1 << RANGE_BITS)) + origin[j];
            }
            data.push(point);

            // println!("Point: {:?}", point);

            let mut point2 = [0u128; DIMENSION];
            for dim in 0..DIMENSION {
                let x_bytes = channel
                    .receive_block::<16>()
                    .expect("Failed to receive x bytes");
                point2[dim] = u128::from_le_bytes(x_bytes[0]);
            }
            let mut in_range = true;
            for dim in 0..DIMENSION {
                if (point2[dim] + (RADIUS as u128) < point[dim])
                    || (point2[dim] > point[dim] + (RADIUS as u128))
                {
                    in_range = false;
                    break;
                }
            }
            if in_range {
                intersection_size += 1;
                let mut recentered_point = [0u128; DIMENSION];
                for dim in 0..DIMENSION {
                    recentered_point[dim] = point[dim] - origin[dim];
                }
                let mut recentered_point2 = [0u128; DIMENSION];
                for dim in 0..DIMENSION {
                    recentered_point2[dim] = point2[dim] - origin[dim];
                }
                // println!("Intersection: Origin: {:?}, Point: {:?}, Point2: {:?}", origin, recentered_point, recentered_point2);
            }
        });

        println!("Intersection size: {}", intersection_size);

        let start = Instant::now();

        let mut sender_psi = SAPSISender::new(SIZE, TABLE_SIZE);
        sender_psi.send(&mut channel, &data, param, &mut comm);

        println!("Sender finished in {:?}", start.elapsed());
        println!("Total communication: {} bytes", comm);

        done_tx.send(()).expect("Failed to send done signal"); // 发送完成信号
    });

    done_rx.recv().expect("Failed to receive done signal"); // 接收完成信号
}
