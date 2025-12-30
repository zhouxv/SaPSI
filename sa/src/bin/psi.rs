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
    /// 半径
    #[arg(long, short, default_value_t = 0)]
    delta_index: usize,

    /// sender方集合大小 log
    #[arg(short, long, default_value_t = 8)]
    num: usize,

    /// 运行次数
    #[arg(short, long, default_value_t = 3)]
    times: usize,

    /// 端口
    #[arg(short, long, default_value_t = 8080)]
    port: usize,
}

/// 生成一个随机的高维点
///
/// # 参数
/// * `rng` - ChaCha12 随机数生成器的可变引用
///
/// # 返回值
/// 返回一个长度为 DIMENSION 的 u128 数组，每个元素都是 128 位的随机数
fn gen_input(rng: &mut ChaCha12Rng) -> [u128; DIMENSION] {
    let mut res = [0u128; DIMENSION];
    for i in 0..DIMENSION {
        res[i] = (rng.next_u64() as u128) << 64 | (rng.next_u64() as u128);
    }
    res
}

/// 生成指定数量的原点（origin），确保去重并排序
///
/// # 参数
/// * `rng` - ChaCha12 随机数生成器的可变引用
/// * `size` - 要生成的点数量
/// * `range_bits` - 范围位数，用于计算原点
///
/// # 返回值
/// 返回一个排序后的原点向量，每个原点是长度为 DIMENSION 的 u128 数组
fn gen_origins(rng: &mut ChaCha12Rng, size: usize, range_bits: usize) -> Vec<[u128; DIMENSION]> {
    // Generate random origins first
    let pre_origin = (0..size)
        .map(|_| gen_input(rng))
        .collect::<Vec<[u128; DIMENSION]>>();
    let mut origins_set: HashSet<[u128; DIMENSION]> = HashSet::new();
    pre_origin.iter().for_each(|point| {
        origins_set.insert(get_origin(point, range_bits));
    });
    let mut origins: Vec<[u128; DIMENSION]> = Vec::new();
    origins_set.iter().for_each(|point| {
        origins.push(*point);
    });
    origins.sort();
    origins
}

/// 根据范围位数计算点的原点（去掉低 range_bits 位）
///
/// # 参数
/// * `point` - 输入点的引用
/// * `range_bits` - 范围位数
///
/// # 返回值
/// 返回原点坐标，其中每维的低 range_bits 位都被清零
fn get_origin(point: &[u128; DIMENSION], range_bits: usize) -> [u128; DIMENSION] {
    let mut origin = [0u128; DIMENSION];
    for i in 0..DIMENSION {
        origin[i] = point[i];
        origin[i] = (origin[i] >> range_bits) << range_bits;
    }
    origin
}

/// 执行一次完整的 PSI（私密集合交集）协议
///
/// 启动两个线程分别模拟 Receiver 和 Sender，通过 TCP 通信执行密码学 PSI 协议。
/// Receiver 先绑定端口监听，Sender 再连接；两个线程通过 channel 同步。
///
/// # 参数
/// * `pt_num` - 点的数量（必须是 2^8、2^12 或 2^16）
/// * `delta` - 搜索半径
/// * `range_bits` - 范围位数
/// * `pref_length` - 前缀长度数组的切片
/// * `port` - TCP 通信的端口号
///
/// # 返回值
/// 返回一个元组 `(time, comm)`：
/// * `time` - 执行时间（毫秒）
/// * `comm` - 总通信字节数
///
/// # Panics
/// 当点数不合法、网络连接失败或线程执行失败时会 panic
fn single_psi(
    pt_num: usize,
    delta: usize,
    range_bits: usize,
    pref_length: &[usize],
    port: usize,
) -> (u64, u64) {
    let (done_tx, done_rx) = std_mpsc::channel::<()>(); // 创建完成信号通道
    let (tcp_done_tx, tcp_done_rx) = std_mpsc::channel::<()>(); // 创建完成信号通道
    let (statistics_tx, statistics_rx) = std_mpsc::channel(); // 创建长度通道
    let (comu_tx, comu_rx) = std_mpsc::channel(); // 创建发送和接收通道

    let table_size = ((pt_num as f32) * 1.5) as usize;

    let pref_length_vec_recv = pref_length.to_vec();
    let pref_length_vec_sender = pref_length.to_vec();

    // 线程间通信通道
    // let (tx, rx) = std_mpsc::channel();
    let recv_handle = thread::spawn(move || {
        let mut comm: u64 = 0;
        let mut param = LPN12;
        if pt_num == 1 << 8 {
            param = LPN12;
        } else if pt_num == 1 << 12 {
            param = LPN16;
        } else if pt_num == 1 << 16 {
            param = LPN20;
        } else {
            panic!("Invalid size, only accept 2^8, 2^12, or 2^16");
        }

        // println!("Starting as Receiver...");
        let listener: TcpListener =
            TcpListener::bind(format!("127.0.0.1:{}", port)).expect("Failed to bind to port");

        tcp_done_tx
            .send(())
            .expect("Failed to send tcp done signal"); // 发送完成信号

        let (stream, _) = listener.accept().expect("Failed to accept connection");
        let mut channel = TcpChannel::new(stream);

        let seed = channel
            .receive_block::<32>()
            .expect("Failed to receive seed from receiver");
        let mut rng = ChaCha12Rng::from_seed(seed[0]);
        let origins = gen_origins(&mut rng, pt_num, range_bits);
        let mut data: Vec<[u128; DIMENSION]> = Vec::new();

        origins.iter().for_each(|origin| {
            let mut point = gen_input(&mut rng);
            for j in 0..DIMENSION {
                point[j] = point[j] % (1 << range_bits);
            }
            // println!("Origin: {:?}, Point: {:?}", origin, point);
            for j in 0..DIMENSION {
                point[j] = (point[j] % (1 << range_bits)) + origin[j];
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

        let mut receiver_psi = SAPSIReceiver::new(pt_num, table_size);
        receiver_psi.receive(
            &mut channel,
            &data,
            param,
            &mut comm,
            pt_num,
            range_bits,
            &pref_length_vec_recv,
        );

        // println!("Total communication: {} bytes", comm);

        comu_tx.send(comm).expect("Failed to send comm");
    });

    let sender_handle = thread::spawn(move || {
        tcp_done_rx
            .recv()
            .expect("Failed to receive tcp done signal"); // 接收完成信号

        let mut comm: u64 = 0;
        let mut param = LPN12;
        if pt_num == 1 << 8 {
            param = LPN12;
        } else if pt_num == 1 << 12 {
            param = LPN16;
        } else if pt_num == 1 << 16 {
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

        let origin = gen_origins(&mut rng, pt_num, range_bits);
        let mut data: Vec<[u128; DIMENSION]> = Vec::new();

        seed = [1u8; 32];
        rng_seed.fill(&mut seed);
        rng = ChaCha12Rng::from_seed(seed);

        let mut intersection_size = 0;

        origin.iter().for_each(|origin| {
            let mut point = gen_input(&mut rng);
            point = gen_input(&mut rng);
            for j in 0..DIMENSION {
                point[j] = point[j] % (1 << range_bits);
            }
            // println!("Origin: {:?}, Point: {:?}", origin, point);
            for j in 0..DIMENSION {
                point[j] = (point[j] % (1 << range_bits)) + origin[j];
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
                if (point2[dim] + (delta as u128) < point[dim])
                    || (point2[dim] > point[dim] + (delta as u128))
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

        // println!("Intersection size: {}", intersection_size);

        let start = Instant::now();

        let mut sender_psi = SAPSISender::new(pt_num, table_size);
        sender_psi.send(
            &mut channel,
            &data,
            param,
            &mut comm,
            pt_num,
            delta,
            range_bits,
            &pref_length_vec_sender,
        );

        // println!("Sender finished in {:?}", start.elapsed());
        // println!("Total communication: {} bytes", comm);

        let recv_comm = comu_rx.recv().expect("Failed to receive recv comm");

        statistics_tx
            .send(start.elapsed().as_millis() as u64)
            .expect("Failed to send time statistics");

        statistics_tx
            .send(comm + recv_comm)
            .expect("Failed to send total commu statistics");

        done_tx.send(()).expect("Failed to send done signal"); // 发送完成信号
    });

    recv_handle.join().expect("Receiver thread panicked");
    sender_handle.join().expect("Sender thread panicked");

    let time = statistics_rx
        .recv()
        .expect("Failed to receive time statistics"); // 接收时间统计
    let comm = statistics_rx
        .recv()
        .expect("Failed to receive commu statistics"); // 接收通信统计

    done_rx.recv().expect("Failed to receive done signal"); // 接收完成信号

    (time, comm)
}

fn main() {
    let cli = Cli::parse();

    let num = cli.num;
    let pt_num = 1 << num; // 点数量

    let port = cli.port;
    let times = cli.times;

    let delta_index = cli.delta_index;

    let delta: usize = RADIUS_PARAM[delta_index].0;
    let range_bits: usize = RADIUS_PARAM[delta_index].1;
    let pref_length: &[usize] = RADIUS_PARAM[delta_index].2;

    if delta == 10 {
        if range_bits != 6 {
            panic!("delta = 10, but range_bits != 6");
        }
        if pref_length != [2, 4, 6] {
            panic!("delta = 10, but pref_length != [2, 4, 6]");
        }
    } else if delta == 30 {
        if range_bits != 7 {
            panic!("delta = 30, but range_bits != 7");
        }
        if pref_length != [1, 3, 5, 7] {
            panic!("delta = 30, but pref_length != [1, 3, 5, 7]");
        }
    } else if delta == 60 {
        if range_bits != 8 {
            panic!("delta = 60, but range_bits != 8");
        }
        if pref_length != [2, 4, 6, 8] {
            panic!("delta = 60, but pref_length != [2, 4, 6, 8]");
        }
    } else if delta == 120 {
        if range_bits != 9 {
            panic!("delta = 120, but range_bits != 9");
        }
        if pref_length != [1, 3, 5, 7, 9] {
            panic!("delta = 120, but pref_length != [1, 3, 5, 7, 9]");
        }
    } else if delta == 250 {
        if range_bits != 10 {
            panic!("delta = 250, but range_bits != 10");
        }
        if pref_length != [2, 4, 6, 8, 10] {
            panic!("delta = 250, but pref_length != [2, 4, 6, 8, 10]");
        }
    } else {
        panic!("Invalid delta");
    }

    // println!(
    //     "Running PSI with size: {}, radius: {}, dimension: {}",
    //     pt_num, delta, DIMENSION
    // );

    let mut total_time: u64 = 0;
    let mut total_commu: u64 = 0;
    for _ in 0..times {
        let (time, commu) = single_psi(pt_num, delta, range_bits, pref_length, port);
        total_time += time;
        total_commu += commu;
    }

    let avg_time_ms = total_time / times as u64;
    let avg_commu_bytes = total_commu / times as u64;

    println!(
        "{:^5} , {:^5} , {:^5} , {:^10} 毫秒, {:^10} 字节, {:^7} 秒, {:^7.3} MB",
        pt_num,
        DIMENSION,
        delta,
        avg_time_ms,
        avg_commu_bytes,
        avg_time_ms as f64 / 1000.0,
        avg_commu_bytes as f64 / 1024.0 / 1024.0
    );
}
