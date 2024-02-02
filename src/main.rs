use std::{process::exit, time::Instant};

use ocl::{flags, Buffer, ProQue};
use sha3::{Digest, Keccak256};

extern crate hashes;
extern crate ocl;
extern crate sha3;

const GLOBAL_WORK_SIZE: usize = 5120000;
const LOCAL_WORK_SIZE: usize = 32;

fn gpu_keccak(samples: &[[u8; 4]]) -> Vec<u8> {
    let binding = samples.to_owned().concat();
    let msgs = binding.as_slice();
    let kernel_source = include_str!("cl/kernel.cl");
    let pro_que = ProQue::builder().src(kernel_source).build().unwrap();
    let buffer_msg = Buffer::builder()
        .queue(pro_que.queue().clone())
        .flags(flags::MEM_READ_ONLY)
        .len(msgs.len())
        .copy_host_slice(msgs)
        .build()
        .unwrap();

    let buffer_out = Buffer::builder()
        .queue(pro_que.queue().clone())
        .flags(flags::MEM_WRITE_ONLY)
        .len(msgs.len() * 8)
        .build()
        .unwrap();

    let start = Instant::now();

    let kernel_build = pro_que
        .kernel_builder("keccak_bench")
        .arg(&buffer_msg)
        .arg(&4u32)
        .arg(&buffer_out)
        .global_work_size(GLOBAL_WORK_SIZE)
        .local_work_size(LOCAL_WORK_SIZE)
        .build();

    match kernel_build {
        Ok(kernel) => unsafe {
            kernel.enq().unwrap();
        },
        Err(x) => {
            println!("{}", x.to_string());
            exit(1);
        }
    }

    let mut out_vec = vec![0u8; msgs.len() * 8];
    buffer_out.read(&mut out_vec).enq().unwrap();
    println!("gpu keccak elapsed: {:?}", start.elapsed());
    out_vec
}

fn cpu_keccak(samples: &[[u8; 4]]) -> Vec<[u8; 32]> {
    let start = Instant::now();
    let mut output = Vec::new();
    for msg in samples {
        let mut keccak = Keccak256::new();
        keccak.update(msg);
        let ret: [u8; 32] = keccak.finalize().into();
        output.push(ret);
    }
    println!("cpu keccak elapsed: {:?}", start.elapsed());
    output
}

fn generate_samples() -> Vec<[u8; 4]> {
    let mut vec = Vec::new();
    for i in 0..200u8 {
        for j in 0..200u8 {
            for k in 0..128u8 {
                vec.push([i, j, k, 0]);
            }
        }
    }
    println!("generated {} sample data", vec.len());

    vec
}

fn main() {
    let samples = generate_samples();
    let gpu_result = gpu_keccak(samples.as_slice());
    let cpu_result = cpu_keccak(&samples.as_slice());
    for i in 0..samples.len() {
        for x in 0..32 {
            assert_eq!(cpu_result[i][x], gpu_result[i * 32 + x])
        }
    }
}
