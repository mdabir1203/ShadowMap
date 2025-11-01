use std::hash::{Hash, Hasher};
use std::hint::black_box;
use std::thread;
use std::time::Duration;

#[cfg(feature = "hotpath")]
use hotpath::{measure_block, Format, GuardBuilder};

#[cfg(not(feature = "hotpath"))]
macro_rules! measure_block {
    ($label:expr, $expr:expr) => {{
        let _ = $label;
        $expr
    }};
}

#[cfg(feature = "hotpath-alloc-count-total")]
use std::collections::HashMap;

fn main() {
    run_benchmark();
}

#[cfg(feature = "hotpath")]
fn run_benchmark() {
    let _guard = GuardBuilder::new("shadowmap::benchmark")
        .percentiles(&[75, 90, 95, 99])
        .format(Format::Json)
        .limit(32)
        .build();

    orchestrate_shadowmap_pipeline();
}

#[cfg(not(feature = "hotpath"))]
fn run_benchmark() {
    eprintln!(
        "Hotpath profiling is disabled; rerun with `--features hotpath,hotpath-ci` to record metrics."
    );
    orchestrate_shadowmap_pipeline();
}

#[cfg_attr(feature = "hotpath", hotpath::measure)]
fn orchestrate_shadowmap_pipeline() {
    let scenarios = [
        ("shadowmap.io", 18usize),
        ("api.shadowmap.io", 22),
        ("assets.shadowmap.io", 16),
        ("billing.shadowmap.io", 20),
    ];

    for (seed, batch) in scenarios {
        let inventory = enumerate_domains(seed, batch);
        correlate_risk(seed, inventory);
    }
}

#[cfg_attr(feature = "hotpath", hotpath::measure)]
fn enumerate_domains(seed: &str, batch: usize) -> usize {
    let mut discovered = 0usize;

    for i in 0..batch {
        let candidate = format!("{seed}-{i:02}");

        measure_block!("dns_resolution", {
            discovered ^= hash_candidate(&candidate);
            if i % 4 == 0 {
                thread::sleep(Duration::from_micros(110));
            }
        });

        if i % 3 == 0 {
            let artifacts = synthesize_fingerprint(i, candidate.len());
            discovered ^= artifacts;
        }
    }

    discovered
}

#[cfg_attr(feature = "hotpath", hotpath::measure)]
fn synthesize_fingerprint(iteration: usize, width: usize) -> usize {
    let size = 128 + (iteration % 8) * 16 + width;
    let mut buffer = Vec::with_capacity(size);

    for offset in 0..size {
        buffer.push(((offset * 37 + iteration) % 255) as u8);
    }

    measure_block!("normalize_headers", {
        buffer.sort_unstable();
        let chunk = (buffer.len() / 8).max(1);
        let mut rolling = 0u32;

        for piece in buffer.chunks(chunk) {
            rolling ^= piece.iter().fold(0u32, |acc, byte| acc ^ (*byte as u32));
        }

        black_box(rolling);
        thread::sleep(Duration::from_micros(80));
    });

    buffer.len()
}

#[cfg_attr(feature = "hotpath", hotpath::measure)]
fn correlate_risk(seed: &str, coverage: usize) {
    let iterations = (coverage % 6) + 5;
    let mut total = 0usize;

    for offset in 0..iterations {
        total += evaluate_certificate(seed, offset, coverage);
    }

    black_box(total);
}

#[cfg_attr(feature = "hotpath", hotpath::measure)]
fn evaluate_certificate(seed: &str, offset: usize, coverage: usize) -> usize {
    let mut bytes = seed.as_bytes().to_vec();
    bytes.resize(bytes.len() + (offset % 5) + 4, b'*');

    measure_block!("tls_parse", {
        let len = bytes.len().max(1);
        bytes.rotate_left(offset % len);
        if coverage % 2 == 0 {
            thread::sleep(Duration::from_micros(60));
        }
    });

    #[cfg(feature = "hotpath-alloc-count-total")]
    {
        let mut map = HashMap::with_capacity(offset + 4);
        for (idx, byte) in bytes.iter().enumerate() {
            map.insert(idx, *byte);
        }
        black_box(map.len());
    }

    bytes.iter().filter(|ch| **ch == b'*').count() + offset
}

fn hash_candidate(input: &str) -> usize {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    input.hash(&mut hasher);
    hasher.finish() as usize
}
