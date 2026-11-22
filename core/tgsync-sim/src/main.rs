// SPDX-License-Identifier: AGPL-3.0-or-later
//! `cargo run --release -p tgsync-sim -- [--seeds N] [--start S] [--steps M]`
//! Runs seeds S..S+N; prints the trace of the first failing seed and exits 1.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str, default: u64| {
        args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map_or(default, |v| v.parse().expect(name))
    };
    let (seeds, start, steps) = (arg("--seeds", 1000), arg("--start", 0), arg("--steps", 200) as usize);
    let t = std::time::Instant::now();
    let (mut msgs, mut conflicts, mut problems, mut stale) = (0, 0, 0, 0);
    for seed in start..start + seeds {
        match tgsync_sim::run(seed, steps) {
            Ok(s) => {
                msgs += s.messages;
                conflicts += s.conflicts;
                problems += s.problems;
                stale += s.stale_epoch;
            }
            Err(e) => {
                eprintln!("{e}");
                eprintln!("replay: cargo run --release -p tgsync-sim -- --start {seed} --seeds 1 --steps {steps}");
                std::process::exit(1);
            }
        }
    }
    println!(
        "{seeds} seeds x {steps} steps ok in {:.1}s: {msgs} messages, {conflicts} conflict copies, {problems} skipped messages, {stale} records rejected for an old key (re-sent)",
        t.elapsed().as_secs_f64()
    );
}
