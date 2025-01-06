use std::time::Duration;

use ceno_emul::{Platform, Program};
use ceno_host::CenoStdin;
use ceno_zkvm::{
    self,
    e2e::{Checkpoint, Preset, run_e2e_with_checkpoint, setup_platform},
};
use criterion::*;

use goldilocks::GoldilocksExt2;
use mpcs::BasefoldDefault;

criterion_group! {
  name = sorting;
  config = Criterion::default().warm_up_time(Duration::from_millis(5000));
  targets = sorting_small
}

criterion_main!(sorting);

const NUM_SAMPLES: usize = 10;
type Pcs = BasefoldDefault<E>;
type E = GoldilocksExt2;

// Relevant init data for fibonacci run
fn setup() -> (Program, Platform) {
    // let mut file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // file_path.push("examples/fibonacci.elf");
    let stack_size = 32768;
    let heap_size = 2097152;
    let pub_io_size = 16;
    // let elf_bytes = fs::read(&file_path).expect("read elf file");

    let program = Program::load_elf(ceno_examples::bubble_sorting, u32::MAX).unwrap();
    let platform = setup_platform(Preset::Ceno, &program, stack_size, heap_size, pub_io_size);
    (program, platform)
}

fn sorting_small(c: &mut Criterion) {
    let (program, platform) = setup();
    use rand::{Rng, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    for n in [100, 500] {
        let max_steps = usize::MAX;
        let mut hints = CenoStdin::default();
        _ = hints.write(&(0..n).map(|_| rng.gen::<u32>()).collect::<Vec<_>>());
        let hints: Vec<u32> = (&hints).into();

        let mut group = c.benchmark_group(format!("sorting"));
        group.sample_size(NUM_SAMPLES);

        // Benchmark the proving time
        group.bench_function(
            BenchmarkId::new("sorting", format!("sorting_n={}", n)),
            |b| {
                b.iter_custom(|iters| {
                    let mut time = Duration::new(0, 0);
                    for _ in 0..iters {
                        let (_, prove) = run_e2e_with_checkpoint::<E, Pcs>(
                            program.clone(),
                            platform.clone(),
                            hints.clone(),
                            max_steps,
                            Checkpoint::PrepE2EProving,
                        );
                        let instant = std::time::Instant::now();
                        prove();
                        time += instant.elapsed();
                    }
                    time
                });
            },
        );

        group.finish();
    }

    type E = GoldilocksExt2;
}
