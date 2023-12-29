use rand::prelude::*;
use rand_chacha::ChaCha8Rng;


pub fn initialize_rng() -> ChaCha8Rng {
	let seed = <ChaCha8Rng as SeedableRng>::Seed::default();
	ChaCha8Rng::from_seed(seed)
}
