use std::path::PathBuf;

use serde::Deserialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod extractor;

fn default_ml_extractor_window_size() -> u64 {
    30
}

#[derive(Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[zeroize(skip)]
    pub extractor_output: Option<PathBuf>,
    #[serde(default = "default_ml_extractor_window_size")]
    pub window_size: u64,
}
