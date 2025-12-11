use std::path::PathBuf;

use serde::Deserialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::util::GDuration;

pub mod extractor;

fn default_ml_extractor_window_size() -> GDuration {
    GDuration::from_secs(30)
}

#[derive(Deserialize, Clone, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[zeroize(skip)]
    pub extractor_output: Option<PathBuf>,
    #[serde(default = "default_ml_extractor_window_size")]
    #[zeroize(skip)]
    pub window_size: GDuration,
}
