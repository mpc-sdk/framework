#[cfg(feature = "cggmp")]
pub mod cggmp;

// TODO: enable for FROST too once available
#[cfg(any(feature = "cggmp"))]
pub mod meeting;
