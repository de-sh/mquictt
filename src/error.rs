#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Quiche Error: {0}")]
    Quiche(#[from] quiche::Error),
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Missing Token Error")]
    MissingToken,
    #[error("Missing Client Error")]
    MissingClient,
    #[error("Ring Unspecified Error")]
    RingUnspecified
}
