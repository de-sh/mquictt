#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Quiche Error: {0}")]
    Quiche(#[from] quiche::Error)
}