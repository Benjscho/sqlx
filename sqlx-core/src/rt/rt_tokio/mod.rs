mod socket;
pub use socket::TokioStream;

pub fn available() -> bool {
    tokio::runtime::Handle::try_current().is_ok()
}
