pub mod ethereum_fixture;

pub const FIXTURE_VERSION: &str = "ethereum-keccak-merkle-prefix-v2-ecdsa";

pub fn master_fixture_dir(fixture_dir: &std::path::Path, master_n: usize) -> std::path::PathBuf {
    fixture_dir
        .join(format!("master_n_{master_n}"))
        .join(FIXTURE_VERSION)
}
