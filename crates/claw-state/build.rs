//! Configures deterministic serial execution for timing-sensitive crate tests.

fn main() {
    println!("cargo:rustc-env=RUST_TEST_THREADS=1");
}
