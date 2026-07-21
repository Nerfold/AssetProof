fn main() {
    sp1_build::build_program("../sp1-programs/init-merkle");
    sp1_build::build_program("../sp1-programs/init-ownership");
    sp1_build::build_program("../sp1-programs/kzg-insert");
    if std::env::var_os("CARGO_FEATURE_SMT_SP1").is_some() {
        sp1_build::build_program("../sp1-programs/smt-init");
        sp1_build::build_program("../sp1-programs/smt-update");
        sp1_build::build_program("../sp1-programs/smt-insert");
    }
}
