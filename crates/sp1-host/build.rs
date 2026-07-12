fn main() {
    sp1_build::build_program("../sp1-programs/init-merkle");
    sp1_build::build_program("../sp1-programs/smt-update");
    sp1_build::build_program("../sp1-programs/smt-insert");
    sp1_build::build_program("../sp1-programs/kzg-insert");
}
