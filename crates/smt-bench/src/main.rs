use smt::bench::run_synthetic_bench;

fn main() -> Result<(), String> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 4 {
        return Err(
            "usage: cargo run -p smt-bench -- <depth> <num-reserves> <modified-addresses>"
                .to_string(),
        );
    }

    let depth = args[1]
        .parse::<usize>()
        .map_err(|err| format!("invalid depth: {err}"))?;
    let num_reserves = args[2]
        .parse::<usize>()
        .map_err(|err| format!("invalid num-reserves: {err}"))?;
    let modified_addresses = args[3]
        .parse::<usize>()
        .map_err(|err| format!("invalid modified-addresses: {err}"))?;

    let result = run_synthetic_bench(depth, num_reserves, modified_addresses)?;

    println!("depth={}", result.depth);
    println!("num_reserves={}", result.num_reserves);
    println!("modified_addresses={}", result.modified_addresses);
    println!("init_millis={}", result.init_elapsed.as_millis());
    println!(
        "multiproof_millis={}",
        result.multiproof_elapsed.as_millis()
    );
    println!(
        "update_witness_millis={}",
        result.witness_elapsed.as_millis()
    );
    println!("update_apply_millis={}", result.update_elapsed.as_millis());
    println!(
        "insert_witness_millis={}",
        result.insert_witness_elapsed.as_millis()
    );
    println!("insert_apply_millis={}", result.insert_elapsed.as_millis());
    println!("frontier_hashes={}", result.frontier_hashes);
    println!("total_path_siblings={}", result.total_path_siblings);
    println!("aggregate_delta={}", result.aggregate_delta);
    println!(
        "post_update_balance_total={}",
        result.post_update_balance_total
    );
    println!(
        "post_insert_balance_total={}",
        result.post_insert_balance_total
    );

    Ok(())
}
