// Compare layer sizes between Rust and Zig implementations
// This uses the actual hypercube implementation from leansig

fn main() {
    // Test cases: (w, v, d) combinations that are relevant for our tests
    let test_cases = vec![
        (8, 1, 0),
        (8, 1, 5),
        (8, 1, 7),
        (8, 2, 0),
        (8, 2, 5),
        (8, 2, 10),
        (8, 2, 14),
        (8, 64, 0),
        (8, 64, 50),
        (8, 64, 71),
        (8, 64, 100),
        (8, 64, 200),
        (8, 64, 300),
        (8, 64, 400),
        (8, 64, 448), // max_d for v=64, w=8
    ];

    println!("Rust Layer Size Values");
    println!("======================");
    println!("Format: w={{}}, v={{}}, d={{}} -> size");
    println!();

    // We need to access the hypercube module, but it's private
    // Let's use the public API if available, or we'll need to make it public
    // For now, let's check what's available
    println!("Note: Need to access hypercube module - checking public API...");
    
    // Try to use the public hypercube_part_size function if it exists
    // This is a workaround - we may need to make hypercube module public
    for (w, v, d) in test_cases {
        let max_d = (w - 1) * v;
        if d > max_d {
            println!("w={{}}, v={{}}, d={{}} -> INVALID (max_d={{}})", w, v, d, max_d);
            continue;
        }
        
        // We can't directly access layer sizes, but we can compute prefix sums
        // which gives us cumulative sizes up to d
        println!("w={{}}, v={{}}, d={{}} -> (need hypercube access)", w, v, d);
    }
}
