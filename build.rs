extern crate string_cache_codegen;

use std::env;
use std::path::Path;

fn main() {
    string_cache_codegen::AtomType::new("cachestr::Cachestr", "cachestr!")
        .atoms(&[
            "dns.google",
            "one.one.one.one",
            "dns.alidns.com",
            "1.1.1.1",
            "1.0.0.1",
            "8.8.8.8",
            "8.8.4.4",
            "dot.pub",
            "doh.pub",
            "119.29.29.29",
        ])
        .write_to_file(&Path::new(&env::var("OUT_DIR").unwrap()).join("cachestr.rs"))
        .unwrap();
}
