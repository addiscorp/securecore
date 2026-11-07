//! Writes the JSON Schema generated from the config types. From ext/:
//!   cargo run -p securecore-config --bin securecore-schema > securecore.schema.json
//! The `schema_in_sync` test fails until the committed file matches.
fn main() {
    print!("{}", securecore_config::schema_json());
}
