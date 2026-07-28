fn main() {
    // `option_env!("METRUNE_RELEASE_PUBKEY")` bakes the release key into the
    // binary at compile time. Without this, a rebuild after the key changes (or
    // after it stops being set) would silently reuse the previously compiled
    // value, and a client could end up trusting a key the release no longer
    // signs with.
    println!("cargo::rerun-if-env-changed=METRUNE_RELEASE_PUBKEY");
}
