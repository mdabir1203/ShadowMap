fn main() {
    if std::env::var_os("CARGO_FEATURE_DASHBOARD").is_some() {
        slint_build::compile("src/gui/dashboard.slint").expect("Failed to compile Slint UI");
    }
}
