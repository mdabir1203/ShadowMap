#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use shadowmap::{run, Args};

#[tauri::command]
async fn run_scan(domain: String) -> Result<String, String> {
    let args = Args {
        domain,
        concurrency: 50,
        timeout: 10,
        retries: 3,
    };
    run(args).await.map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![run_scan])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
