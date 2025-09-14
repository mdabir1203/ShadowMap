#![cfg(feature = "gui")]

use eframe::egui::{self, Color32, CornerRadius, Frame, Layout, Stroke, Visuals};
use shadowmap::{run, Args};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;

struct App {
    domain: String,
    status: String,
    worker: Option<Receiver<String>>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            domain: String::new(),
            status: "Ready".to_string(),
            worker: None,
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Ensure predictable visuals and transparent background for a
        // glassmorphism-inspired design.
        ctx.set_visuals(Visuals::dark());

        if let Some(rx) = &self.worker {
            match rx.try_recv() {
                Ok(msg) => {
                    self.status = msg;
                    self.worker = None;
                }
                Err(TryRecvError::Empty) => ctx.request_repaint(),
                Err(TryRecvError::Disconnected) => {
                    self.status = "Scan failed: worker disconnected".to_string();
                    self.worker = None;
                }
            }
        }
        let frame = Frame::new()
            .fill(Color32::from_rgba_unmultiplied(18, 18, 18, 180))
            .stroke(Stroke::new(1.0, Color32::WHITE.linear_multiply(0.1)))
            .corner_radius(CornerRadius::same(12));

        egui::CentralPanel::default().frame(frame).show(ctx, |ui| {
            ui.with_layout(Layout::top_down(egui::Align::Min), |ui| {
                ui.heading("ShadowMap");
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    ui.label("Domain");
                    let text_edit =
                        egui::TextEdit::singleline(&mut self.domain).hint_text("example.com");
                    ui.add(text_edit);
                    let run_button = ui.add_enabled(
                        self.worker.is_none() && !self.domain.is_empty(),
                        egui::Button::new("Run"),
                    );
                    if run_button.clicked() {
                        let domain = self.domain.clone();
                        let (tx, rx) = mpsc::channel();
                        thread::spawn(move || {
                            let rt = tokio::runtime::Runtime::new().unwrap();
                            let args = Args {
                                domain,
                                concurrency: 100,
                                timeout: 10,
                                retries: 2,
                            };
                            let msg = match rt.block_on(run(args)) {
                                Ok(out) => format!("Scan complete. Output at {out}"),
                                Err(e) => format!("Scan failed: {e}"),
                            };
                            let _ = tx.send(msg);
                        });
                        self.status = "Scanning...".to_string();
                        self.worker = Some(rx);
                    }
                });
                ui.add_space(10.0);
                ui.separator();
                let color = if self.status.starts_with("Scan complete") {
                    Color32::GREEN
                } else if self.status.starts_with("Scan failed") {
                    Color32::RED
                } else {
                    Color32::WHITE
                };
                ui.colored_label(color, &self.status);
            });
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "ShadowMap",
        options,
        Box::new(|_cc| Ok(Box::new(App::default()))),
    )
}
