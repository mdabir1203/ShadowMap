#![cfg(feature = "gui")]

#[path = "gui/app.rs"]
mod app;
#[path = "gui/components.rs"]
mod components;
#[path = "gui/config.rs"]
mod config;
#[path = "gui/constants.rs"]
mod constants;
#[path = "gui/messages.rs"]
mod messages;
#[path = "gui/preferences.rs"]
mod preferences;
#[path = "gui/scan.rs"]
mod scan;
#[path = "gui/settings.rs"]
mod settings;
#[path = "gui/translations.rs"]
mod translations;

pub use app::ShadowMapApp;

pub fn main() -> iced::Result {
    app::launch()
}
