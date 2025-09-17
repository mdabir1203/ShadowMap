use crate::preferences::{Language, StyleType};

#[derive(Debug, Clone)]
pub enum Message {
    DomainChanged(String),
    RunPressed,
    ScanFinished(Result<String, String>),
    Tick,
    ToggleSettings,
    Settings(SettingsMessage),
    ThemeChanged(StyleType),
    LanguageChanged(Language),
    ClearError,
}

#[derive(Debug, Clone)]
pub enum SettingsMessage {
    ConcurrencyChanged(String),
    TimeoutChanged(String),
    RetriesChanged(String),
    Save,
    Dismiss,
}
