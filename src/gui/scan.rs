use iced::Color;

use crate::preferences::Language;
use crate::translations;

#[derive(Debug, Clone)]
pub enum ScanState {
    Idle,
    Running,
    Success { output: String },
    Failure { error: String },
}

#[derive(Debug, Clone)]
pub struct StatusLine {
    text: String,
    color: Color,
}

impl StatusLine {
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn color(&self) -> Color {
        self.color
    }
}

impl ScanState {
    pub fn status_line(&self, language: Language, waiting_dots: usize) -> StatusLine {
        match self {
            ScanState::Idle => StatusLine {
                text: translations::status_ready(language).to_string(),
                color: Color::from_rgb8(200, 200, 200),
            },
            ScanState::Running => StatusLine {
                text: format!(
                    "{}{}",
                    translations::status_running(language),
                    ".".repeat(waiting_dots)
                ),
                color: Color::from_rgb8(140, 200, 255),
            },
            ScanState::Success { .. } => StatusLine {
                text: translations::status_success(language).to_string(),
                color: Color::from_rgb8(140, 220, 160),
            },
            ScanState::Failure { error } => StatusLine {
                text: format!("{}: {}", translations::status_failed(language), error),
                color: Color::from_rgb8(255, 150, 150),
            },
        }
    }

    pub fn is_running(&self) -> bool {
        matches!(self, ScanState::Running)
    }
}
