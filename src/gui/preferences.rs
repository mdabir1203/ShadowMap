use std::fmt;

use iced::theme::Theme;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Language {
    English,
    Chinese,
}

impl Language {
    pub const ALL: [Language; 2] = [Language::English, Language::Chinese];
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Language::English => "English",
            Language::Chinese => "中文",
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum StyleType {
    Dark,
    Light,
}

impl StyleType {
    pub const ALL: [StyleType; 2] = [StyleType::Dark, StyleType::Light];
}

impl Default for StyleType {
    fn default() -> Self {
        StyleType::Dark
    }
}

impl fmt::Display for StyleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            StyleType::Dark => "Dark",
            StyleType::Light => "Light",
        })
    }
}

impl From<StyleType> for Theme {
    fn from(value: StyleType) -> Self {
        match value {
            StyleType::Dark => Theme::Dark,
            StyleType::Light => Theme::Light,
        }
    }
}
