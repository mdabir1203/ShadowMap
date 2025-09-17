#![cfg(feature = "gui")]

use iced::alignment::{Horizontal, Vertical};
use iced::executor;
use iced::theme::{self, Theme};
use iced::time;
use iced::widget::{button, column, container, pick_list, row, text, text_input};
use iced::{Alignment, Application, Color, Command, Element, Length, Settings, Subscription};
use serde::{Deserialize, Serialize};
use shadowmap::{run, Args};
use std::fmt;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::runtime::Builder;

const FONT_SIZE_TITLE: f32 = 32.0;
const FONT_SIZE_LABEL: f32 = 16.0;
const FONT_SIZE_STATUS: f32 = 18.0;
const FONT_SIZE_BUTTON: f32 = 16.0;
const TICK_INTERVAL: Duration = Duration::from_millis(450);

pub fn main() -> iced::Result {
    ShadowMapApp::run(Settings::default())
}

#[derive(Debug)]
struct ShadowMapApp {
    config: Conf,
    domain_input: String,
    scan_state: ScanState,
    waiting_dots: usize,
    show_settings: bool,
    settings_form: SettingsForm,
    language: Language,
    style: StyleType,
    error_message: Option<String>,
}

#[derive(Debug, Clone)]
enum ScanState {
    Idle,
    Running,
    Success { output: String },
    Failure { error: String },
}

struct StatusLine {
    text: String,
    color: Color,
}

impl ScanState {
    fn status_line(&self, language: Language, waiting_dots: usize) -> StatusLine {
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
}

#[derive(Debug, Clone)]
enum Message {
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
enum SettingsMessage {
    ConcurrencyChanged(String),
    TimeoutChanged(String),
    RetriesChanged(String),
    Save,
    Dismiss,
}

impl Application for ShadowMapApp {
    type Executor = executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = ();

    fn new(_flags: Self::Flags) -> (Self, Command<Self::Message>) {
        let (config, load_error) = match Conf::load() {
            Ok(conf) => (conf, None),
            Err(err) => (Conf::default(), Some(err)),
        };

        let mut app = ShadowMapApp {
            domain_input: config.last_domain.clone().unwrap_or_default(),
            scan_state: ScanState::Idle,
            waiting_dots: 0,
            show_settings: false,
            settings_form: SettingsForm::from_conf(&config),
            language: config.language,
            style: config.theme,
            config,
            error_message: None,
        };

        if let Some(error) = load_error {
            app.show_error(format!(
                "{}: {}",
                translations::config_load_failed(app.language),
                error
            ));
        }

        (app, Command::none())
    }

    fn title(&self) -> String {
        translations::window_title(self.language).to_string()
    }

    fn theme(&self) -> Theme {
        self.style.into()
    }

    fn update(&mut self, message: Self::Message) -> Command<Self::Message> {
        match message {
            Message::DomainChanged(value) => {
                self.domain_input = value;
            }
            Message::RunPressed => {
                return self.start_scan();
            }
            Message::ScanFinished(result) => self.apply_scan_result(result),
            Message::Tick => {
                if matches!(self.scan_state, ScanState::Running) {
                    self.waiting_dots = (self.waiting_dots + 1) % 4;
                }
            }
            Message::ToggleSettings => {
                self.show_settings = true;
                self.reset_settings_form();
            }
            Message::Settings(message) => self.update_settings(message),
            Message::ThemeChanged(theme) => {
                self.style = theme;
                self.config.theme = theme;
                self.persist_config();
            }
            Message::LanguageChanged(language) => {
                self.language = language;
                self.config.language = language;
                self.persist_config();
            }
            Message::ClearError => {
                self.error_message = None;
            }
        }

        Command::none()
    }

    fn subscription(&self) -> Subscription<Self::Message> {
        if matches!(self.scan_state, ScanState::Running) {
            time::every(TICK_INTERVAL).map(|_| Message::Tick)
        } else {
            Subscription::none()
        }
    }

    fn view(&self) -> Element<'_, Self::Message> {
        let header = text(translations::app_title(self.language))
            .size(FONT_SIZE_TITLE)
            .horizontal_alignment(Horizontal::Center);

        let StatusLine {
            text: status_text,
            color: status_color,
        } = self.status_line();
        let status_label = text(status_text)
            .size(FONT_SIZE_STATUS)
            .style(theme::Text::Color(status_color));

        let mut content = column![header, self.top_bar(), self.input_row(), status_label,]
            .spacing(20)
            .max_width(720.0)
            .width(Length::Fill);

        if let ScanState::Success { output } = &self.scan_state {
            content = content.push(
                text(translations::output_label(self.language))
                    .size(FONT_SIZE_LABEL)
                    .style(theme::Text::Color(Color::from_rgb8(180, 220, 180))),
            );
            content = content.push(
                text(output)
                    .size(FONT_SIZE_LABEL)
                    .style(theme::Text::Color(Color::from_rgb8(180, 220, 180))),
            );
        }

        if let Some(error) = &self.error_message {
            content = content.push(components::error_banner(
                error,
                translations::dismiss_button(self.language),
            ));
        }

        let base = container(content)
            .padding(24)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .center_y();

        if self.show_settings {
            components::settings_overlay(&self.settings_form, self.language)
        } else {
            base.into()
        }
    }
}

impl ShadowMapApp {
    fn start_scan(&mut self) -> Command<Message> {
        if !self.can_start_scan() {
            return Command::none();
        }

        let domain = self.domain_input.trim().to_string();
        self.scan_state = ScanState::Running;
        self.waiting_dots = 0;
        self.error_message = None;
        self.config.last_domain = Some(domain.clone());
        self.persist_config();

        let args = Args {
            domain,
            concurrency: self.config.concurrency,
            timeout: self.config.timeout,
            retries: self.config.retries,
        };

        Command::perform(run_scan(args), Message::ScanFinished)
    }

    fn can_start_scan(&self) -> bool {
        !self.domain_input.trim().is_empty() && !matches!(self.scan_state, ScanState::Running)
    }

    fn top_bar(&self) -> Element<'_, Message> {
        row![
            pick_list(Language::ALL, Some(self.language), Message::LanguageChanged)
                .placeholder(translations::language_label(self.language)),
            pick_list(StyleType::ALL, Some(self.style), Message::ThemeChanged)
                .placeholder(translations::theme_label(self.language)),
            components::text_button(
                translations::settings_button(self.language),
                Message::ToggleSettings,
            ),
        ]
        .spacing(12)
        .align_items(Alignment::Center)
        .into()
    }

    fn input_row(&self) -> Element<'_, Message> {
        let run_button = components::primary_button(
            translations::run_button(self.language),
            self.can_start_scan(),
            Message::RunPressed,
        );

        row![
            text(translations::domain_label(self.language)).size(FONT_SIZE_LABEL),
            text_input(
                translations::domain_placeholder(self.language),
                &self.domain_input,
            )
            .on_input(Message::DomainChanged)
            .padding(12)
            .size(FONT_SIZE_STATUS)
            .width(Length::Fill),
            run_button,
        ]
        .spacing(12)
        .align_items(Alignment::Center)
        .into()
    }

    fn status_line(&self) -> StatusLine {
        self.scan_state
            .status_line(self.language, self.waiting_dots)
    }

    fn apply_scan_result(&mut self, result: Result<String, String>) {
        self.scan_state = match result {
            Ok(output) => ScanState::Success { output },
            Err(error) => ScanState::Failure { error },
        };
    }

    fn reset_settings_form(&mut self) {
        self.settings_form = SettingsForm::from_conf(&self.config);
    }

    fn show_error(&mut self, message: impl Into<String>) {
        self.error_message = Some(message.into());
    }

    fn update_settings(&mut self, message: SettingsMessage) {
        match message {
            SettingsMessage::ConcurrencyChanged(value) => {
                self.settings_form.concurrency = value;
            }
            SettingsMessage::TimeoutChanged(value) => {
                self.settings_form.timeout = value;
            }
            SettingsMessage::RetriesChanged(value) => {
                self.settings_form.retries = value;
            }
            SettingsMessage::Save => {
                match self.settings_form.apply(&mut self.config, self.language) {
                    Ok(()) => {
                        self.show_settings = false;
                        self.reset_settings_form();
                        self.persist_config();
                    }
                    Err(error) => self.show_error(error),
                }
            }
            SettingsMessage::Dismiss => {
                self.show_settings = false;
                self.reset_settings_form();
            }
        }
    }

    fn persist_config(&mut self) {
        if let Err(err) = self.config.store() {
            self.show_error(format!(
                "{}: {}",
                translations::config_store_failed(self.language),
                err
            ));
        }
    }
}

#[derive(Debug, Clone)]
struct SettingsForm {
    concurrency: String,
    timeout: String,
    retries: String,
}

impl SettingsForm {
    fn from_conf(conf: &Conf) -> Self {
        Self {
            concurrency: conf.concurrency.to_string(),
            timeout: conf.timeout.to_string(),
            retries: conf.retries.to_string(),
        }
    }

    fn apply(&self, conf: &mut Conf, language: Language) -> Result<(), String> {
        let concurrency = Self::parse_field(
            &self.concurrency,
            language,
            translations::invalid_concurrency,
            |value: &usize| *value > 0,
        )?;

        let timeout = Self::parse_field(
            &self.timeout,
            language,
            translations::invalid_timeout,
            |value: &u64| *value > 0,
        )?;

        let retries = Self::parse_field(
            &self.retries,
            language,
            translations::invalid_retries,
            |_| true,
        )?;

        conf.concurrency = concurrency;
        conf.timeout = timeout;
        conf.retries = retries;
        Ok(())
    }

    fn parse_field<T, F>(
        value: &str,
        language: Language,
        error_message: fn(Language) -> &'static str,
        validate: F,
    ) -> Result<T, String>
    where
        T: std::str::FromStr,
        F: Fn(&T) -> bool,
    {
        let parsed = value
            .trim()
            .parse::<T>()
            .map_err(|_| error_message(language).to_string())?;

        if validate(&parsed) {
            Ok(parsed)
        } else {
            Err(error_message(language).to_string())
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum Language {
    English,
    Chinese,
}

impl Language {
    const ALL: [Language; 2] = [Language::English, Language::Chinese];
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
enum StyleType {
    Dark,
    Light,
}

impl StyleType {
    const ALL: [StyleType; 2] = [StyleType::Dark, StyleType::Light];
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Conf {
    theme: StyleType,
    language: Language,
    concurrency: usize,
    timeout: u64,
    retries: usize,
    last_domain: Option<String>,
}

impl Default for Conf {
    fn default() -> Self {
        Self {
            theme: StyleType::Dark,
            language: Language::English,
            concurrency: 50,
            timeout: 10,
            retries: 3,
            last_domain: None,
        }
    }
}

impl Conf {
    fn path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("recon_results")
            .join("shadowmap_gui_config.json")
    }

    fn load() -> Result<Self, ConfigError> {
        let path = Self::path();
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                if content.trim().is_empty() {
                    Ok(Self::default())
                } else {
                    serde_json::from_str(&content).map_err(ConfigError::from)
                }
            }
            Err(err) => {
                if err.kind() == ErrorKind::NotFound {
                    Ok(Self::default())
                } else {
                    Err(ConfigError::Io(err))
                }
            }
        }
    }

    fn store(&self) -> Result<(), ConfigError> {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

#[derive(Debug)]
enum ConfigError {
    Io(io::Error),
    Serde(serde_json::Error),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(err) => write!(f, "{}", err),
            ConfigError::Serde(err) => write!(f, "{}", err),
        }
    }
}

impl From<io::Error> for ConfigError {
    fn from(err: io::Error) -> Self {
        ConfigError::Io(err)
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(err: serde_json::Error) -> Self {
        ConfigError::Serde(err)
    }
}

impl std::error::Error for ConfigError {}

mod translations {
    use super::Language;

    pub fn window_title(language: Language) -> &'static str {
        match language {
            Language::English => "ShadowMap",
            Language::Chinese => "ShadowMap",
        }
    }

    pub fn app_title(language: Language) -> &'static str {
        match language {
            Language::English => "ShadowMap",
            Language::Chinese => "影图 ShadowMap",
        }
    }

    pub fn domain_label(language: Language) -> &'static str {
        match language {
            Language::English => "Domain",
            Language::Chinese => "域名",
        }
    }

    pub fn domain_placeholder(language: Language) -> &'static str {
        match language {
            Language::English => "example.com",
            Language::Chinese => "例: example.com",
        }
    }

    pub fn run_button(language: Language) -> &'static str {
        match language {
            Language::English => "Run",
            Language::Chinese => "开始扫描",
        }
    }

    pub fn settings_button(language: Language) -> &'static str {
        match language {
            Language::English => "Settings",
            Language::Chinese => "设置",
        }
    }

    pub fn theme_label(language: Language) -> &'static str {
        match language {
            Language::English => "Theme",
            Language::Chinese => "主题",
        }
    }

    pub fn language_label(language: Language) -> &'static str {
        match language {
            Language::English => "Language",
            Language::Chinese => "语言",
        }
    }

    pub fn status_ready(language: Language) -> &'static str {
        match language {
            Language::English => "Ready",
            Language::Chinese => "准备就绪",
        }
    }

    pub fn status_running(language: Language) -> &'static str {
        match language {
            Language::English => "Scanning",
            Language::Chinese => "扫描中",
        }
    }

    pub fn status_success(language: Language) -> &'static str {
        match language {
            Language::English => "Scan complete",
            Language::Chinese => "扫描完成",
        }
    }

    pub fn status_failed(language: Language) -> &'static str {
        match language {
            Language::English => "Scan failed",
            Language::Chinese => "扫描失败",
        }
    }

    pub fn output_label(language: Language) -> &'static str {
        match language {
            Language::English => "Results saved to:",
            Language::Chinese => "结果保存到:",
        }
    }

    pub fn config_load_failed(language: Language) -> &'static str {
        match language {
            Language::English => "Failed to load configuration",
            Language::Chinese => "加载配置失败",
        }
    }

    pub fn config_store_failed(language: Language) -> &'static str {
        match language {
            Language::English => "Failed to save configuration",
            Language::Chinese => "保存配置失败",
        }
    }

    pub fn settings_title(language: Language) -> &'static str {
        match language {
            Language::English => "Scan Settings",
            Language::Chinese => "扫描设置",
        }
    }

    pub fn concurrency_label(language: Language) -> &'static str {
        match language {
            Language::English => "Concurrency",
            Language::Chinese => "并发数",
        }
    }

    pub fn timeout_label(language: Language) -> &'static str {
        match language {
            Language::English => "Timeout (seconds)",
            Language::Chinese => "超时时间 (秒)",
        }
    }

    pub fn retries_label(language: Language) -> &'static str {
        match language {
            Language::English => "Retries",
            Language::Chinese => "重试次数",
        }
    }

    pub fn save_button(language: Language) -> &'static str {
        match language {
            Language::English => "Save",
            Language::Chinese => "保存",
        }
    }

    pub fn cancel_button(language: Language) -> &'static str {
        match language {
            Language::English => "Cancel",
            Language::Chinese => "取消",
        }
    }

    pub fn invalid_concurrency(language: Language) -> &'static str {
        match language {
            Language::English => "Concurrency must be a positive number",
            Language::Chinese => "并发数必须为正整数",
        }
    }

    pub fn invalid_timeout(language: Language) -> &'static str {
        match language {
            Language::English => "Timeout must be a positive number",
            Language::Chinese => "超时时间必须为正整数",
        }
    }

    pub fn invalid_retries(language: Language) -> &'static str {
        match language {
            Language::English => "Retries must be a number",
            Language::Chinese => "重试次数必须为整数",
        }
    }

    pub fn dismiss_button(language: Language) -> &'static str {
        match language {
            Language::English => "Dismiss",
            Language::Chinese => "关闭",
        }
    }
}

mod components {
    use super::*;

    pub fn primary_button<'a>(
        label: &'a str,
        enabled: bool,
        message: Message,
    ) -> Element<'a, Message> {
        let button = button(text(label).size(FONT_SIZE_BUTTON)).padding([10, 24]);
        let button = if enabled {
            button.style(theme::Button::Primary).on_press(message)
        } else {
            button.style(theme::Button::Secondary)
        };

        button.into()
    }

    pub fn text_button(label: &str, message: Message) -> Element<'_, Message> {
        button(text(label).size(FONT_SIZE_LABEL))
            .style(theme::Button::Secondary)
            .on_press(message)
            .padding([8, 16])
            .into()
    }

    pub fn error_banner<'a>(message: &'a str, action_label: &'a str) -> Element<'a, Message> {
        container(
            iced::widget::row![
                text(message).size(FONT_SIZE_LABEL),
                button(text(action_label).size(FONT_SIZE_LABEL))
                    .style(theme::Button::Destructive)
                    .on_press(Message::ClearError),
            ]
            .spacing(12)
            .align_items(Alignment::Center),
        )
        .padding(12)
        .style(theme::Container::Box)
        .width(Length::Fill)
        .into()
    }

    pub fn settings_overlay(form: &SettingsForm, language: Language) -> Element<'_, Message> {
        let content = iced::widget::column![
            text(translations::settings_title(language))
                .size(FONT_SIZE_TITLE)
                .horizontal_alignment(Horizontal::Center),
            iced::widget::column![
                labeled_input(
                    translations::concurrency_label(language),
                    &form.concurrency,
                    |value| { Message::Settings(SettingsMessage::ConcurrencyChanged(value)) },
                ),
                labeled_input(
                    translations::timeout_label(language),
                    &form.timeout,
                    |value| Message::Settings(SettingsMessage::TimeoutChanged(value)),
                ),
                labeled_input(
                    translations::retries_label(language),
                    &form.retries,
                    |value| Message::Settings(SettingsMessage::RetriesChanged(value)),
                ),
            ]
            .spacing(12),
            iced::widget::row![
                button(text(translations::cancel_button(language)).size(FONT_SIZE_LABEL))
                    .style(theme::Button::Secondary)
                    .on_press(Message::Settings(SettingsMessage::Dismiss)),
                button(text(translations::save_button(language)).size(FONT_SIZE_LABEL))
                    .style(theme::Button::Primary)
                    .on_press(Message::Settings(SettingsMessage::Save)),
            ]
            .spacing(12)
            .align_items(Alignment::Center),
        ]
        .spacing(16)
        .width(Length::Fill);

        let card = container(content)
            .padding(24)
            .style(theme::Container::Box)
            .max_width(360.0);

        container(card)
            .width(Length::Fill)
            .height(Length::Fill)
            .align_x(Horizontal::Center)
            .align_y(Vertical::Center)
            .style(theme::Container::Transparent)
            .into()
    }

    fn labeled_input<'a, F>(label: &'a str, value: &'a str, message: F) -> Element<'a, Message>
    where
        F: Fn(String) -> Message + 'static,
    {
        iced::widget::row![
            text(label)
                .size(FONT_SIZE_LABEL)
                .width(Length::FillPortion(1)),
            text_input("", value)
                .on_input(message)
                .padding(10)
                .size(FONT_SIZE_STATUS)
                .width(Length::FillPortion(2)),
        ]
        .spacing(12)
        .align_items(Alignment::Center)
        .into()
    }
}

fn run_scan(args: Args) -> impl std::future::Future<Output = Result<String, String>> + Send {
    async move {
        let runtime = Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .map_err(|err| err.to_string())?;

        runtime.block_on(run(args)).map_err(|err| err.to_string())
    }
}
