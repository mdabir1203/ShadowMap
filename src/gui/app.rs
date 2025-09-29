use iced::alignment::Horizontal;
use iced::executor;
use iced::theme::{self, Theme};
use iced::time;
use iced::widget::{column, container, pick_list, row, text, text_input};
use iced::{Alignment, Application, Color, Command, Element, Length, Settings, Subscription};
use shadowmap::{run, Args};
use tokio::runtime::Builder;

use crate::components;
use crate::config::Conf;
use crate::constants::{FONT_SIZE_LABEL, FONT_SIZE_STATUS, FONT_SIZE_TITLE, TICK_INTERVAL};
use crate::messages::{Message, SettingsMessage};
use crate::preferences::{Language, StyleType};
use crate::scan::{ScanState, StatusLine};
use crate::settings::SettingsForm;
use crate::translations;

#[derive(Debug)]
pub struct ShadowMapApp {
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

pub fn launch() -> iced::Result {
    ShadowMapApp::run(Settings::default())
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
                if self.scan_state.is_running() {
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
        if self.scan_state.is_running() {
            time::every(TICK_INTERVAL).map(|_| Message::Tick)
        } else {
            Subscription::none()
        }
    }

    fn view(&self) -> Element<'_, Self::Message> {
        let header = text(translations::app_title(self.language))
            .size(FONT_SIZE_TITLE)
            .horizontal_alignment(Horizontal::Center);

        let status = self.status_line();
        let status_label = text(status.text())
            .size(FONT_SIZE_STATUS)
            .style(theme::Text::Color(status.color()));

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
            autonomous: false,
        };

        Command::perform(run_scan(args), Message::ScanFinished)
    }

    fn can_start_scan(&self) -> bool {
        !self.domain_input.trim().is_empty() && !self.scan_state.is_running()
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
                self.settings_form.set_concurrency(value);
            }
            SettingsMessage::TimeoutChanged(value) => {
                self.settings_form.set_timeout(value);
            }
            SettingsMessage::RetriesChanged(value) => {
                self.settings_form.set_retries(value);
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
