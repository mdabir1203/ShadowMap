use iced::alignment::{Horizontal, Vertical};
use iced::theme;
use iced::widget::{button, column, container, row, text, text_input};
use iced::{Alignment, Element, Length};

use crate::constants::{FONT_SIZE_BUTTON, FONT_SIZE_LABEL, FONT_SIZE_STATUS, FONT_SIZE_TITLE};
use crate::messages::{Message, SettingsMessage};
use crate::preferences::Language;
use crate::settings::SettingsForm;
use crate::translations;

pub fn primary_button<'a>(label: &'a str, enabled: bool, message: Message) -> Element<'a, Message> {
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
        row![
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
    let content = column![
        text(translations::settings_title(language))
            .size(FONT_SIZE_TITLE)
            .horizontal_alignment(Horizontal::Center),
        column![
            labeled_input(
                translations::concurrency_label(language),
                form.concurrency(),
                |value| Message::Settings(SettingsMessage::ConcurrencyChanged(value)),
            ),
            labeled_input(
                translations::timeout_label(language),
                form.timeout(),
                |value| Message::Settings(SettingsMessage::TimeoutChanged(value)),
            ),
            labeled_input(
                translations::retries_label(language),
                form.retries(),
                |value| Message::Settings(SettingsMessage::RetriesChanged(value)),
            ),
        ]
        .spacing(12),
        row![
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
    row![
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
