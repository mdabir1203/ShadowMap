use crate::config::Conf;
use crate::preferences::Language;
use crate::translations;

#[derive(Debug, Clone)]
pub struct SettingsForm {
    concurrency: String,
    timeout: String,
    retries: String,
}

impl SettingsForm {
    pub fn from_conf(conf: &Conf) -> Self {
        Self {
            concurrency: conf.concurrency.to_string(),
            timeout: conf.timeout.to_string(),
            retries: conf.retries.to_string(),
        }
    }

    pub fn apply(&self, conf: &mut Conf, language: Language) -> Result<(), String> {
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

    pub fn concurrency(&self) -> &str {
        &self.concurrency
    }

    pub fn timeout(&self) -> &str {
        &self.timeout
    }

    pub fn retries(&self) -> &str {
        &self.retries
    }

    pub fn set_concurrency(&mut self, value: String) {
        self.concurrency = value;
    }

    pub fn set_timeout(&mut self, value: String) {
        self.timeout = value;
    }

    pub fn set_retries(&mut self, value: String) {
        self.retries = value;
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
