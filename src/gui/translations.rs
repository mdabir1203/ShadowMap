use crate::preferences::Language;

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
