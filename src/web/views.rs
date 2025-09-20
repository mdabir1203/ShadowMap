use chrono::DateTime;
use chrono::Utc;
use v_htmlescape::escape;

use super::state::{Job, JobConfig, JobStatus};

pub fn render_index_page(jobs: &[Job]) -> String {
    let defaults = JobConfig::default();
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ShadowMap Recon Dashboard</title>
    <script src="https://unpkg.com/htmx.org@1.9.12"></script>
    <style>
        :root {{
            color-scheme: dark;
        }}
        body {{
            margin: 0;
            font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: radial-gradient(circle at top, #0f172a, #020617 60%);
            color: #e2e8f0;
        }}
        main {{
            width: min(960px, 94vw);
            margin: 3rem auto;
            background: rgba(15, 23, 42, 0.85);
            backdrop-filter: blur(18px);
            border: 1px solid rgba(148, 163, 184, 0.18);
            border-radius: 18px;
            padding: 2.5rem 2.75rem;
            box-shadow: 0 40px 70px rgba(15, 23, 42, 0.45);
        }}
        header h1 {{
            margin: 0;
            font-size: clamp(1.8rem, 3vw, 2.4rem);
            font-weight: 600;
        }}
        header p {{
            margin: 0.35rem 0 0;
            color: #94a3b8;
        }}
        form {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1.5rem;
            margin-top: 2rem;
            align-items: end;
        }}
        label {{
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            font-size: 0.95rem;
            color: #cbd5f5;
            letter-spacing: 0.01em;
        }}
        input[type="text"],
        input[type="number"] {{
            border-radius: 12px;
            border: 1px solid rgba(148, 163, 184, 0.3);
            background: rgba(15, 23, 42, 0.6);
            color: #e2e8f0;
            padding: 0.75rem 0.9rem;
            font-size: 1rem;
            transition: border-color 0.2s ease, box-shadow 0.2s ease;
        }}
        input:focus {{
            outline: none;
            border-color: #38bdf8;
            box-shadow: 0 0 0 4px rgba(56, 189, 248, 0.15);
        }}
        button {{
            border-radius: 12px;
            border: none;
            padding: 0.85rem 1.6rem;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            background: linear-gradient(135deg, #38bdf8, #2563eb);
            color: #0f172a;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }}
        button:hover {{
            transform: translateY(-1px);
            box-shadow: 0 18px 30px rgba(56, 189, 248, 0.35);
        }}
        section {{
            margin-top: 2.5rem;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1.25rem;
        }}
        thead th {{
            text-align: left;
            font-size: 0.9rem;
            font-weight: 600;
            color: #94a3b8;
            letter-spacing: 0.06em;
            text-transform: uppercase;
            padding: 0.75rem 1rem;
        }}
        tbody td {{
            padding: 0.9rem 1rem;
            border-top: 1px solid rgba(148, 163, 184, 0.12);
            vertical-align: top;
        }}
        tbody tr:hover {{
            background: rgba(56, 189, 248, 0.07);
        }}
        .status {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.3rem 0.9rem;
            border-radius: 999px;
            font-size: 0.85rem;
            letter-spacing: 0.06em;
            text-transform: uppercase;
        }}
        .status::before {{
            content: '';
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }}
        .status-Queued {{
            background: rgba(251, 191, 36, 0.15);
            color: #fbbf24;
        }}
        .status-Queued::before {{
            background: #fbbf24;
        }}
        .status-Running {{
            background: rgba(96, 165, 250, 0.18);
            color: #60a5fa;
        }}
        .status-Running::before {{
            background: #38bdf8;
        }}
        .status-Completed {{
            background: rgba(134, 239, 172, 0.2);
            color: #86efac;
        }}
        .status-Completed::before {{
            background: #4ade80;
        }}
        .status-Failed {{
            background: rgba(248, 113, 113, 0.2);
            color: #f87171;
        }}
        .status-Failed::before {{
            background: #f87171;
        }}
        .job-actions a {{
            color: #38bdf8;
            text-decoration: none;
            font-weight: 600;
        }}
        .job-actions a:hover {{
            text-decoration: underline;
        }}
        .status-note {{
            margin-top: 0.45rem;
            font-size: 0.85rem;
            color: rgba(248, 113, 113, 0.9);
        }}
        .config-pill {{
            display: inline-flex;
            gap: 0.4rem;
            align-items: center;
            padding: 0.3rem 0.75rem;
            border-radius: 999px;
            background: rgba(148, 163, 184, 0.15);
            color: #cbd5f5;
            font-size: 0.85rem;
        }}
        .table-empty {{
            padding: 2.5rem 1rem;
            text-align: center;
            color: #64748b;
            font-size: 0.95rem;
        }}
    </style>
</head>
<body>
<main>
    <header>
        <h1>ShadowMap Recon Dashboard</h1>
        <p>Launch reconnaissance jobs, monitor progress, and retrieve structured reports in seconds.</p>
    </header>
    <form hx-post="/jobs" hx-target="#jobs-body" hx-swap="afterbegin">
        <label>
            Domain
            <input type="text" name="domain" required placeholder="example.com" autocomplete="off">
        </label>
        <label>
            Concurrency
            <input type="number" name="concurrency" min="1" max="500" value="{concurrency}">
        </label>
        <label>
            Timeout (s)
            <input type="number" name="timeout" min="1" max="120" value="{timeout}">
        </label>
        <label>
            Retries
            <input type="number" name="retries" min="0" max="10" value="{retries}">
        </label>
        <button type="submit">Launch recon</button>
    </form>
    <section>
        <h2>Recent jobs</h2>
        <table>
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>Status</th>
                    <th>Last update</th>
                    <th>Config</th>
                    <th>Output</th>
                </tr>
            </thead>
            <tbody id="jobs-body"
                   hx-get="/jobs"
                   hx-trigger="load, every 5s"
                   hx-target="#jobs-body"
                   hx-swap="innerHTML">
                {rows}
            </tbody>
        </table>
    </section>
</main>
</body>
</html>"##,
        concurrency = defaults.concurrency,
        timeout = defaults.timeout,
        retries = defaults.retries,
        rows = if jobs.is_empty() {
            String::from(
                r#"<tr><td colspan="5" class="table-empty">No jobs yet. Launch a scan to populate the dashboard.</td></tr>"#,
            )
        } else {
            render_job_rows(jobs)
        },
    )
}

pub fn render_job_rows(jobs: &[Job]) -> String {
    jobs.iter().map(render_job_row).collect()
}

pub fn render_job_row(job: &Job) -> String {
    let domain = escape(&job.domain);
    let status_class = match job.status {
        JobStatus::Queued => "Queued",
        JobStatus::Running => "Running",
        JobStatus::Completed => "Completed",
        JobStatus::Failed => "Failed",
    };
    let status_label = match job.status {
        JobStatus::Queued => "Queued",
        JobStatus::Running => "Running",
        JobStatus::Completed => "Completed",
        JobStatus::Failed => "Failed",
    };
    let updated = humanize_timestamp(job.updated_at);
    let config = format!(
        r#"<span class="config-pill"><strong>{}</strong> workers • {}s timeout • {} retries</span>"#,
        job.config.concurrency, job.config.timeout, job.config.retries
    );
    let output = match (&job.status, &job.output_path) {
        (JobStatus::Completed, Some(_)) => format!(
            r#"<div class="job-actions"><a href="/jobs/{id}/report" hx-boost="false" target="_blank">Download JSON</a></div>"#,
            id = job.id
        ),
        _ => String::from(r#"<span style="color:#475569;">Pending</span>"#),
    };
    let note = match (&job.status, &job.error) {
        (JobStatus::Failed, Some(err)) => {
            format!(r#"<div class="status-note">{}</div>"#, escape(err))
        }
        _ => String::new(),
    };

    format!(
        r#"<tr id="job-{id}"><td>{domain}</td><td><span class="status status-{class}">{label}</span>{note}</td><td>{updated}</td><td>{config}</td><td>{output}</td></tr>"#,
        id = job.id,
        domain = domain,
        class = status_class,
        label = status_label,
        updated = escape(&updated),
        config = config,
        output = output,
        note = note,
    )
}

fn humanize_timestamp(ts: DateTime<Utc>) -> String {
    ts.with_timezone(&chrono::Local)
        .format("%Y-%m-%d %H:%M:%S %Z")
        .to_string()
}
