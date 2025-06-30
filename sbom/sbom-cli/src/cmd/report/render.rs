use super::ReportResult;
use crate::cmd::report::RenderOptions;
use reqwest::Url;
use std::{
    borrow::Cow,
    fmt::{Display, Formatter},
};
use walker_common::{locale::Formatted, report, report::Summary};

pub fn render_to_html<W: std::io::Write>(
    out: &mut W,
    report: &ReportResult,
    render: &RenderOptions,
) -> anyhow::Result<()> {
    report::render(
        out,
        "SBOM Report",
        HtmlReport(report, render),
        &Default::default(),
    )?;

    Ok(())
}

struct HtmlReport<'r>(&'r ReportResult<'r>, &'r RenderOptions);

impl HtmlReport<'_> {
    fn render_errors(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let total = self.0.errors.values().map(|v| v.len()).sum();
        Self::title(f, "Errors", &[self.0.errors.len(), total])?;

        if !self.0.errors.is_empty() {
            writeln!(
                f,
                r#"
    <table class="table">
        <thead>
            <tr>
                <th scope="col">File</th>
                <th scope="col">Error</th>
            </tr>
        </thead>

        <tbody>
"#
            )?;

            for (k, v) in self.0.errors {
                let k: Cow<str> = match (&self.1.base_url, Url::parse(k)) {
                    (Some(base_url), Ok(url)) => match base_url.make_relative(&url) {
                        Some(url) => Cow::Owned(url),
                        None => Cow::Borrowed(k),
                    },
                    _ => Cow::Borrowed(k),
                };

                let k = k.rsplit_once('/').map(|r| r.1).unwrap_or(&k);
                let id = format!("error-{k}");
                let id = html_escape::encode_quoted_attribute(&id);

                writeln!(
                    f,
                    r##"
            <tr>
                <td id="{id}"><a href="{k}" target="_blank" style="white-space: nowrap;">{k}</a> <a class="link-secondary" href="#{id}">§</a></td>
                <td><ul>
            "##,
                    k = html_escape::encode_quoted_attribute(&k),
                )?;

                for msg in v {
                    writeln!(
                        f,
                        r#"
                            <li>
                              <code>{msg}</code>
                            </li>
                        "#,
                        msg = html_escape::encode_text(&msg),
                    )?;
                }

                writeln!(
                    f,
                    r#"
                </ul></td>
            </tr>
            "#,
                )?;
            }

            writeln!(
                f,
                r#"
        <tbody>
    </table>
"#
            )?;
        }

        Ok(())
    }

    fn render_total(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut summary = Vec::new();

        summary.push(("Total", Formatted(self.0.total).to_string()));
        if let Some(source) = self.1.source_url.as_ref().or(self.1.base_url.as_ref()) {
            summary.push(("Source", source.to_string()));
        }

        Summary(summary).fmt(f)
    }

    fn title(f: &mut Formatter<'_>, title: &str, count: &[usize]) -> std::fmt::Result {
        write!(f, "<h2>{title}")?;

        let total: usize = count.iter().sum();

        let class = if total > 0 {
            "text-bg-danger"
        } else {
            "text-bg-light"
        };

        for v in count {
            let v: Cow<'static, str> = match v {
                0 => "None".into(),
                n => Formatted(*n).to_string().into(),
            };
            write!(f, r#" <span class="badge {class} rounded-pill">{v}</span>"#)?;
        }

        writeln!(f, "</h2>")?;

        Ok(())
    }
}

impl Display for HtmlReport<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.render_total(f)?;
        self.render_errors(f)?;

        Ok(())
    }
}
