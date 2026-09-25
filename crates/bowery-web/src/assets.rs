//! The browser console, compiled into the binary.
//!
//! `include_str!` rather than a directory read at runtime: the binary
//! is scp'd to whichever box holds the operator key, and a console
//! that needs its asset directory copied alongside it is a console
//! that will one day be served half-missing. It also means there is
//! nothing on disk next to the key for a local process to rewrite.

pub(crate) const INDEX_HTML: &str = include_str!("../web/index.html");
pub(crate) const APP_CSS: &str = include_str!("../web/app.css");
pub(crate) const APP_JS: &str = include_str!("../web/app.js");

#[cfg(test)]
mod tests {
    use super::*;

    /// The page fetches nothing from anywhere.
    ///
    /// An operator investigating a compromise must not announce to a
    /// third party the moment they opened an alert, and the host may
    /// have no route out at all — which is a normal state for the
    /// machines this watches. The notification email holds the same
    /// line for the same reasons; this is that rule applied to the
    /// console.
    #[test]
    fn nothing_in_the_page_reaches_off_the_box() {
        for (what, text) in [
            ("index.html", INDEX_HTML),
            ("app.css", APP_CSS),
            ("app.js", APP_JS),
        ] {
            // The SVG and XHTML namespaces are identifiers, not
            // addresses: `createElementNS` compares them as strings
            // and no browser ever resolves them. Stripping them keeps
            // the check honest rather than forcing the code to avoid
            // spelling a namespace correctly.
            let lower = text
                .to_ascii_lowercase()
                .replace("http://www.w3.org/2000/svg", "")
                .replace("http://www.w3.org/1999/xhtml", "");
            for probe in [
                "http://",
                "https://",
                "//cdn",
                "fonts.googleapis",
                "unpkg",
                "jsdelivr",
                "cdnjs",
                "@import url(",
            ] {
                assert!(
                    !lower.contains(probe),
                    "{what} reaches off the box: found {probe:?}"
                );
            }
        }
    }

    /// Every pane the terminal console has, the browser has.
    #[test]
    fn the_panes_match_the_terminal_console() {
        for pane in [
            "query", "alerts", "mesh", "audit", "peers", "silences", "doctor", "chat", "help",
        ] {
            assert!(
                INDEX_HTML.contains(&format!("data-pane=\"{pane}\"")),
                "no {pane} pane in the page"
            );
        }
    }

    /// The assets are actually wired, not empty files that compile.
    #[test]
    fn the_assets_are_not_empty() {
        assert!(INDEX_HTML.contains("<html"), "index is not a document");
        assert!(APP_CSS.len() > 500, "stylesheet looks empty");
        assert!(APP_JS.contains("fetch("), "the page never talks to the API");
    }
}
