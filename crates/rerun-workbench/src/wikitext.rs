//! A bounded scanner for the few template parameters `draft` reads from a PCGamingWiki page's
//! wikitext (P4-14, user decision D4 a: anonymous Cargo queries are refused, so the facts come
//! from the page's own `{{Infobox game}}`, `{{API}}`, `{{Video}}` and `{{Input}}`).
//!
//! The wikitext is untrusted input. The scanner is two linear passes over its bytes, no regex
//! and no recursion:
//!
//! 1. **Clean:** HTML comments `<!-- … -->` are removed (as MediaWiki does); a `<nowiki>` or
//!    `<pre>` element (case ignored, also self-closing) becomes one [`OPAQUE`] character, so
//!    braces inside it count for nothing and a value holding one is never whitelisted. An
//!    unclosed comment or element is an error, never "to the end".
//! 2. **Scan:** `{{` opens and `}}` closes a template, `[[`/`]]` a link inside a template (a
//!    `|` inside a link or a nested template does not split the outer template). Only templates
//!    at the top level are read: their first segment is the name, every `key = value` segment
//!    a named parameter (split at the first `=` of the template's own level), positional ones
//!    are skipped. Nesting is at most [`MAX_DEPTH`], a template has at most [`MAX_SEGMENTS`]
//!    segments, a page at most [`MAX_TEMPLATES`] top-level templates; a template still open at
//!    the end is an error.
//!
//! Only the wanted templates and keys are kept: a wanted template twice, a wanted key twice in
//! one template, or a wanted value above [`MAX_VALUE`] bytes is an error (fail closed, never a
//! guess between two values). Names compare as MediaWiki's do in the parts that matter here: `_`
//! is a space, the first letter's case is ignored, the rest is exact; keys are exact after
//! trimming ASCII white space, so a look-alike key (a zero-width or full-width character) never
//! matches.

/// Deepest nesting of templates and links.
pub const MAX_DEPTH: usize = 64;
/// Most segments (name and parameters) of one top-level template.
pub const MAX_SEGMENTS: usize = 1024;
/// Most top-level templates of one page.
pub const MAX_TEMPLATES: usize = 4096;
/// Most bytes of one wanted value (after trimming).
pub const MAX_VALUE: usize = 4096;
/// Most bytes of the opening tag of a `<nowiki>` or `<pre>` element (`<nowiki attr…>`).
const MAX_TAG: usize = 256;
/// What a `<nowiki>` or `<pre>` element becomes: no value that holds it is whitelisted.
pub const OPAQUE: char = '\u{FFFD}';

/// Why the wikitext was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    /// `<!--` without `-->`.
    UnclosedComment,
    /// `<nowiki>` or `<pre>` without its closing tag.
    UnclosedTag,
    /// A template still open at the end.
    UnclosedTemplate,
    /// Nested deeper than [`MAX_DEPTH`].
    TooDeep,
    /// A template with more than [`MAX_SEGMENTS`] segments.
    TooManyParams,
    /// More than [`MAX_TEMPLATES`] top-level templates.
    TooManyTemplates,
    /// A wanted template twice.
    DuplicateTemplate(&'static str),
    /// A wanted key twice in one template.
    DuplicateParam(&'static str, &'static str),
    /// A wanted value above [`MAX_VALUE`] bytes.
    ValueTooLong(&'static str, &'static str),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnclosedComment => f.write_str("an HTML comment is not closed"),
            Self::UnclosedTag => f.write_str("a <nowiki> or <pre> element is not closed"),
            Self::UnclosedTemplate => f.write_str("a template is not closed"),
            Self::TooDeep => write!(f, "templates nested deeper than {MAX_DEPTH}"),
            Self::TooManyParams => write!(f, "a template with more than {MAX_SEGMENTS} parameters"),
            Self::TooManyTemplates => write!(f, "more than {MAX_TEMPLATES} templates"),
            Self::DuplicateTemplate(t) => write!(f, "{{{{{t}}}}} twice"),
            Self::DuplicateParam(t, k) => write!(f, "{{{{{t}}}}}: the parameter '{k}' twice"),
            Self::ValueTooLong(t, k) => {
                write!(
                    f,
                    "{{{{{t}}}}}: the value of '{k}' is longer than {MAX_VALUE} bytes"
                )
            }
        }
    }
}

/// A template and the keys read from it.
#[derive(Debug, Clone, Copy)]
pub struct Wanted {
    /// The template's name as the wiki spells it (`Infobox game`).
    pub template: &'static str,
    /// The keys (`steam appid`).
    pub keys: &'static [&'static str],
}

/// What [`read`] found for one [`Wanted`]: `None` if the template is not on the page, else the
/// trimmed value of each key in order (`None`: the key is not there).
pub type Found = Option<Vec<Option<String>>>;

/// Reads `wanted` from `text` (module docs).
pub fn read(text: &str, wanted: &[Wanted]) -> Result<Vec<Found>, ScanError> {
    let clean = clean(text)?;
    let mut found: Vec<Found> = vec![None; wanted.len()];
    scan(&clean, &mut |name, params| {
        let Some(w) = wanted.iter().position(|w| same_name(name, w.template)) else {
            return Ok(());
        };
        let spec = wanted[w];
        if found[w].is_some() {
            return Err(ScanError::DuplicateTemplate(spec.template));
        }
        let mut values: Vec<Option<String>> = vec![None; spec.keys.len()];
        for (k, v) in params {
            if let Some(i) = spec.keys.iter().position(|x| *x == k) {
                if values[i].is_some() {
                    return Err(ScanError::DuplicateParam(spec.template, spec.keys[i]));
                }
                if v.len() > MAX_VALUE {
                    return Err(ScanError::ValueTooLong(spec.template, spec.keys[i]));
                }
                values[i] = Some(v.to_owned());
            }
        }
        found[w] = Some(values);
        Ok(())
    })?;
    Ok(found)
}

/// `a` names the template `b`: `_` is a space, the first letter's case ignored, ASCII white
/// space around it trimmed.
fn same_name(a: &str, b: &str) -> bool {
    let a = a
        .trim_matches(|c: char| c.is_ascii_whitespace())
        .replace('_', " ");
    let (mut x, mut y) = (a.chars(), b.chars());
    match (x.next(), y.next()) {
        (Some(p), Some(q)) => p.to_lowercase().eq(q.to_lowercase()) && x.eq(y),
        _ => false,
    }
}

fn starts_ci(b: &[u8], at: usize, pat: &[u8]) -> bool {
    b.get(at..at + pat.len())
        .is_some_and(|s| s.eq_ignore_ascii_case(pat))
}

/// The first `pat` (ASCII, case ignored) at or after `from`.
fn find_ci(b: &[u8], from: usize, pat: &[u8]) -> Option<usize> {
    (from..b.len().saturating_sub(pat.len() - 1)).find(|&i| starts_ci(b, i, pat))
}

/// An opening `<nowiki…>` or `<pre…>` tag at `at`: its closing tag, where the opening tag ends
/// (exclusive) and whether it closes itself.
fn opaque_tag(b: &[u8], at: usize) -> Option<(&'static [u8], usize, bool)> {
    for (name, close) in [
        (&b"nowiki"[..], &b"</nowiki>"[..]),
        (&b"pre"[..], &b"</pre>"[..]),
    ] {
        if !starts_ci(b, at + 1, name) {
            continue;
        }
        let after = at + 1 + name.len();
        if !b
            .get(after)
            .is_some_and(|c| *c == b'>' || *c == b'/' || c.is_ascii_whitespace())
        {
            continue;
        }
        let end = (after..b.len().min(after + MAX_TAG)).find(|&i| b[i] == b'>')?;
        return Some((close, end + 1, b[end - 1] == b'/'));
    }
    None
}

/// Pass 1 (module docs).
fn clean(t: &str) -> Result<String, ScanError> {
    let b = t.as_bytes();
    let mut out = String::with_capacity(t.len());
    let (mut i, mut copied) = (0, 0);
    while let Some(off) = b[i..].iter().position(|c| *c == b'<') {
        let at = i + off;
        // Every slice boundary below is at an ASCII byte, so on a char boundary.
        if b[at..].starts_with(b"<!--") {
            out.push_str(&t[copied..at]);
            let end = find_ci(b, at + 4, b"-->").ok_or(ScanError::UnclosedComment)?;
            i = end + 3;
            copied = i;
        } else if let Some((close, end, closes_itself)) = opaque_tag(b, at) {
            out.push_str(&t[copied..at]);
            out.push(OPAQUE);
            i = if closes_itself {
                end
            } else {
                find_ci(b, end, close).ok_or(ScanError::UnclosedTag)? + close.len()
            };
            copied = i;
        } else {
            i = at + 1;
        }
    }
    out.push_str(&t[copied..]);
    Ok(out)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Open {
    Template,
    Link,
}

fn trim(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_ascii_whitespace())
}

/// A segment of the open top-level template: where it starts, and its first `=` at the
/// template's level.
type Seg = (usize, Option<usize>);

/// A top-level template's name and named parameters, to the caller of [`scan`].
type Each<'f> = dyn FnMut(&str, Vec<(&str, &str)>) -> Result<(), ScanError> + 'f;

/// Pass 2 (module docs): calls `each(name, named parameters)` for every top-level template.
fn scan(t: &str, each: &mut Each<'_>) -> Result<(), ScanError> {
    let b = t.as_bytes();
    let mut stack: Vec<Open> = Vec::new();
    let mut segs: Vec<Seg> = Vec::new();
    let mut templates = 0usize;
    let mut i = 0;
    while i < b.len() {
        let pair = (b[i], b.get(i + 1).copied());
        match pair {
            (b'{', Some(b'{')) => {
                if stack.len() >= MAX_DEPTH {
                    return Err(ScanError::TooDeep);
                }
                if stack.is_empty() {
                    templates += 1;
                    if templates > MAX_TEMPLATES {
                        return Err(ScanError::TooManyTemplates);
                    }
                    segs.clear();
                    segs.push((i + 2, None));
                }
                stack.push(Open::Template);
                i += 2;
            }
            (b'[', Some(b'[')) if !stack.is_empty() => {
                if stack.len() >= MAX_DEPTH {
                    return Err(ScanError::TooDeep);
                }
                stack.push(Open::Link);
                i += 2;
            }
            (b']', Some(b']')) if stack.last() == Some(&Open::Link) => {
                stack.pop();
                i += 2;
            }
            (b'}', Some(b'}')) if !stack.is_empty() => {
                // Links left open inside the template end with it.
                while stack.last() == Some(&Open::Link) {
                    stack.pop();
                }
                stack.pop();
                if stack.is_empty() {
                    let mut params = Vec::new();
                    let ends: Vec<usize> =
                        segs.iter().skip(1).map(|s| s.0 - 1).chain([i]).collect();
                    let name = trim(&t[segs[0].0..ends[0]]);
                    for (s, end) in segs.iter().zip(&ends).skip(1) {
                        if let (start, Some(eq)) = *s {
                            params.push((trim(&t[start..eq]), trim(&t[eq + 1..*end])));
                        }
                    }
                    each(name, params)?;
                }
                i += 2;
            }
            (b'|', _) if stack.len() == 1 => {
                if segs.len() >= MAX_SEGMENTS {
                    return Err(ScanError::TooManyParams);
                }
                segs.push((i + 1, None));
                i += 1;
            }
            (b'=', _) if stack.len() == 1 => {
                // The name segment holds no `=` that counts.
                if segs.len() > 1
                    && let Some(last) = segs.last_mut()
                    && last.1.is_none()
                {
                    last.1 = Some(i);
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    if stack.is_empty() {
        Ok(())
    } else {
        Err(ScanError::UnclosedTemplate)
    }
}

#[cfg(test)]
mod tests;
