use once_cell::sync::Lazy;

pub(crate) mod http;
pub(crate) mod tcp;
pub(crate) mod tls;

pub(crate) fn is_valid_domain(domain: &str) -> bool {
    if domain == "." {
        return true;
    }

    static RE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new("^([a-zA-Z0-9_-]{1,63})(\\.[a-zA-Z0-9_-]{1,63})*\\.?$").unwrap()
    });

    RE.is_match(domain)
}
