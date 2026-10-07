//! LombokSecurity core (Rust reference, `no_std + alloc`, zero dependencies).
//!
//! SHA-256, HMAC, CSRF tokens, security headers and CSP, HTML escaping, open-redirect
//! protection, password policy and rate limiting. Output is identical to the other ports for
//! every vector in `vectors/lomboksecurity-vectors-v1.json`; the normative contract is
//! `docs/SPEC_LombokSecurity_v0.1.0.md`. Randomness and time are supplied by the caller.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod crypto;
pub mod json;

pub use json::{parse_json, Value};

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

const MAX_SAFE: u64 = 9007199254740991;

/// Error with a canonical `code` (contract) and an English message (not normative).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub code: &'static str,
    pub message: String,
}

impl Error {
    fn new(code: &'static str, message: &str) -> Self {
        Error {
            code,
            message: message.to_string(),
        }
    }
    /// Stable message id for translation through LombokLocale.
    pub fn message_id(&self) -> String {
        format!("lomboksecurity.error.{}", self.code)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

fn opt_err(m: &str) -> Error {
    Error::new("invalid_option", m)
}

// ---------------------------------------------------------------- hashing

/// Lowercase hex SHA-256.
pub fn sha256_hex(data: &[u8]) -> String {
    crypto::to_hex(&crypto::sha256(data))
}

/// Lowercase hex HMAC-SHA256.
pub fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    crypto::to_hex(&crypto::hmac_sha256(key, data))
}

/// Equality in time that depends only on the lengths.
pub fn timing_safe_equal(a: &[u8], b: &[u8]) -> bool {
    crypto::constant_time_eq(a, b)
}

// ---------------------------------------------------------------- CSRF

/// Minimum secret length in bytes.
pub const MIN_SECRET_BYTES: usize = 16;

fn check_secret(secret: &[u8]) -> Result<()> {
    if secret.len() < MIN_SECRET_BYTES {
        return Err(Error::new(
            "invalid_secret",
            "secret must be at least 16 bytes",
        ));
    }
    Ok(())
}

fn is_lower_hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn csrf_mac(secret: &[u8], nonce: &str, context: &str) -> String {
    hmac_sha256_hex(secret, format!("csrf|{}|{}", nonce, context).as_bytes())
}

/// Token `nonce.signature` for a caller-supplied 16-byte nonce (32 lowercase hex digits).
pub fn create_csrf_token(secret: &[u8], nonce_hex: &str, context: Option<&str>) -> Result<String> {
    check_secret(secret)?;
    if !is_lower_hex(nonce_hex, 32) {
        return Err(Error::new(
            "invalid_nonce",
            "nonce must be 32 lowercase hex digits",
        ));
    }
    Ok(format!(
        "{}.{}",
        nonce_hex,
        csrf_mac(secret, nonce_hex, context.unwrap_or(""))
    ))
}

/// True only for a well-formed token signed with `secret` for the same `context`.
pub fn verify_csrf_token(secret: &[u8], token: &str, context: Option<&str>) -> Result<bool> {
    check_secret(secret)?;
    let (nonce, sig) = match token.split_once('.') {
        Some(p) => p,
        None => return Ok(false),
    };
    if !is_lower_hex(nonce, 32) || !is_lower_hex(sig, 64) {
        return Ok(false);
    }
    let want = csrf_mac(secret, nonce, context.unwrap_or(""));
    Ok(crypto::constant_time_eq(want.as_bytes(), sig.as_bytes()))
}

// ---------------------------------------------------------------- headers and CSP

/// Default response headers in output order.
pub const DEFAULT_HEADERS: [(&str, &str); 7] = [
    (
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'",
    ),
    (
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains",
    ),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    (
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()",
    ),
];

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+.^_`|~-".contains(&b))
}

fn bad_header_value(s: &str) -> bool {
    s.chars().any(|c| {
        let u = c as u32;
        u <= 0x08 || (0x0a..=0x1f).contains(&u) || u == 0x7f
    })
}

/// Recommended headers as ordered pairs. Each override sets (`Some`) or removes (`None`) a
/// header; names match defaults ASCII case-insensitively and keep the default's position and
/// spelling; other names are appended.
pub fn security_headers(overrides: &[(&str, Option<&str>)]) -> Result<Vec<(String, String)>> {
    let mut out: Vec<(String, Option<String>)> = DEFAULT_HEADERS
        .iter()
        .map(|(n, v)| (n.to_string(), Some(v.to_string())))
        .collect();
    for (name, value) in overrides {
        if !is_token(name) {
            return Err(Error::new(
                "invalid_header",
                "header name is not an RFC 9110 token",
            ));
        }
        if let Some(v) = value {
            if bad_header_value(v) {
                return Err(Error::new(
                    "invalid_header",
                    "header value must not contain CR, LF or control characters",
                ));
            }
        }
        let v = value.map(|s| s.to_string());
        match out.iter_mut().find(|(n, _)| n.eq_ignore_ascii_case(name)) {
            Some(e) => e.1 = v,
            None => out.push((name.to_string(), v)),
        }
    }
    Ok(out
        .into_iter()
        .filter_map(|(n, v)| v.map(|v| (n, v)))
        .collect())
}

/// Value of one CSP directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CspValue {
    /// Directive without sources (`upgrade-insecure-requests`).
    Flag,
    /// Source expressions; an empty list also renders the name alone.
    Sources(Vec<String>),
}

fn is_directive(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn bad_source(s: &str) -> bool {
    s.is_empty()
        || s.chars()
            .any(|c| (c as u32) <= 0x20 || c as u32 == 0x7f || c == ';' || c == ',')
}

/// Serialize CSP directives in the given order.
pub fn build_csp(directives: &[(&str, CspValue)]) -> Result<String> {
    let mut parts = Vec::new();
    for (name, v) in directives {
        if !is_directive(name) {
            return Err(Error::new("invalid_csp", "invalid directive name"));
        }
        match v {
            CspValue::Flag => parts.push(name.to_string()),
            CspValue::Sources(src) => {
                if src.iter().any(|s| bad_source(s)) {
                    return Err(Error::new("invalid_csp", "invalid source expression"));
                }
                if src.is_empty() {
                    parts.push(name.to_string());
                } else {
                    parts.push(format!("{} {}", name, src.join(" ")));
                }
            }
        }
    }
    Ok(parts.join("; "))
}

// ---------------------------------------------------------------- output encoding and redirects

/// Escape `& < > " '` for HTML text and quoted attribute values.
pub fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// Options of [`safe_redirect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectOptions {
    pub allowed_hosts: Vec<String>,
    pub fallback: String,
}

impl Default for RedirectOptions {
    fn default() -> Self {
        RedirectOptions {
            allowed_hosts: Vec::new(),
            fallback: "/".to_string(),
        }
    }
}

fn unsafe_char(c: char) -> bool {
    (c as u32) <= 0x20 || c as u32 == 0x7f || c == '\\'
}

fn is_local_path(s: &str) -> bool {
    s.starts_with('/') && !s.starts_with("//") && !s.chars().any(unsafe_char)
}

impl RedirectOptions {
    /// Validate (hosts non-empty, fallback a local path).
    pub fn validate(&self) -> Result<()> {
        if self.allowed_hosts.iter().any(|h| h.is_empty()) {
            return Err(opt_err(
                "allowedHosts must be an array of non-empty strings",
            ));
        }
        if !is_local_path(&self.fallback) {
            return Err(opt_err("fallback must be a local path"));
        }
        Ok(())
    }
}

/// `target` when it is a local path or an allowed absolute http(s) URL; otherwise the fallback.
pub fn safe_redirect(target: &str, options: &RedirectOptions) -> Result<String> {
    options.validate()?;
    let fb = || Ok(options.fallback.clone());
    if target.is_empty() || target.chars().any(unsafe_char) {
        return fb();
    }
    if is_local_path(target) {
        return Ok(target.to_string());
    }
    let lower = target.to_ascii_lowercase();
    let rest = if lower.starts_with("http://") {
        &target[7..]
    } else if lower.starts_with("https://") {
        &target[8..]
    } else {
        return fb();
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.is_empty() || authority.contains('@') {
        return fb();
    }
    let (host, port) = if authority.starts_with('[') {
        match authority.find(']') {
            Some(i) => (&authority[..=i], &authority[i + 1..]),
            None => return fb(),
        }
    } else {
        match authority.find(':') {
            Some(i) => (&authority[..i], &authority[i..]),
            None => (authority, ""),
        }
    };
    if !port.is_empty() {
        let d = match port.strip_prefix(':') {
            Some(d) => d,
            None => return fb(),
        };
        if d.is_empty() || d.len() > 5 || !d.bytes().all(|b| b.is_ascii_digit()) {
            return fb();
        }
    }
    if host.is_empty() {
        return fb();
    }
    let h = host.to_ascii_lowercase();
    if options
        .allowed_hosts
        .iter()
        .any(|a| a.to_ascii_lowercase() == h)
    {
        Ok(target.to_string())
    } else {
        fb()
    }
}

// ---------------------------------------------------------------- passwords

/// Built-in list of very common passwords (compared after ASCII lowercasing).
pub const COMMON_PASSWORDS: [&str; 40] = [
    "123456",
    "123456789",
    "12345678",
    "1234567890",
    "password",
    "password1",
    "password123",
    "qwerty",
    "qwerty123",
    "qwertyuiop",
    "abc123",
    "111111",
    "000000",
    "iloveyou",
    "admin",
    "admin123",
    "welcome",
    "welcome1",
    "letmein",
    "monkey",
    "dragon",
    "football",
    "baseball",
    "sunshine",
    "princess",
    "master",
    "shadow",
    "superman",
    "trustno1",
    "passw0rd",
    "1q2w3e4r",
    "zaq12wsx",
    "changeme",
    "secret",
    "login",
    "starwars",
    "whatever",
    "123123",
    "654321",
    "1qaz2wsx",
];

/// Password policy; defaults follow NIST SP 800-63B (length and blocklist, no composition rules).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordPolicy {
    pub min_length: u64,
    pub max_length: u64,
    pub require_lowercase: bool,
    pub require_uppercase: bool,
    pub require_digit: bool,
    pub require_symbol: bool,
    pub max_repeat: u64,
    pub blocklist: bool,
    pub extra_blocklist: Vec<String>,
    pub user_inputs: Vec<String>,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        PasswordPolicy {
            min_length: 12,
            max_length: 128,
            require_lowercase: false,
            require_uppercase: false,
            require_digit: false,
            require_symbol: false,
            max_repeat: 0,
            blocklist: true,
            extra_blocklist: Vec::new(),
            user_inputs: Vec::new(),
        }
    }
}

fn is_symbol(c: char) -> bool {
    matches!(c, '!'..='/' | ':'..='@' | '['..='`' | '{'..='~')
}

/// Violated rules in fixed order; empty when the password satisfies the policy.
pub fn check_password(password: &str, p: &PasswordPolicy) -> Result<Vec<&'static str>> {
    if p.min_length < 1 || p.max_length < 1 || p.min_length > p.max_length {
        return Err(opt_err("invalid length bounds"));
    }
    let cps: Vec<char> = password.chars().collect();
    let n = cps.len() as u64;
    let mut v = Vec::new();
    if n < p.min_length {
        v.push("too_short");
    }
    if n > p.max_length {
        v.push("too_long");
    }
    if p.require_lowercase && !cps.iter().any(|c| c.is_ascii_lowercase()) {
        v.push("missing_lowercase");
    }
    if p.require_uppercase && !cps.iter().any(|c| c.is_ascii_uppercase()) {
        v.push("missing_uppercase");
    }
    if p.require_digit && !cps.iter().any(|c| c.is_ascii_digit()) {
        v.push("missing_digit");
    }
    if p.require_symbol && !cps.iter().any(|c| is_symbol(*c)) {
        v.push("missing_symbol");
    }
    if p.max_repeat > 0 {
        let mut run = 1u64;
        for i in 1..cps.len() {
            run = if cps[i] == cps[i - 1] { run + 1 } else { 1 };
            if run > p.max_repeat {
                v.push("repeated_characters");
                break;
            }
        }
    }
    let lower = password.to_ascii_lowercase();
    if (p.blocklist && COMMON_PASSWORDS.contains(&lower.as_str()))
        || p.extra_blocklist
            .iter()
            .any(|e| e.to_ascii_lowercase() == lower)
    {
        v.push("common_password");
    }
    if p.user_inputs
        .iter()
        .any(|u| u.chars().count() >= 3 && lower.contains(u.to_ascii_lowercase().as_str()))
    {
        v.push("contains_user_input");
    }
    Ok(v)
}

// ---------------------------------------------------------------- rate limiting

/// Outcome of one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateResult {
    pub allowed: bool,
    pub remaining: u64,
    /// Milliseconds until a request can succeed; 0 when allowed.
    pub retry_after: u64,
}

/// State of a fixed window limiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedWindowState {
    pub window_start: u64,
    pub count: u64,
}

fn check_pos(v: u64, what: &str) -> Result<u64> {
    if (1..=MAX_SAFE).contains(&v) {
        Ok(v)
    } else {
        Err(opt_err(&format!("{} must be an integer >= 1", what)))
    }
}

fn check_now(now: u64) -> Result<u64> {
    if now > MAX_SAFE {
        return Err(opt_err("now must be a non-negative integer"));
    }
    Ok(now)
}

/// Fixed window aligned to multiples of `window_ms`.
pub fn fixed_window(
    state: Option<FixedWindowState>,
    now: u64,
    limit: u64,
    window_ms: u64,
) -> Result<(RateResult, FixedWindowState)> {
    let limit = check_pos(limit, "limit")?;
    let window_ms = check_pos(window_ms, "windowMs")?;
    let t = check_now(now)?;
    let window_start = t - t % window_ms;
    let mut count = match state {
        Some(s) if s.window_start == window_start => s.count,
        _ => 0,
    };
    let allowed = count < limit;
    if allowed {
        count += 1;
    }
    Ok((
        RateResult {
            allowed,
            remaining: limit.saturating_sub(count),
            retry_after: if allowed {
                0
            } else {
                window_start + window_ms - t
            },
        },
        FixedWindowState {
            window_start,
            count,
        },
    ))
}

/// State of a token bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenBucketState {
    pub tokens: u64,
    pub updated_at: u64,
}

/// Token bucket configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenBucketConfig {
    pub capacity: u64,
    pub refill_tokens: u64,
    pub refill_interval_ms: u64,
    pub cost: u64,
}

/// Token bucket with integer refill: `refill_tokens` every `refill_interval_ms`.
pub fn token_bucket(
    state: Option<TokenBucketState>,
    now: u64,
    c: &TokenBucketConfig,
) -> Result<(RateResult, TokenBucketState)> {
    let capacity = check_pos(c.capacity, "capacity")?;
    let refill = check_pos(c.refill_tokens, "refillTokens")?;
    let interval = check_pos(c.refill_interval_ms, "refillIntervalMs")?;
    let cost = check_pos(c.cost, "cost")?;
    if cost > capacity {
        return Err(opt_err("cost must not exceed capacity"));
    }
    let t = check_now(now)?;
    let (mut tokens, mut updated_at) = match state {
        None => (capacity, t),
        Some(s) => (s.tokens.min(capacity), s.updated_at),
    };
    if t > updated_at {
        let intervals = (t - updated_at) / interval;
        tokens = capacity.min(tokens.saturating_add(intervals.saturating_mul(refill)));
        updated_at = if tokens == capacity {
            t
        } else {
            updated_at + intervals * interval
        };
    }
    let st = |tokens| TokenBucketState { tokens, updated_at };
    if tokens >= cost {
        tokens -= cost;
        return Ok((
            RateResult {
                allowed: true,
                remaining: tokens,
                retry_after: 0,
            },
            st(tokens),
        ));
    }
    let need = (cost - tokens + refill - 1) / refill;
    let elapsed = t.saturating_sub(updated_at);
    Ok((
        RateResult {
            allowed: false,
            remaining: tokens,
            retry_after: need * interval - elapsed,
        },
        st(tokens),
    ))
}

// ---------------------------------------------------------------- contract entry point

fn safe_u64(v: &Value) -> Option<u64> {
    match v {
        Value::Num(n) if (0.0..=MAX_SAFE as f64).contains(n) && *n == (*n as u64) as f64 => {
            Some(*n as u64)
        }
        _ => None,
    }
}

fn bytes_of(v: Option<&Value>) -> Result<Vec<u8>> {
    match v {
        Some(Value::Str(s)) => Ok(s.as_bytes().to_vec()),
        Some(o @ Value::Obj(m)) if m.len() == 1 => match o.get("hex") {
            Some(Value::Str(h)) => {
                crypto::from_hex(h).ok_or_else(|| Error::new("invalid_input", "invalid hex"))
            }
            _ => Err(Error::new("invalid_input", "expected a string or bytes")),
        },
        _ => Err(Error::new("invalid_input", "expected a string or bytes")),
    }
}

fn context_of(v: Option<&Value>) -> Result<Option<&str>> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Str(s)) => Ok(Some(s)),
        _ => Err(Error::new("invalid_input", "context must be a string")),
    }
}

fn str_list(v: &Value, what: &str, non_empty: bool) -> Result<Vec<String>> {
    let a = v.as_arr().ok_or_else(|| opt_err(what))?;
    a.iter()
        .map(|x| match x {
            Value::Str(s) if !(non_empty && s.is_empty()) => Ok(s.clone()),
            _ => Err(opt_err(what)),
        })
        .collect()
}

fn policy_of(v: Option<&Value>) -> Result<PasswordPolicy> {
    let mut p = PasswordPolicy::default();
    let v = match v {
        None | Some(Value::Null) => return Ok(p),
        Some(v) => v,
    };
    let m = v
        .as_obj()
        .ok_or_else(|| opt_err("policy must be an object"))?;
    const KEYS: [&str; 10] = [
        "minLength",
        "maxLength",
        "requireLowercase",
        "requireUppercase",
        "requireDigit",
        "requireSymbol",
        "maxRepeat",
        "blocklist",
        "extraBlocklist",
        "userInputs",
    ];
    for (k, _) in m {
        if !KEYS.contains(&k.as_str()) {
            return Err(opt_err("unknown policy key"));
        }
    }
    let int = |k: &str, d: u64, min: u64| -> Result<u64> {
        match v.get(k) {
            None => Ok(d),
            Some(x) => match safe_u64(x) {
                Some(n) if n >= min => Ok(n),
                _ => Err(opt_err("integer option out of range")),
            },
        }
    };
    let boolean = |k: &str, d: bool| -> Result<bool> {
        match v.get(k) {
            None => Ok(d),
            Some(Value::Bool(b)) => Ok(*b),
            Some(_) => Err(opt_err("boolean option expected")),
        }
    };
    p.min_length = int("minLength", 12, 1)?;
    p.max_length = int("maxLength", 128, 1)?;
    if p.min_length > p.max_length {
        return Err(opt_err("minLength is greater than maxLength"));
    }
    p.require_lowercase = boolean("requireLowercase", false)?;
    p.require_uppercase = boolean("requireUppercase", false)?;
    p.require_digit = boolean("requireDigit", false)?;
    p.require_symbol = boolean("requireSymbol", false)?;
    p.max_repeat = int("maxRepeat", 0, 0)?;
    p.blocklist = boolean("blocklist", true)?;
    if let Some(x) = v.get("extraBlocklist") {
        p.extra_blocklist = str_list(x, "extraBlocklist must be an array of strings", false)?;
    }
    if let Some(x) = v.get("userInputs") {
        p.user_inputs = str_list(x, "userInputs must be an array of strings", false)?;
    }
    Ok(p)
}

fn redirect_options_of(v: Option<&Value>) -> Result<RedirectOptions> {
    let mut o = RedirectOptions::default();
    let v = match v {
        None | Some(Value::Null) => return Ok(o),
        Some(v) => v,
    };
    let m = v
        .as_obj()
        .ok_or_else(|| opt_err("options must be an object"))?;
    for (k, _) in m {
        if k != "allowedHosts" && k != "fallback" {
            return Err(opt_err("unknown option"));
        }
    }
    if let Some(a) = v.get("allowedHosts") {
        o.allowed_hosts = str_list(
            a,
            "allowedHosts must be an array of non-empty strings",
            true,
        )?;
    }
    if let Some(f) = v.get("fallback") {
        match f {
            Value::Str(s) if is_local_path(s) => o.fallback = s.clone(),
            _ => return Err(opt_err("fallback must be a local path")),
        }
    }
    Ok(o)
}

fn rate_value(r: &RateResult) -> Value {
    let mut o = Value::Obj(Vec::new());
    o.set("allowed", Value::Bool(r.allowed));
    o.set("remaining", Value::Num(r.remaining as f64));
    o.set("retryAfter", Value::Num(r.retry_after as f64));
    o
}

fn cfg_int(c: &Value, k: &str) -> Result<u64> {
    match c.get(k).and_then(safe_u64) {
        Some(n) if n >= 1 => Ok(n),
        _ => Err(opt_err("config value must be an integer >= 1")),
    }
}

fn simulate(kind: Option<&Value>, config: Option<&Value>, times: Option<&Value>) -> Result<Value> {
    let kind = match kind {
        Some(Value::Str(k)) if k == "fixedWindow" || k == "tokenBucket" => k.as_str(),
        _ => return Err(opt_err("kind must be fixedWindow or tokenBucket")),
    };
    let times = times
        .and_then(|t| t.as_arr())
        .ok_or_else(|| opt_err("times must be an array"))?;
    let mut out = Vec::new();
    let mut fw: Option<FixedWindowState> = None;
    let mut tb: Option<TokenBucketState> = None;
    for now in times {
        let c = match config {
            Some(c @ Value::Obj(_)) => c,
            _ => return Err(opt_err("config must be an object")),
        };
        if kind == "fixedWindow" {
            let limit = cfg_int(c, "limit")?;
            let window = cfg_int(c, "windowMs")?;
            let t = safe_u64(now).ok_or_else(|| opt_err("now must be a non-negative integer"))?;
            let (r, s) = fixed_window(fw, t, limit, window)?;
            fw = Some(s);
            out.push(rate_value(&r));
        } else {
            let cfg = TokenBucketConfig {
                capacity: cfg_int(c, "capacity")?,
                refill_tokens: cfg_int(c, "refillTokens")?,
                refill_interval_ms: cfg_int(c, "refillIntervalMs")?,
                cost: if c.get("cost").is_none() {
                    1
                } else {
                    cfg_int(c, "cost")?
                },
            };
            if cfg.cost > cfg.capacity {
                return Err(opt_err("cost must not exceed capacity"));
            }
            let t = safe_u64(now).ok_or_else(|| opt_err("now must be a non-negative integer"))?;
            let (r, s) = token_bucket(tb, t, &cfg)?;
            tb = Some(s);
            out.push(rate_value(&r));
        }
    }
    Ok(Value::Arr(out))
}

/// Dynamic entry point with the contract's JSON calling convention; `{"hex": "..."}` denotes bytes.
pub fn call(func: &str, args: &[Value]) -> Result<Value> {
    let a = |i: usize| args.get(i);
    let s = |x: String| Value::Str(x);
    match func {
        "sha256Hex" => Ok(s(sha256_hex(&bytes_of(a(0))?))),
        "hmacSha256Hex" => {
            let k = bytes_of(a(0))?;
            let d = bytes_of(a(1))?;
            Ok(s(hmac_sha256_hex(&k, &d)))
        }
        "timingSafeEqual" => {
            let x = bytes_of(a(0))?;
            let y = bytes_of(a(1))?;
            Ok(Value::Bool(timing_safe_equal(&x, &y)))
        }
        "createCsrfToken" => {
            let secret = bytes_of(a(0))?;
            check_secret(&secret)?;
            let nonce = match a(1) {
                Some(Value::Str(n)) => n.as_str(),
                _ => {
                    return Err(Error::new(
                        "invalid_nonce",
                        "nonce must be 32 lowercase hex digits",
                    ))
                }
            };
            if !is_lower_hex(nonce, 32) {
                return Err(Error::new(
                    "invalid_nonce",
                    "nonce must be 32 lowercase hex digits",
                ));
            }
            let ctx = context_of(a(2))?;
            create_csrf_token(&secret, nonce, ctx).map(s)
        }
        "verifyCsrfToken" => {
            let secret = bytes_of(a(0))?;
            check_secret(&secret)?;
            let ctx = context_of(a(2))?;
            match a(1) {
                Some(Value::Str(t)) => verify_csrf_token(&secret, t, ctx).map(Value::Bool),
                _ => Ok(Value::Bool(false)),
            }
        }
        "securityHeaders" => {
            let mut ov: Vec<(&str, Option<&str>)> = Vec::new();
            match a(0) {
                None | Some(Value::Null) => {}
                Some(o @ Value::Obj(_)) => {
                    for (k, v) in o.js_entries() {
                        if !is_token(k) {
                            return Err(Error::new(
                                "invalid_header",
                                "header name is not an RFC 9110 token",
                            ));
                        }
                        match v {
                            Value::Null => ov.push((k, None)),
                            Value::Str(x) => ov.push((k, Some(x))),
                            _ => {
                                return Err(Error::new(
                                    "invalid_header",
                                    "header value must be a string or null",
                                ))
                            }
                        }
                    }
                }
                Some(_) => return Err(opt_err("overrides must be an object")),
            }
            let h = security_headers(&ov)?;
            Ok(Value::Arr(
                h.into_iter()
                    .map(|(n, v)| Value::Arr(vec![Value::Str(n), Value::Str(v)]))
                    .collect(),
            ))
        }
        "buildCsp" => {
            let o = match a(0) {
                Some(o @ Value::Obj(_)) => o,
                _ => return Err(Error::new("invalid_csp", "directives must be an object")),
            };
            let mut d: Vec<(&str, CspValue)> = Vec::new();
            for (k, v) in o.js_entries() {
                if !is_directive(k) {
                    return Err(Error::new("invalid_csp", "invalid directive name"));
                }
                match v {
                    Value::Bool(true) => d.push((k, CspValue::Flag)),
                    Value::Arr(items) => {
                        let mut src = Vec::new();
                        for x in items {
                            match x {
                                Value::Str(t) if !bad_source(t) => src.push(t.clone()),
                                _ => {
                                    return Err(Error::new(
                                        "invalid_csp",
                                        "invalid source expression",
                                    ))
                                }
                            }
                        }
                        d.push((k, CspValue::Sources(src)));
                    }
                    _ => {
                        return Err(Error::new(
                            "invalid_csp",
                            "directive value must be an array or true",
                        ))
                    }
                }
            }
            build_csp(&d).map(s)
        }
        "escapeHtml" => match a(0) {
            Some(Value::Str(t)) => Ok(s(escape_html(t))),
            _ => Err(Error::new("invalid_input", "text must be a string")),
        },
        "safeRedirect" => {
            let o = redirect_options_of(a(1))?;
            match a(0) {
                Some(Value::Str(t)) => safe_redirect(t, &o).map(s),
                _ => Ok(s(o.fallback)),
            }
        }
        "checkPassword" => {
            let p = policy_of(a(1))?;
            match a(0) {
                Some(Value::Str(pw)) => Ok(Value::Arr(
                    check_password(pw, &p)?
                        .into_iter()
                        .map(|x| Value::Str(x.to_string()))
                        .collect(),
                )),
                _ => Err(Error::new("invalid_input", "password must be a string")),
            }
        }
        "simulateRateLimit" => simulate(a(0), a(1), a(2)),
        _ => Err(opt_err("unknown function")),
    }
}
