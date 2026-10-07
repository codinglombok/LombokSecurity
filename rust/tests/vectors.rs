//! Executes every case of vectors/lomboksecurity-vectors-v1.json (GP-11).
use lomboksecurity::{call, parse_json, Value};

fn vector_text() -> String {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../vectors/lomboksecurity-vectors-v1.json"
    );
    std::fs::read_to_string(p).expect("vectors file")
}

fn s(v: &Value) -> &str {
    v.as_str().expect("expected string")
}

#[test]
fn all_vectors_match() {
    let doc = parse_json(&vector_text()).expect("vectors parse");
    let groups = doc.get("groups").and_then(|g| g.as_arr()).expect("groups");
    let mut total = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for g in groups {
        for k in g.get("cases").and_then(|c| c.as_arr()).expect("cases") {
            total += 1;
            let name = s(k.get("name").unwrap());
            let func = s(k.get("fn").unwrap());
            let args = k.get("args").and_then(|a| a.as_arr()).expect("args");
            let expect = k.get("expect").unwrap();
            let got = call(func, args);
            match (expect.get("error"), got) {
                (Some(code), Err(e)) => {
                    if e.code != s(code) {
                        failures.push(format!("{}: error {} != {}", name, e.code, s(code)));
                    }
                }
                (Some(code), Ok(r)) => failures.push(format!(
                    "{}: expected error {} but got {}",
                    name,
                    s(code),
                    r.to_json()
                )),
                (None, Err(e)) => failures.push(format!("{}: unexpected error {}", name, e)),
                (None, Ok(r)) => {
                    let want = expect.get("result").unwrap().to_json();
                    if r.to_json() != want {
                        failures.push(format!(
                            "{}:\n  got      {}\n  expected {}",
                            name,
                            r.to_json(),
                            want
                        ));
                    }
                }
            }
        }
    }
    assert!(total >= 100, "GP-11 needs >= 100 cases, ran {}", total);
    assert!(
        failures.is_empty(),
        "{} of {} failed:\n{}",
        failures.len(),
        total,
        failures.join("\n")
    );
    println!("vectors executed: {}", total);
}

#[test]
fn malformed_json_is_rejected_without_panic() {
    for bad in [
        "",
        "{",
        "[1,]",
        "{\"a\":}",
        "\"\\ud800\"",
        "01",
        "1.",
        "nul",
        "{} x",
    ] {
        assert!(parse_json(bad).is_err(), "input {:?}", bad);
    }
    let deep = format!("{}1{}", "[".repeat(5000), "]".repeat(5000));
    assert!(parse_json(&deep).is_err());
}

#[test]
fn js_number_formatting() {
    for (n, t) in [
        (1.0, "1"),
        (0.5, "0.5"),
        (-3.0, "-3"),
        (1e21, "1e+21"),
        (1e20, "100000000000000000000"),
        (1e-7, "1e-7"),
        (0.000001, "0.000001"),
        (123456789012.0, "123456789012"),
        (-0.0, "0"),
        (1.5e300, "1.5e+300"),
        (5e-324, "5e-324"),
        (0.1 + 0.2, "0.30000000000000004"),
    ] {
        assert_eq!(Value::Num(n).to_json(), t);
    }
}

#[test]
fn crypto_known_answers() {
    use lomboksecurity::crypto::*;
    assert_eq!(
        to_hex(&sha1(b"abc")),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(
        to_hex(&sha1(b"")),
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    );
    assert_eq!(
        to_hex(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    // RFC 2202 test case 2 (HMAC-SHA1)
    assert_eq!(
        to_hex(&hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
        "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
    );
    // PBKDF2-HMAC-SHA256 published vectors (P="password", S="salt")
    assert_eq!(
        to_hex(&pbkdf2_sha256(b"password", b"salt", 1, 32)),
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
    );
    assert_eq!(
        to_hex(&pbkdf2_sha256(b"password", b"salt", 2, 32)),
        "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
    );
    assert_eq!(
        to_hex(&pbkdf2_sha256(b"password", b"salt", 4096, 32)),
        "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
    );
    assert_eq!(base64url(b"\xfb\xff"), "-_8");
    assert_eq!(base64(b"\xfb\xff"), "+/8=");
    assert_eq!(base64url_decode("-_8").unwrap(), b"\xfb\xff");
    assert!(base64url_decode("-_9").is_none(), "non-zero trailing bits");
    assert!(base64_decode("+/8").is_none(), "missing padding");
    assert!(from_hex("0g").is_none());
    assert!(constant_time_eq(b"", b""));
    assert!(!constant_time_eq(b"ab", b"abab"));
}

#[test]
fn redirect_never_panics_on_odd_authorities() {
    use lomboksecurity::{safe_redirect, RedirectOptions};
    let o = RedirectOptions {
        allowed_hosts: vec!["[::1]".into()],
        fallback: "/".into(),
    };
    for t in [
        "https://[::1]\u{e9}",
        "https://\u{e9}:",
        "http://a:\u{1F600}",
        "https://[",
        "https://]",
        "https://:",
    ] {
        let _ = safe_redirect(t, &o).unwrap();
    }
}

#[test]
fn readme_rust_example() {
    use lomboksecurity::{create_csrf_token, escape_html, verify_csrf_token};
    let secret = b"0123456789abcdef0123456789abcdef";
    let token = create_csrf_token(
        secret,
        "00112233445566778899aabbccddeeff",
        Some("session-1"),
    )
    .unwrap();
    assert!(verify_csrf_token(secret, &token, Some("session-1")).unwrap());
    assert_eq!(
        escape_html("<b>\"x\"</b>"),
        "&lt;b&gt;&quot;x&quot;&lt;/b&gt;"
    );
}
