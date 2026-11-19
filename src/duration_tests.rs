use std::time::Duration;

use crate::config::duration::parse_duration;

#[test]
fn positive_durations_preserve_units_fractions_and_rounding() {
    for (input, nanos) in [
        ("1ns", 1),
        ("1us", 1_000),
        ("1\u{00b5}s", 1_000),
        ("1\u{03bc}s", 1_000),
        ("1ms", 1_000_000),
        ("1s", 1_000_000_000),
        ("1m", 60_000_000_000),
        ("1h", 3_600_000_000_000),
        ("1h2m3.004005006s", 3_723_004_005_006),
        ("+.5s", 500_000_000),
        ("1.s", 1_000_000_000),
        ("0s1ns", 1),
        ("0.0000000009s1ns", 1),
        ("0.9999999999999999999ns", 1),
        ("0.999999999999999999999999999999s", 1_000_000_000),
        ("2562047h47m16.854775807s", i64::MAX as u64),
    ] {
        assert_eq!(
            parse_duration(input),
            Some(Duration::from_nanos(nanos)),
            "{input}"
        );
    }
}

#[test]
fn invalid_zero_and_overflowing_durations_are_rejected() {
    for input in [
        "",
        "+",
        "0",
        "0s",
        "0.1ns",
        "-1s",
        "1d",
        "1",
        "1 s",
        " 1s",
        "1s ",
        ".s",
        "1..2s",
        "1e3s",
        "++1s",
        "1s+1s",
        "1s-1s",
        "1S",
        "1\u{03bc}",
        "2562047h47m16.854775808s",
        "9223372036854775807ns1ns",
        "18446744073709551616ns",
        "18446744073709551615h",
        "9223372036854775807ns9223372036854775809ns",
    ] {
        assert_eq!(parse_duration(input), None, "{input:?}");
    }
}
