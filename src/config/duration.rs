use std::time::Duration;

pub(crate) fn parse_duration(text: &str) -> Option<Duration> {
    let mut rest = text.strip_prefix('+').unwrap_or(text);
    let mut total = 0_u64;

    while !rest.is_empty() {
        let end = rest
            .bytes()
            .take_while(|byte| byte.is_ascii_digit() || *byte == b'.')
            .count();
        let number = &rest[..end];
        if !number.bytes().any(|byte| byte.is_ascii_digit()) {
            return None;
        }

        let mut parts = number.split('.');
        let whole = parts.next()?;
        let fraction = parts.next().unwrap_or("");
        if parts.next().is_some() {
            return None;
        }

        rest = &rest[end..];
        let (unit, scale) = [
            ("ns", 1_u64),
            ("us", 1_000),
            ("\u{00b5}s", 1_000),
            ("\u{03bc}s", 1_000),
            ("ms", 1_000_000),
            ("s", 1_000_000_000),
            ("m", 60_000_000_000),
            ("h", 3_600_000_000_000),
        ]
        .into_iter()
        .find(|(unit, _)| rest.starts_with(unit))?;
        rest = &rest[unit.len()..];

        let integral = if whole.is_empty() {
            0
        } else {
            whole.parse::<u64>().ok()?
        };
        let mut nanoseconds = integral.checked_mul(scale)?;

        // Match time.ParseDuration's bounded significand and floating-point scaling.
        let mut numerator = 0_u64;
        let mut divisor = 1_f64;
        for digit in fraction.bytes() {
            if numerator > i64::MAX as u64 / 10 {
                break;
            }
            let next = numerator * 10 + u64::from(digit - b'0');
            if next > 1_u64 << 63 {
                break;
            }
            numerator = next;
            divisor *= 10.0;
        }

        if numerator > 0 {
            nanoseconds =
                nanoseconds.checked_add((numerator as f64 * (scale as f64 / divisor)) as u64)?;
        }

        total = total.checked_add(nanoseconds)?;
        if total > i64::MAX as u64 {
            return None;
        }
    }

    (total > 0).then(|| Duration::from_nanos(total))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::config::duration::parse_duration;

    #[test]
    fn positive_durations_preserve_units_fractions_and_rounding() {
        for (input, nanoseconds) in [
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
                Some(Duration::from_nanos(nanoseconds)),
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
}
