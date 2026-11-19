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
        let mut nanos = integral.checked_mul(scale)?;

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
            nanos = nanos.checked_add((numerator as f64 * (scale as f64 / divisor)) as u64)?;
        }

        total = total.checked_add(nanos)?;
        if total > i64::MAX as u64 {
            return None;
        }
    }

    (total > 0).then(|| Duration::from_nanos(total))
}
