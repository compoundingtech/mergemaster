//! CPython 3.14.7 tomllib/_re.py temporal matching without a regex dependency.
use super::{Date, Error, Source, Time, Value};

impl Source {
    pub fn temporal(&self, position: usize) -> Result<Option<(usize, Value)>, Error> {
        let Some(text) = self.chars.get(position..) else {
            return Ok(None);
        };
        if let Some(date) = date_prefix(text) {
            let leap = date.year % 4 == 0 && (date.year % 100 != 0 || date.year % 400 == 0);
            let days = match date.month {
                2 => {
                    if leap {
                        29
                    } else {
                        28
                    }
                }
                4 | 6 | 9 | 11 => 30,
                _ => 31,
            };
            if date.year == 0 || date.day > days {
                return Err(self.error("Invalid date or datetime", position));
            }
            // The entire separator/time group is optional, not just its suffix.
            if matches!(text.get(10), Some('T' | 't' | ' '))
                && let Some((length, time)) = text.get(11..).and_then(time_prefix)
            {
                let end = 11 + length;
                let (offset_length, offset_minutes) = offset_prefix(&text[end..]);
                return Ok(Some((
                    position + end + offset_length,
                    Value::DateTime {
                        date,
                        time,
                        offset_minutes,
                    },
                )));
            }
            return Ok(Some((position + 10, Value::Date(date))));
        }
        Ok(time_prefix(text).map(|(length, time)| (position + length, Value::Time(time))))
    }
}

fn decimal(text: &[char], width: usize) -> Option<u16> {
    let mut value = 0;
    for &c in text.get(..width)? {
        if !c.is_ascii_digit() {
            return None;
        }
        value = value * 10 + u16::try_from(u32::from(c) - u32::from('0')).ok()?;
    }
    Some(value)
}

fn pair(text: &[char], start: usize, maximum: u8) -> Option<u8> {
    let value = u8::try_from(decimal(text.get(start..)?, 2)?).ok()?;
    (value <= maximum).then_some(value)
}

fn date_prefix(text: &[char]) -> Option<Date> {
    let year = decimal(text, 4)?;
    if text.get(4) != Some(&'-') || text.get(7) != Some(&'-') {
        return None;
    }
    let month = pair(text, 5, 12)?;
    let day = pair(text, 8, 31)?;
    (month != 0 && day != 0).then_some(Date { year, month, day })
}

fn time_prefix(text: &[char]) -> Option<(usize, Time)> {
    if text.get(2) != Some(&':') || text.get(5) != Some(&':') {
        return None;
    }
    let hour = pair(text, 0, 23)?;
    let minute = pair(text, 3, 59)?;
    let second = pair(text, 6, 59)?;
    let mut end = 8;
    let mut microsecond = 0;
    // A dot with no following digit backtracks out of the whole fraction.
    if text.get(end) == Some(&'.') && text.get(end + 1).is_some_and(char::is_ascii_digit) {
        end += 1;
        let fraction = end;
        while let Some(&c) = text.get(end).filter(|c| c.is_ascii_digit()) {
            if end - fraction < 6 {
                microsecond = microsecond * 10 + u32::from(c) - u32::from('0');
            }
            end += 1;
        }
        for _ in (end - fraction)..6 {
            microsecond *= 10;
        }
    }
    Some((
        end,
        Time {
            hour,
            minute,
            second,
            microsecond,
        },
    ))
}

fn offset_prefix(text: &[char]) -> (usize, Option<i16>) {
    if matches!(text.first(), Some('Z' | 'z')) {
        return (1, Some(0));
    }
    if matches!(text.first(), Some('+' | '-'))
        && text.get(3) == Some(&':')
        && let (Some(hour), Some(minute)) = (pair(text, 1, 23), pair(text, 4, 59))
    {
        let minutes = i16::from(hour) * 60 + i16::from(minute);
        return (
            6,
            Some(if text.first() == Some(&'-') {
                -minutes
            } else {
                minutes
            }),
        );
    }
    (0, None)
}
