use std::time::{Duration, SystemTime};
use chrono::prelude::{DateTime, Utc};

pub fn format_u32_as_ctime(ctime: u32) -> String {
    let time = SystemTime::UNIX_EPOCH + Duration::from_secs(ctime as u64);
    let dt: DateTime<Utc> = time.into();

    return format!("{}", dt.format("%d/%m/%Y %H:%M"));
}
