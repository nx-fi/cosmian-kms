use std::time::Duration;

use actix_web::cookie::time::OffsetDateTime;
use time::format_description::well_known::Rfc2822;
use tracing_log::log::warn;

// check every 1 hour
const ONE_HOUR: Duration = Duration::from_secs(60 * 60); // 1 hour

// include timeout datetime defined at compile-time (see `build.rs` file)
include!(concat!(env!("OUT_DIR"), "/demo_timeout.rs"));

/// # Panics
///
/// Will panic if automatically generated datetime cannot be stringified back
pub async fn demo_timeout() {
    loop {
        {
            let now = OffsetDateTime::now_utc();
            let end = OffsetDateTime::parse(
                &String::from_utf8(DEMO_TIMEOUT.to_vec())
                    .expect("should be ok to convert back to String"),
                &Rfc2822,
            )
            .expect("should be able to parse rfc2822 datetime");

            if now > end {
                warn!("Shutting down...");
                warn!("Demo version expired ! If you ❤️  this software please buy a license 🦀");
                warn!("Reach us at https://cosmian.com/contact-us");
                break
            }
        }
        actix_rt::time::sleep(ONE_HOUR).await;
    }
}
