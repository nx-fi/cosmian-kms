#!/bin/sh

reset

# cargo build

export TEST_GOOGLE_OAUTH_CLIENT_ID=764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com
export TEST_GOOGLE_OAUTH_CLIENT_SECRET=d-FL95Q19q7MQmFpd7hHD0Ty
export TEST_GOOGLE_OAUTH_REFRESH_TOKEN=1//03UPlZDb4OtpwCgYIARAAGAMSNwF-L9Ir8J7wICIWWsmXRVtSFdmOfTDoFpqCnk01jqPAoDHtW9nl3PC1nrYJD_68hgLuAda4FCg
cargo test -- --nocapture test_cse_private_key_decrypt
