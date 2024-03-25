use cosmian_kms_server::config::JwtAuthConfig;

// Test auth0 Config
pub const AUTH0_JWT_ISSUER_URI: &str = "https://kms-cosmian.eu.auth0.com/";
pub const AUTH0_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjVVU1FrSVlULW9QMWZrcjQtNnRrciJ9.eyJuaWNrbmFtZSI6InRlY2giLCJuYW1lIjoidGVjaEBjb3NtaWFuLmNvbSIsInBpY3R1cmUiOiJodHRwczovL3MuZ3JhdmF0YXIuY29tL2F2YXRhci81MmZiMzFjOGNjYWQzNDU4MTIzZDRmYWQxNDA4NTRjZj9zPTQ4MCZyPXBnJmQ9aHR0cHMlM0ElMkYlMkZjZG4uYXV0aDAuY29tJTJGYXZhdGFycyUyRnRlLnBuZyIsInVwZGF0ZWRfYXQiOiIyMDIzLTA1LTMwVDA5OjMxOjExLjM4NloiLCJlbWFpbCI6InRlY2hAY29zbWlhbi5jb20iLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImlzcyI6Imh0dHBzOi8va21zLWNvc21pYW4uZXUuYXV0aDAuY29tLyIsImF1ZCI6IkszaXhldXhuVDVrM0Roa0tocWhiMXpYbjlFNjJGRXdJIiwiaWF0IjoxNjg1NDM5MDc0LCJleHAiOjE2ODU0NzUwNzQsInN1YiI6ImF1dGgwfDYzZDNkM2VhOTNmZjE2NDJjNzdkZjkyOCIsInNpZCI6ImJnVUNuTTNBRjVxMlpaVHFxMTZwclBCMi11Z0NNaUNPIiwibm9uY2UiOiJVRUZWTlZWeVluWTVUbHBwWjJScGNqSmtVMEZ4TmxkUFEwc3dTVGMwWHpaV2RVVmtkVnBEVGxSMldnPT0ifQ.HmU9fFwZ-JjJVlSy_PTei3ys0upeWQbWWiESmKBtRSClGnAXJNCpwuP4Jw7fgKn-8IBf-PYmP1_54u2Rw3RcJFVl7EblVoGMghYxVq5hViGpd00st3VwZmyCwOUz2CE5RBnBAoES4C8xA3zWg6oau0xjFQbC3jNU20eyFYMDewXA8UXCHQrEiQ56ylqSbyqlBbQIWbmOO4m5w2WDkx0bVyyJ893JfIJr_NANEQMJITYo8Mp_iHCyKp7llsfgCt07xN8ZqnsrMsJ15zC1n50bHGrTQisxURS1dpuFXF1hfrxhzogxYMX8CEISjsFgROjPY84GRMmvpYZfyaJbDDql3A";

pub fn get_auth0_jwt_config() -> JwtAuthConfig {
    JwtAuthConfig {
        jwt_issuer_uri: Some(AUTH0_JWT_ISSUER_URI.to_owned()),
        jwks_uri: None,
        jwt_audience: None,
    }
}
