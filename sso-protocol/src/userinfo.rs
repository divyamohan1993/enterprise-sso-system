use serde::Serialize;

#[derive(Serialize)]
pub struct UserInfo {
    pub sub: String,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub email: Option<String>,
}
