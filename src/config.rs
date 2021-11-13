pub struct Config {
    pub auth: Auth
}

pub struct Auth {
    pub ca_cert_file: String,
    pub cert_file: String,
    pub key_file: String
}