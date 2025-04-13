use coentro_vpn::config::Config;

#[test]
fn test_load_config_from_file() {
    let config = Config::builder()
        .add_source(config::File::with_name("Config.toml"))
        .build()
        .expect("Failed to load configuration");

    assert_eq!(config.get_string("mode").unwrap(), "server");
    assert_eq!(config.get_string("server_addr").unwrap(), "127.0.0.1");
    assert_eq!(config.get_int("udp.mtu").unwrap(), 1500);
}

#[test]
fn test_invalid_config_key() {
    let config = Config::builder()
        .add_source(config::File::with_name("Config.toml"))
        .build()
        .expect("Failed to load configuration");

    assert!(
        config.get_string("invalid_key").is_err(),
        "Invalid key should return an error"
    );
}
