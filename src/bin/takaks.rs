extern crate takaks;
use std::env;

fn main() {
    let server = env::var("TACACS_SERVER").expect("TACACS_SERVER must be set");
    let secret = env::var("TACACS_SECRET").expect("TACACS_SECRET must be set");
    let test_user = env::var("TACACS_TEST_USER").expect("TACACS_TEST_USER must be set");
    let test_pass = env::var("TACACS_TEST_PASS").expect("TACACS_TEST_PASS must be set");

    match (takaks::TacacsPlusClient::new(&server, &secret)) {
        Ok(mut tc) => {
            let res = tc.AuthenticateUser(&test_user, &test_pass);
            println!("Auth result: {:?}", res);
        }
        Err(e) => {
            println!("Error setting up TACACS+ client: {:?}", &e);
        }
    }
}
