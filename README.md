# takaks
This is a simple TACACS+ protocol implementation, used in another project for a couple of years,
that I decided to open source.

The usage is very simple - the below code is the test executable:


```rust

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


```

And this is a relevant *tac_plus.conf* config snippet for a test user:

```

user = test1 {
  name = "Test User"
  login = cleartext "insecure"
}


```

