# salvo-casbin

[![Crates.io](https://img.shields.io/crates/d/salvo-casbin)](https://crates.io/crates/salvo-casbin)
[![Docs](https://docs.rs/salvo-casbin/badge.svg)](https://docs.rs/salvo-casbin)
[![CI](https://github.com/andeya/salvo-casbin/actions/workflows/ci.yml/badge.svg)](https://github.com/andeya/salvo-casbin/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/andeya/salvo-casbin/branch/main/graph/badge.svg)](https://codecov.io/gh/andeya/salvo-casbin)

[Casbin](https://github.com/casbin/casbin-rs) access control hoop for [salvo](https://github.com/salvo-rs/salvo) framework

## Install

Add dependencies to `Cargo.toml`

```bash
cargo add salvo
cargo add salvo-casbin
cargo add tokio --features full
```

## Requirement

**Casbin only takes charge of permission control**, so you need to implement an `Authentication Middleware` to identify user.

For example:
```rust
use casbin::function_map::key_match2;
use casbin::{CoreApi, DefaultModel, Enforcer, FileAdapter};
use salvo::prelude::*;
use salvo_casbin::{CasbinHoop, CasbinVals};

// Handler that immediately returns an empty `200 OK` response.
#[handler]
async fn handler() {}

#[tokio::main]
async fn main() {
    let m = DefaultModel::from_file("examples/rbac_with_pattern_model.conf")
        .await
        .unwrap();

    let a = FileAdapter::new("examples/rbac_with_pattern_policy.csv");

    let casbin_hoop = CasbinHoop::new(Enforcer::new(m, a).await.unwrap(), |_req, _depot| {
        Ok(Some(CasbinVals {
            subject: String::from("alice"),
            domain: None,
        }))
    })
    .await
    .unwrap();

    casbin_hoop
        .write()
        .await
        .get_role_manager()
        .write()
        .matching_fn(Some(key_match2), None);

    let app = Router::new()
        .hoop(casbin_hoop)
        .push(Router::with_path("/pen/1").get(handler))
        .push(Router::with_path("/pen/2").get(handler))
        .push(Router::with_path("/book/<id>").get(handler));
    
    let acceptor = TcpListener::new("127.0.0.1:5800").bind().await;
    Server::new(acceptor).serve(app).await;
}
```

## License

This project is licensed under

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0))
