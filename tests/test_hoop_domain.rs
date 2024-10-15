use std::sync::Arc;

use casbin::{CoreApi, DefaultModel, Enforcer, FileAdapter};
use salvo::prelude::*;
use salvo::test::TestClient;
use salvo_casbin::{CasbinHoop, CasbinVals};

// Handler that immediately returns an empty `200 OK` response.
#[handler]
async fn handler() {}

#[tokio::test]
async fn test_hoop_domain() {
    let m = DefaultModel::from_file("examples/rbac_with_domains_model.conf")
        .await
        .unwrap();
    let a = FileAdapter::new("examples/rbac_with_domains_policy.csv");

    let casbin_hoop = CasbinHoop::new(Enforcer::new(m, a).await.unwrap(), false, |_req, _depot| {
        Ok(Some(CasbinVals {
            subject: String::from("alice"),
            domain: Some(String::from("domain1")),
        }))
    });

    let app = Router::new()
        .hoop(casbin_hoop)
        .push(Router::with_path("/pen/1").get(handler))
        .push(Router::with_path("/book/1").get(handler));
    let app = Arc::new(app);

    let resp_pen = TestClient::get("http://127.0.0.1:5800/pen/1")
        .send(app.clone())
        .await;
    assert_eq!(resp_pen.status_code.unwrap_or_default(), StatusCode::OK);

    let resp_book = TestClient::get("http://127.0.0.1:5800/book/1")
        .send(app.clone())
        .await;
    assert_eq!(
        resp_book.status_code.unwrap_or_default(),
        StatusCode::FORBIDDEN
    );
}
