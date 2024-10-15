use casbin::IEnforcer;
use salvo::prelude::*;
use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct CasbinVals {
    pub subject: String,
    pub domain: Option<String>,
}

#[derive(Clone)]
pub struct CasbinHoop<E, F> {
    enforcer: Arc<RwLock<E>>,
    use_enforcer_mut: bool,
    get_casbin_vals: F,
}

impl<E, F> Deref for CasbinHoop<E, F> {
    type Target = Arc<RwLock<E>>;

    fn deref(&self) -> &Self::Target {
        &self.enforcer
    }
}

impl<E, F> DerefMut for CasbinHoop<E, F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.enforcer
    }
}

#[handler]
impl<E, F> CasbinHoop<E, F>
where
    E: IEnforcer + 'static,
    F: Fn(&mut Request, &mut Depot) -> Result<Option<CasbinVals>, StatusError>
        + Send
        + Sync
        + 'static,
{
    pub fn new(enforcer: E, use_enforcer_mut: bool, get_casbin_vals: F) -> Self {
        CasbinHoop {
            enforcer: Arc::new(RwLock::new(enforcer)),
            use_enforcer_mut,
            get_casbin_vals,
        }
    }

    pub fn get_enforcer(&self) -> Arc<RwLock<E>> {
        self.enforcer.clone()
    }

    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        _ctrl: &mut FlowCtrl,
    ) {
        let vals = match (self.get_casbin_vals)(req, depot) {
            Ok(option_vals) => {
                let Some(vals) = option_vals else {
                    res.render(StatusError::unauthorized());
                    return;
                };
                vals
            }
            Err(err) => {
                res.render(err);
                return;
            }
        };

        let path = req.uri().path().to_string();
        let action = req.method().as_str().to_string();

        if vals.subject.is_empty() {
            res.render(StatusError::unauthorized());
            return;
        }

        let rvals = if let Some(domain) = vals.domain {
            vec![vals.subject, domain, path, action]
        } else {
            vec![vals.subject, path, action]
        };
        let r = if self.use_enforcer_mut {
            self.enforcer.write().await.enforce_mut(rvals)
        } else {
            self.enforcer.read().await.enforce(rvals)
        };
        match r {
            Ok(true) => {}
            Ok(false) => {
                res.render(StatusError::forbidden());
            }
            Err(_) => {
                res.render(StatusError::bad_gateway());
            }
        }
    }
}
