use casbin::{IEnforcer, Result as CasbinResult};
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
    pub async fn new(enforcer: E, get_casbin_vals: F) -> CasbinResult<Self> {
        Ok(CasbinHoop {
            enforcer: Arc::new(RwLock::new(enforcer)),
            get_casbin_vals,
        })
    }

    pub fn get_enforcer(&mut self) -> Arc<RwLock<E>> {
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

        let subject = vals.subject.clone();
        let path = req.uri().path().to_string();
        let action = req.method().as_str().to_string();

        if !vals.subject.is_empty() {
            if let Some(domain) = vals.domain {
                let mut lock = self.enforcer.write().await;
                match lock.enforce_mut(vec![subject, domain, path, action]) {
                    Ok(true) => {
                        drop(lock);
                    }
                    Ok(false) => {
                        drop(lock);
                        res.render(StatusError::forbidden());
                    }
                    Err(_) => {
                        drop(lock);
                        res.render(StatusError::bad_gateway());
                    }
                }
            } else {
                let mut lock = self.enforcer.write().await;
                match lock.enforce_mut(vec![subject, path, action]) {
                    Ok(true) => {
                        drop(lock);
                    }
                    Ok(false) => {
                        drop(lock);
                        res.render(StatusError::forbidden());
                    }
                    Err(_) => {
                        drop(lock);
                        res.render(StatusError::bad_gateway());
                    }
                }
            }
        } else {
            res.render(StatusError::unauthorized());
        }
    }
}
