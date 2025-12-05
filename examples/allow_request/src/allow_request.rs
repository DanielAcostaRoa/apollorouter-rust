use std::ops::ControlFlow;
use std::path::PathBuf;

use apollo_router::layers::ServiceBuilderExt;
use apollo_router::plugin::PluginInit;
use apollo_router::plugin::Plugin;
use apollo_router::register_plugin;
use apollo_router::services::supergraph;
use http::StatusCode;
use schemars::JsonSchema;
use serde::Deserialize;
use tower::BoxError;
use tower::ServiceBuilder;
use tower::ServiceExt;

use acme_router::functions::authenticate;
use acme_router::functions::error_response;
use acme_router::functions::introspection;

#[derive(Deserialize, JsonSchema)]
struct AllowRequestConfig {
    introspection: bool,
    path: String,
    public_key_path: String,
}

struct AllowRequest {
    introspection: bool,
    file_path: PathBuf,
    public_key_path: PathBuf,
}

#[async_trait::async_trait]
impl Plugin for AllowRequest {
    type Config = AllowRequestConfig;

    async fn new(init: PluginInit<Self::Config>) -> Result<Self, BoxError> {
        let AllowRequestConfig { path, introspection, public_key_path } = init.config;
        let file_path = PathBuf::from(path.as_str());
        let public_key_path = PathBuf::from(public_key_path.as_str());

        Ok(Self {
            introspection,
            file_path,
            public_key_path,
        })
    }

    fn supergraph_service(&self, service: supergraph::BoxService) -> supergraph::BoxService {
        let introspection_cfg = self.introspection.clone();
        let file_path = self.file_path.clone();
        let public_key_path = self.public_key_path.clone();

        let handler = move |mut req: supergraph::Request| {
            let mut res = None;
            let file_path = file_path.clone();
            let introspection_cfg = introspection_cfg.clone();
            let public_key_path = public_key_path.clone();

            async move {
                let query_opt = req.supergraph_request.body().query.clone();

                if let Some(ref query_string) = query_opt {
                    if introspection_cfg {
                        if !introspection(query_string) {
                            match authenticate(&req.supergraph_request.headers().clone(), &public_key_path.clone()) {
                                Ok(data) => {
                                    println!("Token data: {:#?}", data);
                                }
                                Err(error) => {
                                    println!("Error al obtener el token: {}", error);
                                    res = error_response(&error, StatusCode::UNAUTHORIZED, "UNAUTHORIZED", &req);
                                }
                            }
                        }
                    }
                } else {
                    res = error_response(
                        "Debes proporcionar una consulta válida",
                        StatusCode::BAD_REQUEST,
                        "GRAPHQL_ERROR",
                        &req
                    );
                }

                match res {
                    Some(res) => Ok(ControlFlow::Break(res)),
                    None => Ok(ControlFlow::Continue(req)),
                }
            }
        };

        ServiceBuilder::new().oneshot_checkpoint_async(handler).service(service).boxed()
    }
}

register_plugin!("auth", "allow_request", AllowRequest);
