use std::ops::ControlFlow;
use std::path::PathBuf;

use apollo_router::layers::ServiceBuilderExt;
use apollo_router::plugin::Plugin;
use apollo_router::plugin::PluginInit;
use apollo_router::register_plugin;
use apollo_router::services::supergraph;
use http::StatusCode;
use http::HeaderValue;
use base64::decode;
use schemars::JsonSchema;
use serde::Deserialize;
use tower::BoxError;
use tower::ServiceBuilder;
use tower::ServiceExt;

use acme_router::plugin_functions::validate_operation;
use acme_router::plugin_functions::error_response;

#[derive(Deserialize, JsonSchema)]
struct AllowAppConfig {
    header: String,
    path: String,
}

#[derive(Debug, serde::Deserialize)]
struct Payload {
    _id: String,
    iss: String,
}

struct AllowApp {
    header: String,
    file_path: PathBuf,
}

#[async_trait::async_trait]
impl Plugin for AllowApp {
    type Config = AllowAppConfig;

    async fn new(init: PluginInit<Self::Config>) -> Result<Self, BoxError> {
        let AllowAppConfig { path, header } = init.config;
        let file_path = PathBuf::from(path.as_str());

        Ok(Self {
            file_path,
            header,
        })
    }

    fn supergraph_service(&self, service: supergraph::BoxService) -> supergraph::BoxService {
        let header_key = self.header.clone();
        let file_path = self.file_path.clone();

        let handler = move |mut req: supergraph::Request| {
            let mut res = None;
            //Get query from the body
            let query = &req.supergraph_request.body().query;

            match query {
                Some(query_string) => {
                    // First it is checked if the request has the Authorization header
                    if !req.supergraph_request.headers().contains_key(&header_key) {
                        res = error_response(
                            "No se ha recibido el encabezado" + header_key,
                            StatusCode::UNAUTHORIZED,
                            "AUTH_ERROR",
                            &req
                        );
                    } else {
                        // Get token from the Authorization header
                        let token = req.supergraph_request
                            .headers()
                            .get("Authorization")
                            .expect("No se pudo extraer el token de la petición")
                            .to_str();

                        match token {
                            Ok(token) => {
                                let token_base_64: Vec<&str> = token.split('.').collect();

                                // Decode payload from jwt
                                match decode(token_base_64[1]) {
                                    Ok(decoded_bytes) => {
                                        let payload = String::from_utf8(decoded_bytes).expect(
                                            "Error al validar access Token"
                                        );

                                        // Cast to Payload
                                        if
                                            let Ok(payload_data) = serde_json::from_str::<Payload>(
                                                &payload
                                            )
                                        {
                                            // Validate query to execute
                                            let valid_query = validate_operation(
                                                &payload_data.iss,
                                                query_string,
                                                file_path.clone()
                                            );

                                            match valid_query {
                                                Ok(app) => {
                                                    req.supergraph_request
                                                        .headers_mut()
                                                        .insert(
                                                            "appName",
                                                            HeaderValue::from_str(
                                                                &app.nombre
                                                            ).unwrap()
                                                        );
                                                }
                                                Err(err) => {
                                                    res = error_response(
                                                        err,
                                                        StatusCode::UNAUTHORIZED,
                                                        "UNAUTHORIZED",
                                                        &req
                                                    );
                                                }
                                            }
                                        } else {
                                            res = error_response(
                                                "Error al validar access Token",
                                                StatusCode::UNAUTHORIZED,
                                                "UNAUTHORIZED",
                                                &req
                                            );
                                        }
                                    }
                                    Err(_err) => {
                                        res = error_response(
                                            "Error al validar access Token",
                                            StatusCode::UNAUTHORIZED,
                                            "UNAUTHORIZED",
                                            &req
                                        );
                                    }
                                }
                            }
                            Err(_err) => {
                                res = error_response(
                                    "Error al validar access Token",
                                    StatusCode::UNAUTHORIZED,
                                    "UNAUTHORIZED",
                                    &req
                                );
                            }
                        }
                    }
                }
                None => {
                    res = error_response(
                        "Query is not present",
                        StatusCode::BAD_REQUEST,
                        "GRAPHQL_ERROR",
                        &req
                    );
                }
            }

            async {
                match res {
                    Some(res) => Ok(ControlFlow::Break(res)),
                    None => Ok(ControlFlow::Continue(req)),
                }
            }
        };

        ServiceBuilder::new().oneshot_checkpoint_async(handler).service(service).boxed()
    }
}

register_plugin!("apps", "allow_app", AllowApp);
