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

use acme_router::plugin_functions::validate_operation;
use acme_router::plugin_functions::get_operation_name;
use acme_router::plugin_functions::error_response;
use acme_router::plugin_functions::insert_header;
use acme_router::plugin_functions::get_payload;
use acme_router::plugin_functions::get_app;

#[derive(Deserialize, JsonSchema)]
struct AllowRequestConfig {
    introspection: bool,
    header: String,
    path: String,
}

struct AllowRequest {
    introspection: bool,
    header: String,
    file_path: PathBuf,
}

#[async_trait::async_trait]
impl Plugin for AllowRequest {
    type Config = AllowRequestConfig;

    async fn new(init: PluginInit<Self::Config>) -> Result<Self, BoxError> {
        let AllowRequestConfig { path, header, introspection } = init.config;
        let file_path = PathBuf::from(path.as_str());

        Ok(Self {
            introspection,
            file_path,
            header,
        })
    }

    fn supergraph_service(&self, service: supergraph::BoxService) -> supergraph::BoxService {
        let introspection = self.introspection.clone();
        let file_path = self.file_path.clone();
        let header_key = self.header.clone();

        let handler = move |mut req: supergraph::Request| {
            let mut res = None;

            //Get query from the body
            if let Some(query_string) = &req.supergraph_request.body().query {
                let mut operation_name = String::new();

                // Check if the introspection is enabled to allow query
                if introspection {
                    operation_name = get_operation_name(query_string);
                }

                if operation_name != "schema" {
                    // Check if the request has the Authorization header
                    if !req.supergraph_request.headers().contains_key(&header_key) {
                        res = error_response(
                            "No se ha recibido el encabezado de autorización",
                            StatusCode::UNAUTHORIZED,
                            "AUTH_ERROR",
                            &req
                        );
                    } else {
                        // Get token from the Authorization header
                        if
                            let Ok(token) = req.supergraph_request
                                .headers()
                                .get("Authorization")
                                .expect("No se pudo extraer el token de la petición")
                                .to_str()
                        {
                            //Get token Payload
                            match get_payload(&token) {
                                Ok(payload) => {
                                    if let Ok(app) = get_app(&payload.iss, file_path.clone()) {
                                        // Validate query to execute
                                        match validate_operation(&app.permissions, &payload.claims, query_string) {
                                            Ok(_query) => {
                                                insert_header(&mut req, "user_id", &payload._id);
                                                insert_header(&mut req, "app_id", &app._id);
                                                insert_header(&mut req, "app_name", &app.name);
                                                insert_header(&mut req, "app_url", &app.url);
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
                                            "Aplicación no registrada",
                                            StatusCode::UNAUTHORIZED,
                                            "UNAUTHORIZED",
                                            &req
                                        );
                                    }
                                }
                                Err(_err) => {
                                    let error_message = format!("Token de acceso no válido: {}", _err);
                                    res = error_response(
                                        &error_message,
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
                }
            } else {
                res = error_response(
                    "La consulta no puede estar vacía",
                    StatusCode::BAD_REQUEST,
                    "GRAPHQL_ERROR",
                    &req
                );
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

register_plugin!("auth", "allow_request", AllowRequest);
