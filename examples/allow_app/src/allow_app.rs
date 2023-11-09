use std::ops::ControlFlow;
use std::path::PathBuf;

use apollo_router::graphql;
use apollo_router::layers::ServiceBuilderExt;
use apollo_router::plugin::Plugin;
use apollo_router::plugin::PluginInit;
use apollo_router::register_plugin;
use apollo_router::services::supergraph;
use http::StatusCode;
use http::HeaderValue;
use schemars::JsonSchema;
use serde::Deserialize;
use tower::BoxError;
use tower::ServiceBuilder;
use tower::ServiceExt;

#[derive(Deserialize, JsonSchema)]
struct AllowAppConfig {
    header: String,
    path: String,
}

#[warn(dead_code)]
#[derive(Deserialize, JsonSchema, Debug, Clone)]
struct AppConfig {
    id: String,
    nombre: String,
    queries: Vec<String>,
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

            let query = &req.supergraph_request.body().query;
            match query {
                Some(query_string) => {
                    let ops: Vec<&str> = query_string.split('{').collect();
                    let op1: Vec<&str> = ops[1].split('(').collect();
                    let operation_name = &op1[0].replace(|c: char| !c.is_alphanumeric(), "");

                    if !req.supergraph_request.headers().contains_key(&header_key) {
                        res = Some(
                            supergraph::Response
                                ::error_builder()
                                .error(
                                    graphql::Error
                                        ::builder()
                                        .message(
                                            format!(
                                                "No se ha recibido el encabezado '{header_key}'"
                                            )
                                        )
                                        .extension_code("AUTH_ERROR")
                                        .build()
                                )
                                .status_code(StatusCode::UNAUTHORIZED)
                                .context(req.context.clone())
                                .build()
                                .expect("response is valid")
                        );
                    } else {
                        let app_id = req.supergraph_request
                            .headers()
                            .get("app-token")
                            .expect("No se pudo extraer el app-token de la petición")
                            .to_str();

                        match app_id {
                            Ok(app_id) => {
                                let apps: Vec<AppConfig> = serde_json
                                    ::from_str(
                                        std::fs::read_to_string(file_path.clone()).unwrap().as_str()
                                    )
                                    .unwrap();
                                if let Some(app) = apps.iter().find(|app| app.id == app_id) {
                                    let query_is_allowed = app.queries
                                        .iter()
                                        .any(|query| query == operation_name);
                                    if query_is_allowed {
                                        req.supergraph_request
                                            .headers_mut()
                                            .insert(
                                                "appName",
                                                HeaderValue::from_str(&app.nombre).unwrap()
                                            );
                                    } else {
                                        res = Some(
                                            supergraph::Response
                                                ::error_builder()
                                                .error(
                                                    graphql::Error
                                                        ::builder()
                                                        .message(
                                                            format!(
                                                                "No tienes permisos para ejecutar esta acción"
                                                            )
                                                        )
                                                        .extension_code("UNAUTHORIZED")
                                                        .build()
                                                )
                                                .status_code(StatusCode::FORBIDDEN)
                                                .context(req.context.clone())
                                                .build()
                                                .expect("response is valid")
                                        );
                                    }
                                } else {
                                    res = Some(
                                        supergraph::Response
                                            ::error_builder()
                                            .error(
                                                graphql::Error
                                                    ::builder()
                                                    .message(format!("Aplicación no registrada"))
                                                    .extension_code("BAD_CLIENT_ID")
                                                    .build()
                                            )
                                            .status_code(StatusCode::BAD_REQUEST)
                                            .context(req.context.clone())
                                            .build()
                                            .expect("response is valid")
                                    );
                                }
                            }
                            Err(_not_a_string_error) => {
                                res = Some(
                                    supergraph::Response
                                        ::error_builder()
                                        .error(
                                            graphql::Error
                                                ::builder()
                                                .message(
                                                    format!("'{header_key}' value is not a string")
                                                )
                                                .extension_code("BAD_CLIENT_ID")
                                                .build()
                                        )
                                        .status_code(StatusCode::BAD_REQUEST)
                                        .context(req.context.clone())
                                        .build()
                                        .expect("response is valid")
                                );
                            }
                        }
                    }
                }
                None => {
                    res = Some(
                        supergraph::Response
                            ::error_builder()
                            .error(
                                graphql::Error
                                    ::builder()
                                    .message(format!("Query is not present"))
                                    .extension_code("GRAPHQL_ERROR")
                                    .build()
                            )
                            .status_code(StatusCode::BAD_REQUEST)
                            .context(req.context.clone())
                            .build()
                            .expect("response is valid")
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
