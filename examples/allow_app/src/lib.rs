use std::path::PathBuf;

use apollo_router::graphql;
use apollo_router::services::supergraph;
use serde::Deserialize;
use schemars::JsonSchema;
use http::StatusCode;

#[warn(dead_code)]
#[derive(Deserialize, JsonSchema, Clone)]
pub struct AppConfig {
    id: String,
    pub nombre: String,
    pub queries: Vec<String>,
}

pub mod plugin_functions {
    use super::*;

    pub fn get_operation_name(query_string: &str) -> String {
        let ops: Vec<&str> = query_string.split('{').collect();
        let op1: Vec<&str> = ops[1].split('(').collect();
        op1[0].replace(|c: char| !c.is_alphanumeric(), "")
    }

    pub fn error_response(
        message: &str,
        status_code: StatusCode,
        extension_code: &str,
        req: &supergraph::Request
    ) -> Option<supergraph::Response> {
        return Some(
            supergraph::Response
                ::error_builder()
                .error(
                    graphql::Error
                        ::builder()
                        .message(message.to_string())
                        .extension_code(extension_code)
                        .build()
                )
                .status_code(status_code)
                .context(req.context.clone())
                .build()
                .expect("response is valid")
        );
    }

    pub fn validate_operation(
        app_id: &str,
        query_string: &str,
        file_path: PathBuf
    ) -> Result<AppConfig, &'static str> {
        // Get query to execute
        let operation_name = get_operation_name(query_string);

        let apps: Vec<AppConfig> = serde_json
            ::from_str(std::fs::read_to_string(file_path).unwrap().as_str())
            .unwrap();

        if let Some(app) = apps.iter().find(|app| app.id == app_id) {
            let query_is_allowed = app.queries.iter().any(|query| query == &operation_name);

            if !query_is_allowed {
                return Err("No tienes permisos para ejecutar esta acción");
            }

            Ok(app.clone())
        } else {
            Err("Aplicación no registrada")
        }
    }
}
