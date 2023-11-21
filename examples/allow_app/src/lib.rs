use std::path::PathBuf;

use base64::decode;
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

    #[warn(dead_code)]
    #[derive(Debug, serde::Deserialize, Clone)]
    pub struct Payload {
        pub _id: String,
        pub iss: String,
    }

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

    pub fn get_payload(token: &str) -> Result<Payload, &'static str> {
        let token_base_64: Vec<&str> = token.split('.').collect();

        // Decode payload from jwt
        match decode(token_base_64[1]) {
            Ok(decoded_bytes) => {
                let payload = String::from_utf8(decoded_bytes).expect(
                    "Error al decodificar payload de access Token"
                );

                // Cast to Payload
                if let Ok(payload_data) = serde_json::from_str::<Payload>(&payload) {
                    return Ok(payload_data.clone());
                } else {
                    return Err("Error al obtener payload de access Token");
                }
            }
            Err(_err) => {
                eprintln!("{}", _err);
                return Err("Error al decodificar access Token");
            }
        }
    }
}
