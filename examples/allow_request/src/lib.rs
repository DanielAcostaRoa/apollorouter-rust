use std::path::PathBuf;

use apollo_router::graphql;
use apollo_router::services::supergraph;
use apollo_parser::{ cst, Parser };

use base64::decode;
use http::StatusCode;
use http::HeaderValue;
use serde::Deserialize;
use schemars::JsonSchema;

pub mod plugin_functions {
    use super::*;

    #[warn(dead_code)]
    #[derive(Debug, serde::Deserialize, Clone)]
    pub struct Payload {
        pub _id: String,
        pub iss: String,
        pub claims: Vec<String>,
    }

    #[warn(dead_code)]
    #[derive(Deserialize, JsonSchema, Clone)]
    pub struct AppConfig {
        pub _id: String,
        pub name: String,
        pub url: String,
        pub permissions: Vec<String>,
    }

    pub fn introspection(query_string: &str) -> bool {
        let parser = Parser::new(query_string);
        let cst = parser.parse();

        let doc = cst.document();

        for def in doc.definitions() {
            if let cst::Definition::OperationDefinition(op_def) = def {
                if let Some(selection_set) = op_def.selection_set() {
                    for selection in selection_set.selections() {
                        match selection {
                            cst::Selection::Field(field) => {
                                if let Some(name) = field.name() {
                                    if name.text() == "__schema" {
                                        return true;
                                    }
                                }
                            }
                            _selection => {}
                        }
                    }
                }
            }
        }
        false
    }

    pub fn get_operations_name(query_string: &str) -> Vec<String> {
        let mut operations = Vec::new();
        let parser = Parser::new(query_string);
        let cst = parser.parse();

        let doc = cst.document();

        for def in doc.definitions() {
            if let cst::Definition::OperationDefinition(op_def) = def {
                if let Some(selection_set) = op_def.selection_set() {
                    for selection in selection_set.selections() {
                        match selection {
                            cst::Selection::Field(field) => {
                                if let Some(name) = field.name() {
                                    operations.push(name.text().to_string());
                                }
                            }
                            _selection => {}
                        }
                    }
                }
            }
        }
        operations
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
                .error(graphql::Error::builder().message(message.to_string()).extension_code(extension_code).build())
                .status_code(status_code)
                .context(req.context.clone())
                .build()
                .expect("response is valid")
        );
    }

    pub fn validate_operation(
        permissions: &Vec<String>,
        claims: &Vec<String>,
        query_string: &str
    ) -> Result<Vec<String>, &'static str> {
        let mut _allowed_query = false;

        // Get query to execute
        let operations = get_operations_name(query_string);

        if claims[0] == "*" {
            _allowed_query = operations.iter().all(|operation| permissions.contains(operation));
        } else {
            _allowed_query = operations.iter().all(|operation| claims.contains(operation));
        }

        if !_allowed_query {
            return Err("No tienes permisos para ejecutar esta acción");
        }

        Ok(operations)
    }

    pub fn get_payload(token: &str) -> Result<Payload, &'static str> {
        let token_base_64: Vec<&str> = token.split('.').collect();

        // Decode payload from jwt
        match token_base_64.get(1) {
            Some(token_payload) => {
                match decode(token_payload) {
                    Ok(decoded_bytes) => {
                        match String::from_utf8(decoded_bytes) {
                            Ok(payload) => {
                                // Cast to Payload
                                if let Ok(payload_data) = serde_json::from_str::<Payload>(&payload) {
                                    return Ok(payload_data.clone());
                                } else {
                                    return Err("El formato es incorrecto");
                                }
                            }
                            Err(_err) => Err("No se pudo decodificar el payload del token"),
                        }
                    }
                    Err(_err) => Err("No se pudo decodificar el token."),
                }
            }
            None => Err("El formato es incorrecto"),
        }
    }

    pub fn get_app(app_id: &str, file_path: PathBuf) -> Result<AppConfig, &'static str> {
        let apps: Vec<AppConfig> = serde_json::from_str(std::fs::read_to_string(file_path).unwrap().as_str()).unwrap();

        if let Some(app) = apps.iter().find(|app| app._id == app_id) {
            Ok(app.clone())
        } else {
            Err("Aplicación no registrada")
        }
    }

    pub fn insert_header(req: &mut supergraph::Request, key: &'static str, value: &str) {
        req.supergraph_request.headers_mut().insert(key, HeaderValue::from_str(value).unwrap());
    }
}
