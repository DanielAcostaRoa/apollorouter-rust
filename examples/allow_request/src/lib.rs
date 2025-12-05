use std::path::PathBuf;
use http::HeaderMap;

use apollo_router::graphql;
use apollo_router::services::supergraph;
use apollo_parser::{ cst, Parser };

use http::StatusCode;
use http::HeaderValue;
use serde::Deserialize;
use schemars::JsonSchema;
use jsonwebtoken::{ decode, Algorithm, DecodingKey, Validation };

pub mod functions {
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

    pub fn get_auth_token(headers: &http::HeaderMap) -> Result<String, &'static str> {
        let header = match headers.get("Authorization") {
            Some(v) => v,
            None => {
                return Err("No se ha proporcionado el encabezado de autorización");
            }
        };
        let auth_header = match std::str::from_utf8(header.as_bytes()) {
            Ok(v) => v,
            Err(_) => {
                return Err("Error al validar el encabezado de autorización");
            }
        };
        if !auth_header.starts_with("Bearer ") {
            return Err("Token de acceso no válido no válido");
        }
        Ok(auth_header.trim_start_matches("Bearer ").to_string())
    }

    pub fn validate_jwt_rsa(token: &str, public_key_path: &PathBuf) -> Result<Payload, &'static str> {
        let public_key_pem = std::fs::read(public_key_path).map_err(|_| "Error al leer clave pública")?;

        let decoding_key = DecodingKey::from_rsa_pem(&public_key_pem).map_err(
            |_| "Error al decodificar clave pública"
        )?;

        let validation = Validation::new(Algorithm::RS256);

        let token_data = match decode::<Payload>(token, &decoding_key, &validation) {
            Ok(data) => data,
            Err(err) => {
                if err.to_string() == "ExpiredSignature" {
                    return Err("Su sesión ha expirado");
                }
                return Err("Token de acceso no válido");
            }
        };

        Ok(token_data.claims)
    }

    pub fn authenticate(headers: &HeaderMap, public_key_path: &PathBuf) -> Result<Payload, &'static str> {
        let jwt = match get_auth_token(headers) {
            Ok(token) => token,
            Err(err) => {
                return Err(err);
            }
        };

        let payload = match validate_jwt_rsa(&jwt, public_key_path) {
            Ok(data) => data,
            Err(err) => {
                return Err(err);
            }
        };

        Ok(payload)
    }

    pub fn authorize(
        file: PathBuf,
        query: &str,
        payload: &Payload,
        req: &mut supergraph::Request
    ) -> Result<(), &'static str> {
        let app = match get_app(&payload.iss, file.clone()) {
            Ok(app) => app,
            Err(err) => {
                return Err(err);
            }
        };

        match validate_operation(&app.permissions, &payload.claims, query) {
            Ok(query) => {
                insert_header(req, "user_id", &payload._id);
                insert_header(req, "app_id", &app._id);
                insert_header(req, "app_name", &app.name);
                insert_header(req, "app_url", &app.url);
                insert_header(req, "permissions", &query.join(","));
                Ok(())
            }
            Err(err) => {
                return Err(err);
            }
        }
    }
}
