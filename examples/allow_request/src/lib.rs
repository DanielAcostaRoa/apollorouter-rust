use apollo_router::graphql;
use apollo_router::services::supergraph;

use base64::decode;
use http::StatusCode;

pub mod plugin_functions {
    use super::*;

    #[warn(dead_code)]
    #[derive(Debug, serde::Deserialize, Clone)]
    pub struct Payload {
        pub _id: String,
        pub iss: String,
        pub claims: Vec<String>,
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
        claims: &Vec<String>,
        query_string: &str
    ) -> Result<String, &'static str> {
        // Get query to execute
        let operation_name = get_operation_name(query_string);
        let query_is_allowed = claims.iter().any(|query| query == &operation_name);

        if !query_is_allowed {
            return Err("No tienes permisos para ejecutar esta acción");
        }

        Ok(operation_name)
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
}
