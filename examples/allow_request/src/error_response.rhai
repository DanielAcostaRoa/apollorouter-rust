fn supergraph_service(service) {
    let f = |response| {
        // Check if there was a network error
        response.body.errors = response.body.errors.map(|v| {
            if (v.message.contains("HTTP fetch failed from ")) {
                let error_to_add = #{
                    message: "Error interno de conexión, por favor intente nuevamente.",
                    extensions: #{
                        code: "NETWORK_ERROR",
                        reason: "Subgraph responded with an error"
                    }
                };
                error_to_add
            } else {
                v
            }
            
        });

    };
    service.map_response(f);
}
