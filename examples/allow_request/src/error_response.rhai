fn supergraph_service(service) {
    let f = |response| {
        response.body.errors = response.body.errors.map(|v| {
            if (v.message.contains("HTTP fetch failed from ")) {
                let subgraph = v.message.split(24)[1].split("'")[0];
                let error_to_add = #{
                    message: "No se obtuvo respuesta del servicio, por favor intente nuevamente.",
                    extensions: #{
                        code: "SUBGRAPH_UNAVAILABLE",
                        reason: `El servicio '${subgraph}' no está disponible en este momento.`
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
