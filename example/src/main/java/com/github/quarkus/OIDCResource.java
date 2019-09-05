package com.github.quarkus;

import java.security.Principal;
import java.util.stream.Collectors;

import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.stream.JsonCollectors;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.SecurityContext;

import org.eclipse.microprofile.jwt.JsonWebToken;

@Path("/oidc")
public class OIDCResource {

	@Inject
	JsonWebToken jwt;

	@GET()
	@Path("token")
	@RolesAllowed({ "Everyone" })
	@Produces(MediaType.APPLICATION_JSON)
	public JsonObject jwtDetails(@Context SecurityContext ctx) {
		JsonObjectBuilder builder = Json.createObjectBuilder();
		Principal caller = ctx.getUserPrincipal();
		builder.add("name", caller == null ? "anonymous" : caller.getName());
		if (jwt != null) {
			builder.add("issuer", jwt.getIssuer());			
			builder.add("claimNames", jwt.getClaimNames().stream().map(n -> Json.createValue(n)).collect(JsonCollectors.toJsonArray()));
			builder.add("jwtToken", jwt.getRawToken());
		}

		return builder.build();
	}
}