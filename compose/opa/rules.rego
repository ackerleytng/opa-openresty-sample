package authz

import input

# -----------------------------------------------
#   Configure this
# -----------------------------------------------

client_id := "whoami"

keycloak_well_known_location = "http://keycloak.localhost/auth/realms/applications/.well-known/openid-configuration"

# -----------------------------------------------
#   Stuff you don't need to modify
# -----------------------------------------------

oidc_config = http.send({
	"url": keycloak_well_known_location,
	"method": "GET",
}).body

jwks = http.send({
	"url": oidc_config.jwks_uri,
	"method": "GET",
}).raw_body

token_constraints = {
	"cert": jwks,
	"iss": oidc_config.issuer,
	"time": time.now_ns(),
	"aud": client_id,
}

token = {"type": type, "payload": payload, "valid": valid} {
	[type, bearer_token] := regex.split("\\s+", input.headers.authorization)

	[valid, _, payload] := io.jwt.decode_verify(bearer_token, token_constraints)
}

default allow = false

# -----------------------------------------------
#   Your rules start below
# -----------------------------------------------

# Requests with headers other than those on this whitelist will be rejected

# Note: OpenResty will normalize headers by lowercasing all headers and
#   converting all underscores to dashes before sending it to opa, so define
#   your whitelist in lowercase with dashes

# OpenResty will only retain one of the headers, after normalizing them. If
#   there are duplicate headers, OPA will only get one of them. Just DON'T rely
#   on duplicate headers for anything.
whitelisted_headers := {
	"host",
	"accept",
	"accept-encoding",
	"user-agent",
	"authorization",
	"x-forwarded-for",
	"x-forwarded-proto",
	"x-auth-user",
}

all_headers_in_whitelist {
	count({h | input.headers[h]; not whitelisted_headers[h]}) == 0
}

x_auth_user_must_match_user_in_token {
	input.headers["x-auth-user"] == token.payload.preferred_username
}

token_type_is_bearer {
	token.type == "bearer"
}

token_type_is_bearer {
	token.type == "Bearer"
}

default_rule_components {
	token.valid
	token_type_is_bearer
	all_headers_in_whitelist
	x_auth_user_must_match_user_in_token
}

# -----------------------------------------------
#   Per-route rules
#   (each must include default_rule_components)
# -----------------------------------------------

allow {
	default_rule_components
	input.path == "/"
	input.method == "GET"
}
