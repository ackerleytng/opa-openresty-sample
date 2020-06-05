package authz

import input

# -----------------------------------------------
#   Configure this
# -----------------------------------------------

client_id := "foo"

# -----------------------------------------------
#   Stuff you don't need to modify
# -----------------------------------------------

token = {"payload": payload} {
	# TODO: switch to decode_verify
	#   This will be used to verify the token itself, aud, expiry and issuer
	[header, payload, _] := io.jwt.decode(input.token)
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
	"user-agent",
	"authorization",
	"x-auth-user",
}

all_headers_in_whitelist {
	count({h | input.headers[h]; not whitelisted_headers[h]}) == 0
}

x_auth_user_must_match_user_in_token {
	input.headers["x-auth-user"] == token.payload.preferred_username
}

default_rule_components {
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
