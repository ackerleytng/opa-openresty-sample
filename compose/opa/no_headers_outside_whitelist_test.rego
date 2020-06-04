package authz

test_null_headers {
	no_headers_outside_whitelist with input as {}
}

test_empty_headers {
	no_headers_outside_whitelist with input as {"headers": {}}
}

test_subset_of_whitelisted_headers {
	no_headers_outside_whitelist with input as {"headers": {"user-agent": "rego test"}}
}

test_happy_case_whitelisted_headers {
	no_headers_outside_whitelist with input as {"headers": {
		"host": "rego test",
		"accept": "rego test",
		"user-agent": "rego test",
	}}
}

test_superset_of_whitelisted_headers {
	not no_headers_outside_whitelist with input as {"headers": {
		"host": "rego test",
		"accept": "rego test",
		"user-agent": "rego test",
		"some-other": "rego test",
	}}
}

test_stray_header_not_part_of_whitelist {
	not no_headers_outside_whitelist with input as {
		"headers": {"stray": "header"},
		"method": "GET",
	}
}
