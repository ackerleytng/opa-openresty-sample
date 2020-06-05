package authz

test_null_headers {
	all_headers_in_whitelist with input as {}
}

test_empty_headers {
	all_headers_in_whitelist with input as {"headers": {}}
}

test_subset_of_whitelisted_headers {
	all_headers_in_whitelist with input as {"headers": {"user-agent": "rego test"}}
}

test_happy_case_whitelisted_headers {
	all_headers_in_whitelist with input as {"headers": {
		"host": "rego test",
		"accept": "rego test",
		"user-agent": "rego test",
	}}
}

test_superset_of_whitelisted_headers {
	not all_headers_in_whitelist with input as {"headers": {
		"host": "rego test",
		"accept": "rego test",
		"user-agent": "rego test",
		"some-other": "rego test",
	}}
}

test_stray_header_not_part_of_whitelist {
	not all_headers_in_whitelist with input as {
		"headers": {"stray": "header"},
		"method": "GET",
	}
}
