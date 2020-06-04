package authz

test_no_headers {
	not x_auth_user_must_match_user_in_token with input as {}
		 with token as {"payload": {"preferred_username": "user0"}}
}

test_no_x_auth_user_header {
	not x_auth_user_must_match_user_in_token with input as {"headers": {"some-other": "header"}}
		 with token as {"payload": {"preferred_username": "user0"}}
}

test_name_not_in_token {
	not x_auth_user_must_match_user_in_token with input as {"headers": {"x-auth-user": "user0"}}
		 with token as {"payload": {}}
}

test_happy_case {
	x_auth_user_must_match_user_in_token with input as {"headers": {"x-auth-user": "user0"}}
		 with token as {"payload": {"preferred_username": "user0"}}
}

test_mismatch {
	not x_auth_user_must_match_user_in_token with input as {"headers": {"x-auth-user": "user1"}}
		 with token as {"payload": {"preferred_username": "user0"}}
}
