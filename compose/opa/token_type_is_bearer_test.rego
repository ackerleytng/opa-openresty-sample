package authz

test_lowercase {
	token_type_is_bearer with token as {"type": "bearer"}
}

test_title_case {
	token_type_is_bearer with token as {"type": "Bearer"}
}

test_null {
	not token_type_is_bearer with token as {"type": null}
}

test_undefined {
	not token_type_is_bearer with token as {}
}

test_some_other {
	not token_type_is_bearer with token as {"type": "wrong"}
}

test_parse_from_header {
	token_type_is_bearer with input as {"headers": {"authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIxM28yajc1VlRPUU5rWUhEcWxIUEltYjVaQ21IbFp4bzZaTzJNOXMyTl9VIn0.eyJleHAiOjE1OTExNTkwMDEsImlhdCI6MTU5MTE1ODcwMSwiYXV0aF90aW1lIjoxNTkxMTU4NzAxLCJqdGkiOiJlY2U2ZDViMi04MWVmLTQxZWYtODc4OS04ZDE0ZDNiMjg5NjEiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLmxvY2FsaG9zdC9hdXRoL3JlYWxtcy9hcHBsaWNhdGlvbnMiLCJhdWQiOiJmb28iLCJzdWIiOiI0YzBkNDU1ZC00YmZlLTQyZjItYTlkNC02MDJiNDk0Y2NjYzAiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJmb28iLCJzZXNzaW9uX3N0YXRlIjoiZGJiZDhkNDgtMGIzZC00ZTZkLWIzZDQtMjI5Yjc0Y2RlZTQ2IiwiYWNyIjoiMSIsInNjb3BlIjoib3BlbmlkIGZvbyBwcm9maWxlIGVtYWlsIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoiVXNlciBaZXJvIiwicHJlZmVycmVkX3VzZXJuYW1lIjoidXNlcjAiLCJnaXZlbl9uYW1lIjoiVXNlciIsImZhbWlseV9uYW1lIjoiWmVybyIsImVtYWlsIjoidXNlcjBAbWFpbC5jb20ifQ.fsKy6fTCifKsOnznQHJEGWd2aY3TbKbiwrbOEV4bwevPkt_ths7kS3sWPbGCi9hphZQ9zup_wJYKudwpluyoDk5YIbBrwPUpu4P6Ocist5-oGvlAbUhVyIy8Ylh2gs3hLLnUPYdg0Cj19c467Yw1fiX7kdYFumr9AOB0arlvzsdYKNewls6-AZqTvICmhXWplHcu8DQRtinSf6vTnCLcqesc_PB-udWYmednT5CxZxcYQkWfVvyAN7EQa22dUXLTHfOKwF2csIsTBrn21xvVbBcTfbDZDfCR3UXrZ2AQLYPxkaUAxslW9zbyenQhSMeQhTZFfIUjp8ipS7AroEmviw"}}
}

test_parse_from_header_w_many_spaces {
	token_type_is_bearer with input as {"headers": {"authorization": "Bearer          eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIxM28yajc1VlRPUU5rWUhEcWxIUEltYjVaQ21IbFp4bzZaTzJNOXMyTl9VIn0.eyJleHAiOjE1OTExNTkwMDEsImlhdCI6MTU5MTE1ODcwMSwiYXV0aF90aW1lIjoxNTkxMTU4NzAxLCJqdGkiOiJlY2U2ZDViMi04MWVmLTQxZWYtODc4OS04ZDE0ZDNiMjg5NjEiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLmxvY2FsaG9zdC9hdXRoL3JlYWxtcy9hcHBsaWNhdGlvbnMiLCJhdWQiOiJmb28iLCJzdWIiOiI0YzBkNDU1ZC00YmZlLTQyZjItYTlkNC02MDJiNDk0Y2NjYzAiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJmb28iLCJzZXNzaW9uX3N0YXRlIjoiZGJiZDhkNDgtMGIzZC00ZTZkLWIzZDQtMjI5Yjc0Y2RlZTQ2IiwiYWNyIjoiMSIsInNjb3BlIjoib3BlbmlkIGZvbyBwcm9maWxlIGVtYWlsIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoiVXNlciBaZXJvIiwicHJlZmVycmVkX3VzZXJuYW1lIjoidXNlcjAiLCJnaXZlbl9uYW1lIjoiVXNlciIsImZhbWlseV9uYW1lIjoiWmVybyIsImVtYWlsIjoidXNlcjBAbWFpbC5jb20ifQ.fsKy6fTCifKsOnznQHJEGWd2aY3TbKbiwrbOEV4bwevPkt_ths7kS3sWPbGCi9hphZQ9zup_wJYKudwpluyoDk5YIbBrwPUpu4P6Ocist5-oGvlAbUhVyIy8Ylh2gs3hLLnUPYdg0Cj19c467Yw1fiX7kdYFumr9AOB0arlvzsdYKNewls6-AZqTvICmhXWplHcu8DQRtinSf6vTnCLcqesc_PB-udWYmednT5CxZxcYQkWfVvyAN7EQa22dUXLTHfOKwF2csIsTBrn21xvVbBcTfbDZDfCR3UXrZ2AQLYPxkaUAxslW9zbyenQhSMeQhTZFfIUjp8ipS7AroEmviw"}}
}

test_parse_without_bearer {
	not token_type_is_bearer with input as {"headers": {"authorization": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIxM28yajc1VlRPUU5rWUhEcWxIUEltYjVaQ21IbFp4bzZaTzJNOXMyTl9VIn0.eyJleHAiOjE1OTExNTkwMDEsImlhdCI6MTU5MTE1ODcwMSwiYXV0aF90aW1lIjoxNTkxMTU4NzAxLCJqdGkiOiJlY2U2ZDViMi04MWVmLTQxZWYtODc4OS04ZDE0ZDNiMjg5NjEiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLmxvY2FsaG9zdC9hdXRoL3JlYWxtcy9hcHBsaWNhdGlvbnMiLCJhdWQiOiJmb28iLCJzdWIiOiI0YzBkNDU1ZC00YmZlLTQyZjItYTlkNC02MDJiNDk0Y2NjYzAiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJmb28iLCJzZXNzaW9uX3N0YXRlIjoiZGJiZDhkNDgtMGIzZC00ZTZkLWIzZDQtMjI5Yjc0Y2RlZTQ2IiwiYWNyIjoiMSIsInNjb3BlIjoib3BlbmlkIGZvbyBwcm9maWxlIGVtYWlsIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoiVXNlciBaZXJvIiwicHJlZmVycmVkX3VzZXJuYW1lIjoidXNlcjAiLCJnaXZlbl9uYW1lIjoiVXNlciIsImZhbWlseV9uYW1lIjoiWmVybyIsImVtYWlsIjoidXNlcjBAbWFpbC5jb20ifQ.fsKy6fTCifKsOnznQHJEGWd2aY3TbKbiwrbOEV4bwevPkt_ths7kS3sWPbGCi9hphZQ9zup_wJYKudwpluyoDk5YIbBrwPUpu4P6Ocist5-oGvlAbUhVyIy8Ylh2gs3hLLnUPYdg0Cj19c467Yw1fiX7kdYFumr9AOB0arlvzsdYKNewls6-AZqTvICmhXWplHcu8DQRtinSf6vTnCLcqesc_PB-udWYmednT5CxZxcYQkWfVvyAN7EQa22dUXLTHfOKwF2csIsTBrn21xvVbBcTfbDZDfCR3UXrZ2AQLYPxkaUAxslW9zbyenQhSMeQhTZFfIUjp8ipS7AroEmviw"}}
}
