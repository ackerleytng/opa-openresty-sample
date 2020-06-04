# OPA + OpenResty + Toy App

This repo shows how to integrate OPA with a Toy App using OpenResty.

## Quickstart

Start everything with

```
docker-compose up -d
```

Try this (you should get a 200)

```
$ curl -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIxM28yajc1VlRPUU5rWUhEcWxIUEltYjVaQ21IbFp4bzZaTzJNOXMyTl9VIn0.eyJleHAiOjE1OTExNTkwMDEsImlhdCI6MTU5MTE1ODcwMSwiYXV0aF90aW1lIjoxNTkxMTU4NzAxLCJqdGkiOiJlY2U2ZDViMi04MWVmLTQxZWYtODc4OS04ZDE0ZDNiMjg5NjEiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLmxvY2FsaG9zdC9hdXRoL3JlYWxtcy9hcHBsaWNhdGlvbnMiLCJhdWQiOiJmb28iLCJzdWIiOiI0YzBkNDU1ZC00YmZlLTQyZjItYTlkNC02MDJiNDk0Y2NjYzAiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJmb28iLCJzZXNzaW9uX3N0YXRlIjoiZGJiZDhkNDgtMGIzZC00ZTZkLWIzZDQtMjI5Yjc0Y2RlZTQ2IiwiYWNyIjoiMSIsInNjb3BlIjoib3BlbmlkIGZvbyBwcm9maWxlIGVtYWlsIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoiVXNlciBaZXJvIiwicHJlZmVycmVkX3VzZXJuYW1lIjoidXNlcjAiLCJnaXZlbl9uYW1lIjoiVXNlciIsImZhbWlseV9uYW1lIjoiWmVybyIsImVtYWlsIjoidXNlcjBAbWFpbC5jb20ifQ.fsKy6fTCifKsOnznQHJEGWd2aY3TbKbiwrbOEV4bwevPkt_ths7kS3sWPbGCi9hphZQ9zup_wJYKudwpluyoDk5YIbBrwPUpu4P6Ocist5-oGvlAbUhVyIy8Ylh2gs3hLLnUPYdg0Cj19c467Yw1fiX7kdYFumr9AOB0arlvzsdYKNewls6-AZqTvICmhXWplHcu8DQRtinSf6vTnCLcqesc_PB-udWYmednT5CxZxcYQkWfVvyAN7EQa22dUXLTHfOKwF2csIsTBrn21xvVbBcTfbDZDfCR3UXrZ2AQLYPxkaUAxslW9zbyenQhSMeQhTZFfIUjp8ipS7AroEmviw" -H 'X-Auth-User: user0' -X GET http://localhost/
Hostname: efa2cf55066e
IP: 127.0.0.1
IP: 172.25.0.2
RemoteAddr: 172.25.0.3:59658
GET / HTTP/1.1
Host: whoami
User-Agent: curl/7.58.0
Accept: */*
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIxM28yajc1VlRPUU5rWUhEcWxIUEltYjVaQ21IbFp4bzZaTzJNOXMyTl9VIn0.eyJleHAiOjE1OTExNTkwMDEsImlhdCI6MTU5MTE1ODcwMSwiYXV0aF90aW1lIjoxNTkxMTU4NzAxLCJqdGkiOiJlY2U2ZDViMi04MWVmLTQxZWYtODc4OS04ZDE0ZDNiMjg5NjEiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLmxvY2FsaG9zdC9hdXRoL3JlYWxtcy9hcHBsaWNhdGlvbnMiLCJhdWQiOiJmb28iLCJzdWIiOiI0YzBkNDU1ZC00YmZlLTQyZjItYTlkNC02MDJiNDk0Y2NjYzAiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJmb28iLCJzZXNzaW9uX3N0YXRlIjoiZGJiZDhkNDgtMGIzZC00ZTZkLWIzZDQtMjI5Yjc0Y2RlZTQ2IiwiYWNyIjoiMSIsInNjb3BlIjoib3BlbmlkIGZvbyBwcm9maWxlIGVtYWlsIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoiVXNlciBaZXJvIiwicHJlZmVycmVkX3VzZXJuYW1lIjoidXNlcjAiLCJnaXZlbl9uYW1lIjoiVXNlciIsImZhbWlseV9uYW1lIjoiWmVybyIsImVtYWlsIjoidXNlcjBAbWFpbC5jb20ifQ.fsKy6fTCifKsOnznQHJEGWd2aY3TbKbiwrbOEV4bwevPkt_ths7kS3sWPbGCi9hphZQ9zup_wJYKudwpluyoDk5YIbBrwPUpu4P6Ocist5-oGvlAbUhVyIy8Ylh2gs3hLLnUPYdg0Cj19c467Yw1fiX7kdYFumr9AOB0arlvzsdYKNewls6-AZqTvICmhXWplHcu8DQRtinSf6vTnCLcqesc_PB-udWYmednT5CxZxcYQkWfVvyAN7EQa22dUXLTHfOKwF2csIsTBrn21xvVbBcTfbDZDfCR3UXrZ2AQLYPxkaUAxslW9zbyenQhSMeQhTZFfIUjp8ipS7AroEmviw
Connection: close
X-Auth-User: user0
$
```

This jwt decodes as follows

```
$ echo 'eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIxM28yajc1VlRPUU5rWUhEcWxIUEltYjVaQ21IbFp4bzZaTzJNOXMyTl9VIn0.eyJleHAiOjE1OTExNTkwMDEsImlhdCI6MTU5MTE1ODcwMSwiYXV0aF90aW1lIjoxNTkxMTU4NzAxLCJqdGkiOiJlY2U2ZDViMi04MWVmLTQxZWYtODc4OS04ZDE0ZDNiMjg5NjEiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLmxvY2FsaG9zdC9hdXRoL3JlYWxtcy9hcHBsaWNhdGlvbnMiLCJhdWQiOiJmb28iLCJzdWIiOiI0YzBkNDU1ZC00YmZlLTQyZjItYTlkNC02MDJiNDk0Y2NjYzAiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJmb28iLCJzZXNzaW9uX3N0YXRlIjoiZGJiZDhkNDgtMGIzZC00ZTZkLWIzZDQtMjI5Yjc0Y2RlZTQ2IiwiYWNyIjoiMSIsInNjb3BlIjoib3BlbmlkIGZvbyBwcm9maWxlIGVtYWlsIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoiVXNlciBaZXJvIiwicHJlZmVycmVkX3VzZXJuYW1lIjoidXNlcjAiLCJnaXZlbl9uYW1lIjoiVXNlciIsImZhbWlseV9uYW1lIjoiWmVybyIsImVtYWlsIjoidXNlcjBAbWFpbC5jb20ifQ.fsKy6fTCifKsOnznQHJEGWd2aY3TbKbiwrbOEV4bwevPkt_ths7kS3sWPbGCi9hphZQ9zup_wJYKudwpluyoDk5YIbBrwPUpu4P6Ocist5-oGvlAbUhVyIy8Ylh2gs3hLLnUPYdg0Cj19c467Yw1fiX7kdYFumr9AOB0arlvzsdYKNewls6-AZqTvICmhXWplHcu8DQRtinSf6vTnCLcqesc_PB-udWYmednT5CxZxcYQkWfVvyAN7EQa22dUXLTHfOKwF2csIsTBrn21xvVbBcTfbDZDfCR3UXrZ2AQLYPxkaUAxslW9zbyenQhSMeQhTZFfIUjp8ipS7AroEmviw' | jq -R 'split(".") | .[1] | @base64d | fromjson'
{
  "exp": 1591159001,
  "iat": 1591158701,
  "auth_time": 1591158701,
  "jti": "ece6d5b2-81ef-41ef-8789-8d14d3b28961",
  "iss": "https://keycloak.localhost/auth/realms/applications",
  "aud": "foo",
  "sub": "4c0d455d-4bfe-42f2-a9d4-602b494cccc0",
  "typ": "Bearer",
  "azp": "foo",
  "session_state": "dbbd8d48-0b3d-4e6d-b3d4-229b74cdee46",
  "acr": "1",
  "scope": "openid foo profile email",
  "email_verified": false,
  "name": "User Zero",
  "preferred_username": "user0",
  "given_name": "User",
  "family_name": "Zero",
  "email": "user0@mail.com"
}
$
```