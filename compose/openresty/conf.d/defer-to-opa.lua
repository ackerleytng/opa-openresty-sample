local http = require("resty.http")
local Url = require("min.url")
local json = require("json")


-- parse the necessary information out of the request
local path = Url.parse(ngx.var.uri).pathname

local auth_header = ngx.var.http_Authorization
local token = nil
if auth_header then
   _, _, token = string.find(auth_header, "Bearer%s+(.+)")
end

-- form specs for opa to make decision
local request_specs = {
   method = ngx.req.get_method(),
   path = path,
   token = token,
   headers = ngx.req.get_headers(),
   remote_addr = ngx.var.remote_addr
}

-- make the request out to opa
local httpc = http.new()

-- 10ms timeout, because opa should always run near(TM) to openresty
-- We do this so that if opa is down, the request fails fast (request is rejected)
httpc:set_timeout(10)

local res, err = httpc:request_uri(
   "http://opa:8181/v1/data/authz",
   {
      method = "POST",
      body = json.encode({input = request_specs}),
   }
)

-- error checking
if (err or res == nil) then
   ngx.status = ngx.HTTP_FORBIDDEN
   ngx.print(err)
   ngx.exit(ngx.HTTP_FORBIDDEN)
end

if res.status ~= 200 then
   ngx.status = ngx.HTTP_FORBIDDEN
   ngx.print(res.body)
   ngx.exit(ngx.HTTP_FORBIDDEN)
end

-- check opa's decision
local r = json.decode(res.body)
if not (r.result and r.result.allow) then
   ngx.status = ngx.HTTP_FORBIDDEN
   ngx.print(res.body)
   ngx.exit(ngx.HTTP_FORBIDDEN)
end

-- allow request to proceed otherwise
