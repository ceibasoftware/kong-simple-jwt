-- If you're not sure your plugin is executing, uncomment the line below and restart Kong
-- then it will throw an error which indicates the plugin is being loaded at least.

-- assert(ngx.get_phase() == "timer", "The world is coming to an end!")


-- Grab pluginname from module name
local plugin_name = ({...})[1]:match("^kong%.plugins%.([^%.]+)")

-- load the base plugin object and create a subclass
local plugin = require("kong.plugins.base_plugin"):extend()
local singletons = require "kong.singletons"
local constants = require "kong.constants"
local meta = require "kong.meta"
local http = require "resty.http"
local xjwt = require "resty.jwt"
local string  = string

local cjson   = require "cjson"
local cjson_s = require "cjson.safe"

local ngx     = ngx

local b64     = ngx.encode_base64
local unb64   = ngx.decode_base64

local kong = kong

-- constructor
function plugin:new()
  plugin.super.new(self, plugin_name)

  -- do initialization here, runs in the 'init_by_lua_block', before worker processes are forked

end

--[[ handles more initialization, but AFTER the worker process has been forked/created.
-- It runs in the 'init_worker_by_lua_block'
function plugin:init_worker()
  plugin.super.init_worker(self)

  -- your custom code here

end --]]

---[[ runs in the 'access_by_lua_block'
function plugin:access(plugin_conf)
  plugin.super.access(self)    
  reject = false;      

  local token, token_err = extract(plugin_conf)
    
  if token == nil then
  	return kong.response.exit(401, token_err);
  end

  -- this is the jwt 
  local jwt_token = xjwt:load_jwt(token)

  -- if valid, extract jwk and check token
  if jwt_token.valid == true then 
    
    local keys, keys_err = openidc_jwks(plugin_conf) 

    -- let's fetch the key
    if keys == nil then
      return kong.response.exit(400, keys_err)    
    end

    local jwk, jwk_err = get_jwk(keys, jwt_token.header.kid);

    -- check for jwk key
    if jwk == nil then
      return kong.response.exit(401, jwk_err);
    end

    -- load pem cert to validate token
    local pem_cert, pem_cert_err = get_pem(jwk)
    
    if pem_cert == nil then
      return kong.response.exit(401, pem_cert_err);
    end

    -- we have the public key, let's inspect the token
    local token_validated = xjwt:verify(pem_cert, token)

    if not token_validated.verified then     
      return kong.response.exit(401,token_validated.reason)
    end

    -- let's send all claims in token as headers
    update_headers(jwt_token.payload, plugin_conf)
    
  else
    return kong.response.exit(401,jwt_token.reason)
  end  

end 

function update_headers(jwt_payload, config)    
  if config.remove_auth_header then
    ngx.req.clear_header("Authorization")
    for k,v in pairs(jwt_payload) do
      ngx.req.set_header("X-JWT-CLAIMS-"..string.upper(k), v)
    end
  end
end

function get_pem(jwk)
  local pem
  if jwk.x5c then
    pem = openidc_pem_from_x5c(jwk.x5c)
  elseif jwk.kty == "RSA" and jwk.n and jwk.e then
    pem = openidc_pem_from_rsa_n_and_e(jwk.n, jwk.e)
  else
    return nil, "don't know how to create RSA key/cert for " .. cjson.encode(jwt)
  end
  return pem,nil
end

---[[extracts jwt from header (Authorization Bearer)]
function extract(config) 
  local jwt
  local err
  local header = ngx.req.get_headers()[config.auth_header]
  
  if header == nil then
    err = "No token found using header: " .. config.auth_header
    ngx.log(ngx.ERR, err)
    return nil, err
  end
  
  if header:find(" ") then
    local divider = header:find(' ')
    if string.lower(header:sub(0, divider-1)) == string.lower(config.schema) then
      jwt = header:sub(divider+1)
      if jwt == nil then
        err = "No Bearer token value found from header: " .. config.auth_header
        ngx.log(ngx.ERR, err)
        return nil, err
      end
    end
  end 
  
  if jwt == nil then
    jwt =  header
  end 
  
  ngx.log(ngx.DEBUG, "JWT token located using header: " .. config.auth_header .. ", token length: " .. string.len(jwt))
  return jwt, err
end --]]

---[[extract jwk key ]]
function openidc_jwks(config)
  
  local json, err, v
 
  v = cache_get("kong_db_cache", config.discovery)
  -- not in cache, go for it
  if not v then

    ngx.log(ngx.DEBUG, "cannot use cached JWKS data; making call to jwks endpoint")
    -- make the call to the jwks endpoint
    local httpc = http.new()
    --openidc_configure_timeouts(httpc, timeout)
    --openidc_configure_proxy(httpc, proxy_opts)
    local res, error = httpc:request_uri(config.discovery, {
      ssl_verify = false
    })
    if not res then
      err = "accessing jwks url ("..config.discovery..") failed: "..error
      ngx.log(ngx.ERR, err)
    else
      ngx.log(ngx.DEBUG, "response data: "..res.body)
      json, err = openidc_parse_json_response(res)
      if json then
        cache_set("kong_db_cache", config.discovery, cjson.encode(json), config.ttl_jwks or 24 * 60 * 60)
      end
    end

  else
    json = cjson.decode(v)
  end  

  return json, err
end

-- parse the JSON result from a call to the OP
function openidc_parse_json_response(response)

  local err
  local res

  -- check the response from the OP
  if response.status ~= 200 then
    err = "response indicates failure, status="..response.status..", body="..response.body
  else
    -- decode the response and extract the JSON object
    res = cjson_s.decode(response.body)

    if not res then
      err = "JSON decoding failed"
    end
  end

  return res, err
end

-- fetch jwk
function get_jwk (keys, kid)

  local rsa_keys = {}
  for k, value in pairs(keys.keys) do
    if value.kty == "RSA" and (not value.use or value.use == "sig") then
      table.insert(rsa_keys, value)
    end
  end

  
  if kid == nil then
    if #rsa_keys == 1 then
      ngx.log(ngx.DEBUG, "returning only RSA key of JWKS for keyid-less JWT")
      return rsa_keys[1], nil
    else
      return nil, "JWT doesn't specify kid but the keystore contains multiple RSA keys"
    end
  end
  for k, value in pairs(rsa_keys) do
    if value.kid == kid then
      return value, nil
    end
  end

  return nil, "RSA key with id " .. kid .. " not found"
end

-- pem from x5c
function openidc_pem_from_x5c(x5c)
  -- TODO check x5c length
  ngx.log(ngx.DEBUG, "Found x5c, getting PEM public key from x5c entry of json public key")
  local chunks = split_by_chunk(b64(openidc_base64_url_decode(x5c[1])), 64)
  local pem = "-----BEGIN CERTIFICATE-----\n" ..
    table.concat(chunks, "\n") ..
    "\n-----END CERTIFICATE-----"
  ngx.log(ngx.DEBUG,"Generated PEM key from x5c:", pem)
  return pem
end

function split_by_chunk(text, chunkSize)
  local s = {}
  for i=1, #text, chunkSize do
    s[#s+1] = text:sub(i,i+chunkSize - 1)
  end
  return s
end

function openidc_pem_from_rsa_n_and_e(n, e)
  ngx.log(ngx.DEBUG , "getting PEM public key from n and e parameters of json public key")

  local der_key = {
    openidc_base64_url_decode(n), openidc_base64_url_decode(e)
  }
  local encoded_key = encode_sequence_of_integer(der_key)
  local pem = der2pem(encode_sequence({
    encode_sequence({
        "\6\9\42\134\72\134\247\13\1\1\1" -- OID :rsaEncryption
        .. "\5\0" -- ASN.1 NULL of length 0
    }),
    encode_bit_string(encoded_key)
  }), "PUBLIC KEY")
  ngx.log(ngx.DEBUG, "Generated pem key from n and e: ", pem)
  return pem
end

function der2pem(data, typ)
  local wrap = ('.'):rep(64)
  local envelope = "-----BEGIN %s-----\n%s\n-----END %s-----\n"
  local typ = typ:upper() or "CERTIFICATE"
  local data = b64(data)
  return string.format(envelope, typ, data:gsub(wrap, '%0\n', (#data-1)/64), typ)     
end

function openidc_base64_url_decode(input)
  local reminder = #input % 4
  if reminder > 0 then
    local padlen = 4 - reminder
    input = input .. string.rep('=', padlen)
  end
  input = input:gsub('-','+'):gsub('_','/')
  return unb64(input)
end

function encode_sequence_of_integer(array)
  return encode_sequence(array,encode_binary_integer)
end

function encode_binary_integer(bytes)
  if bytes:byte(1) > 127 then
      -- We currenly only use this for unsigned integers,
      -- however since the high bit is set here, it would look
      -- like a negative signed int, so prefix with zeroes
      bytes = "\0" .. bytes
   end
   return "\2" .. encode_length(#bytes) .. bytes
end

function encode_sequence(array, of)
  local encoded_array = array
  if of then
      encoded_array = {}
      for i = 1, #array do
          encoded_array[i] = of(array[i])
      end
  end
  encoded_array = table.concat(encoded_array)

  return string.char(0x30) .. encode_length(#encoded_array) .. encoded_array
end

function encode_length(length)
  if length < 0x80 then
      return string.char(length)
  elseif length < 0x100 then
      return string.char(0x81, length)
  elseif length < 0x10000 then
      return string.char(0x82, math.floor(length/0x100), length%0x100)
  end
  error("Can't encode lengths over 65535")
end

function encode_bit_string(array)
  local s = "\0" .. array -- first octet holds the number of unused bits
  return "\3" .. encode_length(#s) .. s
end

-- set value in server-wide cache if available
function cache_set(type, key, value, exp)
  local dict = ngx.shared[type]
  if dict and (exp > 0) then
    local success, err, forcible = dict:set(key, value, exp)    
  end
end

-- retrieve value from server-wide cache if available
function cache_get(type, key)
  local dict = ngx.shared[type]
  local value
  if dict then
    value = dict:get(key)    
  end
  return value
end


-- set the plugin priority, which determines plugin execution order
plugin.PRIORITY = 1000

-- return our plugin object
return plugin
