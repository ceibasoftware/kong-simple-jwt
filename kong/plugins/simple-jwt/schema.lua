local typedefs = require "kong.db.schema.typedefs"


return {
  name = "myplugin",
  fields = {
    {
      consumer = typedefs.no_consumer
    },
    {
      run_on = typedefs.run_on_first
    },
    {
      protocols = typedefs.protocols_http
    },
    {
      config = {
        type = "record",
        fields = {
          {
            auth_header = {
              type = "string",
              required = false,              
              default = "Authorization",
            },
          },
          {
            schema = {
              type = "string",
	            required = false,
              default = "Bearer",
            },
          },
          {
            ttl_jwks = {
              type = "number",
	            required = false,
              default = 3600,
            },
          },
          {
            remove_auth_header = {
              type = "boolean",
	            required = false,
              default = true,
            },
          },
          {
            discovery = {
              type = "string",
              required = false,
              default = "https://oidcb2c.b2clogin.com/oidcb2c.onmicrosoft.com/discovery/v2.0/keys?p=b2c_1_basesigninup",
            },
          },
        },
      },
    },
  },
}
