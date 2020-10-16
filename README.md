# Tarantool-http OpenAPI support

You may use your openapi specification file to map the routes and handlers inside your project.

## Table of contents

- [Quickstart](#quickstart)
- [Routing](#routing)
- [Security Example](#security-example)
- [Describing multipart/formdata request](#describing-multipartform-data-request)
- [Route settings](#route-settings)
- [Check schema coverage](#check-schema-coverage)
- [Strict mode](#strict-mode)
- [CORS handling](#cors-handling)

## Quickstart

```lua
local openapi = require("gtn.openapi")

local app = openapi(
   require("http.server"),
   require("http.router"),
   "api.yaml",
   {
       security = require("authorization")
   }
)

app:start()
```

As you can see, openapi call takes four positional arguments, which are:
server module, router module, path to read specification from and also a table with
options.

## Routing

The openapi module uses `opeartionId` and `tags` options from [operation object](https://github.com/OAI/OpenAPI-Specification/blob/master/versions/2.0.md#operation-object)
to map controller function to the route. For example, you wrote a `./controllers/example.lua` module:

```lua
local _M = {}
function _M.userinfo(self)
   -- some code here
   return self:render({
       json = {
            data = user_data
       }
   })
end

return _M
```

Operation object from spec file should look something like this:

```yaml
/example:
  get:
    tags:
      - example
    operationId: "userinfo"
    summary: "Example request"
    # ...
```

So, the module will map `GET /example` request to be handled by `userinfo` function in `controllers.example` module.
All the modules must be stored within the `controllers` directory, because the module exploits tarantool-http's ability
to map handlers with a `controller#action` string. Place your controller modules inside the **controllers** folder, relative
to your `app_dir` option.

The controller module may also return a function instead of a table, in that case just make sure your `example.lua` module
returns the function and drop the operationId from operation object schema.

Note that the module maps only the first tag of the list, every other tag would be ignored.

## Security Example

The `security` option contains either a table of methods to handle security schemas described
in your spec-file, or a function if you don't have multiple authorization protocols.

api.yaml

```yaml
components:
securitySchemes:
  bearerAuth:
    type: http
    scheme: bearer
  apiKeyAuth:
    type: apiKey
    in: header
    name: X-API-KEY
  basicAuth:
    type: http
    scheme: basic
  cookieAuth:
    type: apiKey
    in: cookie
    name: cookiename
```

authorization.lua file

```lua
local _M = {}

function _M.bearerAuth(url, scopes, token)
    -- validate token
    return result, err
end

function _M.apiKeyAuth(url, scopes, api_key)
    -- validate API-key
    return result, err
end

function _M.basicAuth(url, scopes, username, password)
    -- validate user credentials
    return result, err
end

function _M.cookieAuth(url, scopes, cookie)
    -- validate cookie here
    return result, err
end

return _M
```

The module correlate those automatically by the name of security scheme and method.
and also sends corresponding arguments to the function. The basic authorization header is
decoded from base64 and also splits by ":" symbol to form username and password.

The `url` argument is the current request's path, taken from `request_object.req.path`.
The scopes are sent from the security option in the operation object schema:

```yaml
get:
  tags:
    - example
  operationId: "userinfo"
  summary: "Example request"
  security:
    - bearerAuth: ["test_scope", "example_scope", "etc_scope"] #here they are
```

As for token, api_key and username\password pair: those are, obviously, your authorization data,
that needs to be checked in order to proceed with the request handling process.

Authorization functions must return two values. In case of an error, be sure to `return nil, error_string`,
in case of successful authorization just return current user's data, that you may later access inside your
controller function. For example, inside of our `controllers/example.lua` described above:

```lua
function userinfo(self)
    local user_data = self.authorization

    return self:render({
        json = {
            data = user_data
        }
    })
end
```

You may also override default error handling with a function:

```lua
local openapi = require("gtn.openapi")

local app = openapi(
   require("http.server"),
   require("http.router"),
   "api.yaml",
   {
       security = require("authorization")
   }
)

-- the default error override
-- invalid repsponse format, or some crucial option that is not set for the endpoint will end up here
app:default(
   function(ctx, err)
        return ctx:render({
            status = 204,
            json = {
                success = false,
                message = err,
                error   = "No Content"
            }
        })
   end
)

-- all unexpected errors during the call of the actual handler will end up here
app:error_handler(
   function(ctx, err)
        -- err argument here will be a table most of the time
        return ctx:render({
            json = {
                success = false,
                errors  = err
            }
        })
   end
)

-- the second return value of our `bearerAuth`, `apiKeyAuth` and `basicAuth` functions will be here
app:security_error_handler(
   function(ctx, err)
        return ctx:render({
            status = 401,
            json = {
                success = false,
                error   = "Unauthorized",
                message = err
            }
        })
   end
)

-- override the default 404 handler if needed
-- 404.html file form the "/templates" folder will be rendered by default
-- the first parameter is either a function, or a boolean value
-- the second parameter is the matching pattern
app:not_found_handler(
   function(ctx)
       return ctx:render({
           json = {
               success = false,
               error   = "Not found"
           }
       })
   end,
   "/api/v1/*path"
)

-- to render default 404 for any unmatched path
app:not_found_handler(true)


-- all of the request parameters validation errors would end up here
-- by default the response in json = { error = err } with http-status of 400
app:bad_request_handler(
   function(ctx, err)
       ctx:render({
           status = 400,
           json = {
               success = false,
               error   = err,
               msg     = "Bad request"
           }
       })
   end
)
```

## Describing multipart/form-data request

OpenAPI specification has two options to describe a file parameter for now:

```yaml
# this one is for raw binary file data
/upload/binary:
  post:
    tags:
      - main
    operationId: "upload_binary"
    requestBody:
      content:
        multipart/form-data:
          schema:
            type: object
            properties:
              file:
                type: string
                format: binary

# this one is for base64-encoded binary
/upload/bytes:
  post:
    tags:
      - main
    operationId: "upload_bytes"
    requestBody:
      content:
        multipart/form-data:
          schema:
            type: object
            properties:
              file:
                type: string
                format: bytes
```

Take note, that inside of an openapi validator, the _bytes_ and _binary_ formats are actually treated
as an object and not a string value. So, inside of a controller function the **file** parameter will be a table containing:

- **data** — binary file content
- **headers** — file headers, containing _filename_ and _name_ which are: actual file name(~duh) and parameter name accordingly
- **mime** — a mime type of the file: image/jpeg, image/png etc.

## API versioning

There's a possibility to pass multiple schemas to the openapi object constructor function. It's primarily aimed to add
an ability to maintain several versions of your API.

```lua
-- app.lua file
local openapi = require("gtn.openapi")

local schema_options = {
   base_path         = "schemas",
   primary_schema    = "base.yaml",
   secondary_schemas = {
       {
           schema = "api_v2.yaml",
           path = "/api/v2",
       },
       {
           schema = "api_v3.yaml"
       },
       {
           schema = "relative.yaml",
           path   = "/relative",
           relative = true
       }
   }
}

local app = openapi(
    require("http.server"),
    require("http.router"),
     schema_options,
    {
        security = require("authorization")
    }
)

app:start()
```

Let's take a closer look to _schema_options_ table fields:

- **base_path** — option indicates in which directory the schemas will be located, in this case the server will look for
  a schemas folder relatively to your _app_dir_ option
- **primary_schema** — quite self-descriptive: the primary schema from which the server settings and all of the basic
  paths and components will be taken
- **secondary_schemas** — a list of additional schemas, in this case a v2 and v3 of our API.
- **schema** — in secondary_schemas is a name of a file relative to our **base_path** option, i.e **./schemas/v2.yaml** and **./schemas/v3.yaml** in this case.
- **path** — is a prefix to all the paths, described in current schema. If this option is not set, this file will simply extend the primary schema.
  Please note, that if there's a global path option set in primary schema, it'll also be applied to this one's paths.
- **relative** - is and option that idicates, that given schema paths would be relative to primary ones, i.e. the primary
  schema's base_path would be a prefix to every path withing this schema

You may also set new schema without changing the old-way options, just by calling a couple of new methods:

```lua
-- app.lua file
local app = openapi(
   require("http.server"),
   require("http.router"),
    "schema.yaml",
   {
       security = require("authorization")
   }
)

--[[
   the first argument is the path to the schema file to read
   the second one is actually a base_path option from before.
   this calls will add new secondary schemas inside of openapi object
]]
app.openapi:add_schema("./schemas/api_v2.yaml", "/api/v2")
app.openapi:add_schema("./schemas/api_v3.yaml")

-- calling this method will automatically set new routes to server object
app:bind_paths()
```

## Route settings

There are additional tweaks for a single path object, that are set in a special option, called **x-settings**. For example,
you have a global prefix for your API endpoints:

```yaml
servers:
   - url: http://localhost:{port}/{path}/
   description: 'development'
   variables:
     port:
       default: '8080'
     path:
       default: 'api/v1' # this one here
```

And you need just a couple of enpoints to ignore this options and be outside of "/api/v1' path. It's simple: just add
an x-settings option with fullPath inside of those:

```yaml
/outside_path:
  get:
    x-settings:
      fullPath: true
    responses:
      200:
        desciption: I am outside
/outside_too:
  post:
    x-settings:
      fullPath: true
    responses: ...
```

It primarily has some features for automatic schema testing, that are initiated by **./app.lua --test** command. For, example,
if you want to exclude some parts of api from being tested or you expet some other http-code in response:

```yaml
  /outside_path:
    get:
      x-settings:
        fullPath: true
        skipTest: true # this endpoint will skip testing
  /outside_too:
    post:
      x-settings:
        fullPath: true
        testStatus: 403 # Will look for 403 schema in responses part
    responses:
      # not this one
      200:
        desciption: Ok
      # yup, this one
      403:
        description: Bad Request
          content:
            application/json:
              schema:
                type: object
                required:
                  - success
                properties:
                  success:
                    type: boolean
                    # will expect this value in assertion
                    example: true
                  error:
                    type: string
                    # this field is optional, but if exists, this value will be expected during auto testing
                    example: invalid parameters
```

## Check schema coverage

There's a command to check schema controller coverage, i.e. to determine which parts of the schema do not have actual
controllers written. For example, you wrote a simple schema with 3 paths:

```yaml
paths:
  /this_one:
    get:
      tags:
        - example
      operationId: this_one
      responses:
        200:
          description: ok
  /that_one:
    get:
      tags:
        - example
      operationId: that_one
      responses:
        200:
          description: ok
  /another_one:
    get:
      tags:
        - example
      operationId: another_one
      responses:
        200:
          description: ok
```

Also, you have **example.lua** file inside your project's **controllers** directory:

```lua
-- example.lua
local _M = {}

function _M.this_one(self)
    return self:render({
        json = {
            success = true
        }
    })
end

return _M
```

And you want to find parts of your API not covered by handlers. Just run the command:

```bash
./app.lua --test coverage
FAILED TOTAL: 2
FAILED PATHS:
/that_one
/another_one
```

See, there are two endpoints described in openapi schema, but not actually handled. This feature is particularly handy if you have a
massive several-thousand-lined schema.

## Strict mode

To set the strict parameter validation mode set the strict parameter in options to true:

```lua
local app = openapi(
    require("http.server"),
    require("http.router"),
     "schema.yaml",
    {
        security = require("authorization"),
        strict   = true
    }
)
```

## CORS handling

You may set cors handling by setting the **cors** option to your openapi instance initialization

#### Example

```lua
local openapi = require("gtn.openapi")

local app = openapi(
    require("http.server"),
    require("http.router"),
    "api.yaml",
    {
        security = require("authorization"),
        cors     = {
            -- default value 3600
            max_age = 18400,
            -- default value true
            allow_credentials = false,
            -- default {"Authorization", "Content-Type"}
            allow_headers = {"Authorization", "Content-Type", "X-Requested-With"},
            -- default {"*"}
            allow_origin = {"http://example.com"}
        }
    }
)

app:route({path="/api/user", method="GET"}, some_handler)

app:start()
```

To set default CORS settings:

```lua
local openapi = require("gtn.openapi")

local app = openapi(
   require("http.server"),
   require("http.router"),
   "api.yaml",
   {
       security = require("authorization"),
       cors     = {} -- takes only a table value
   }
)
app:start()
```

The default CORS options should suffice for the development process.
