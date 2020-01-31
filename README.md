 ## Tarantool-http OpenAPI support
 You may use your openapi specification file to map the routes and handlers inside your project.
 
 #### Quickstart
 ```lua
 local server  = require("http.server").new(nil, 5000)
 local openapi = require("http.openapi")
 
 local httpd = openapi(server, 'api.yaml', {
     security = require("authorization")
 })
 
 httpd:start()
 ```
 As you can see, openapi call takes three positional arguments, which are:
 server instance, path to read specification from and also a table with
 options(only takes security for now).
 
 
 #### Routing
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
     operationId: 'userinfo'
     summary: 'Example request'
     # ...
 ```
 So, the module will map `GET /example` request to be handled by `userinfo` function in `controllers.example` module.
 All the modules must be stored within the `controllers` directory, because the module exploits tarantool-http's ability
 to map handlers with a `controller#action` string. Place your controller modules inside the **controllers** folder, relative
 to your `app_dir` option.
 
 The controller module may also return a function instead of a table, in that case just make sure your `example.lua` module
 returns the function and drop the operationId from operation object schema.
 
 Note that the module maps only the first tag of the list, every other tag would be ignored.
 
 #### Security Example
 
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
   operationId: 'userinfo'
   summary: 'Example request'
   security:
     - bearerAuth: ['test_scope', 'example_scope', 'etc_scope'] #here they are
   ...
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
 local server  = require("http.server").new(nil, 5000)
 local openapi = require("http.openapi")
 
 local httpd = openapi(server, 'api.yaml', {
     security = require("authorization")
 })
 
 -- the default return value
 -- ctx is a context value, that is a request object here
 httpd:default(
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
 
 -- this will catch all request validation exceptions, etc. 
 httpd:error_handler(
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
 httpd:security_error_handler(
     function(ctx, err)
         return self:render({
             status = 401,
             json = {
                 success = false,
                 error   = "Unauthorized",
                 message = err
             }   
         })
     end
 )
 ```
 
 You can also wrap openapi return value inside the cors call:
 ```lua
 local server  = require("http.server").new(nil, 5000)
 local openapi = require("http.openapi")
 
 local httpd = openapi(server, 'api.yaml', {
     security = require("authorization")
 })
 
 cors(httpd)
 ```
 
 The default CORS options should suffice for the development process.