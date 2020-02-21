-- tnt imports
local base64_encode = require("digest").base64_encode
local base64_decode = require("digest").base64_decode
local uuid          = require("uuid")
local fio           = require("fio")
local fun           = require("fun")

-- helpers
local sprintf = string.format

--[[
    set variables for test cases beforehand
    kinda lazy-loading
]]
local json, tap, log, uri

local function read_spec(spec_path)
    assert(
        fio.path.is_file(spec_path),
        sprintf("Spec file %s does not exist", spec_path)
    )

    local tab = spec_path:split(".")
    local ext = tab[#tab]
    assert(ext == "yaml" or ext == "json", "Invalid openapi file extension")
    local decoder = require(ext)
    local file = fio.open(spec_path, {"O_RDONLY"})

    local data = file:read()
    local status, res = pcall(decoder.decode, data)
    assert(
        status,
        sprintf("Specification file %s is not valid", spec_path)
    )

    return res
end

local _M = {}
local _V = {}
local _U = {}
local _T = {}
local mt = {}

function mt:__call(httpd, spec_path, options)
    httpd.openapi = self:new(read_spec(spec_path))
    local routes = httpd.openapi:parse_paths()

    for _, v in next, routes do
        httpd:route(v.options, v.controller)
    end
    httpd.options.handler = _U.handler

    httpd.default                = _U.httpd_default_handler
    httpd.error_handler          = _U.httpd_error_handler
    httpd.security_error_handler = _U.httpd_security_error_handler

    _T.httpd_start = httpd.start
    _T.httpd_stop  = httpd.stop

    httpd.start = _T.start

    for k, v in next, options do
        rawset(httpd.options, k, v)
    end

    return httpd
end

setmetatable(_M, mt)

function _M:new(spec)
    local obj = spec or {}

    function self:parse_paths()
        local result = {}
        for path, methods in next, self.paths do
            fun.map(
                function(method, opts)
                    local options = table.deepcopy(opts)
                    options.method = method
                    options.path = path
                    return options
                end,
                methods
            ):reduce(
                function(res, opts)
                    opts.tags = opts.tags or {"default"}
                    -- gets the first tag from value
                    local _, tag = next(opts.tags)
                    local method = opts.method:upper()
                    if not tag then
                        return res
                    end

                    local controller = tag
                    if opts.operationId then
                        controller = sprintf("%s#%s", tag, opts.operationId)
                    end

                    local auth
                    if opts.security then
                        local _, v = next(opts.security)
                        local key, scope = next(v)
                        local options
                        if self.components.securitySchemes then
                            options = self.components.securitySchemes[key]
                            if not options then
                                error(sprintf(
                                    "Schema %s is not described in securitySchemes",
                                    key
                                ))
                            end
                        end
                        auth = {
                            name = key,
                            scope = scope,
                            options = options
                        }
                    end

                    table.insert(res, {
                        options = {
                            method = method,
                            path   = self.parse_path(path),
                            openapi_path = path,
                            security = auth
                        },
                        controller = controller
                    })
                    return res
                end,
                result
            )
        end

        return result
    end

    function self:has_params(path, method, ctype)
        if not self.paths[path] then
            return false, "Bad Request"
        end

        if not self.paths[path][method] then
            return false, sprintf("%s method is not supported", method:upper())
        end

        local options = self.paths[path][method]

        if method == "post" then
            if not options.requestBody then
                return false
            end

            if not ctype then
                return false, "No Content-Type in request"
            end

            if not options.requestBody.content[ctype] then
                return false, sprintf("Content-type %s is not supported", ctype)
            end
        end

        return true
    end

    function self:form_params(path, method, ctype)
        local body = {}
        if method == "post" and ctype then
            body = self.paths[path][method].requestBody
        end

        local query = self.paths[path][method].parameters

        local result = {
            query = query or {}
        }

        if body then
            if not ctype then
                return result
            end

            body = self:form_post(body.content[ctype].schema)
            result.body  = body
        end

        return result
    end

    function self:form_post(parameters)
        if type(parameters) ~= "table" then
            return {}
        end

        local result = {}
        for k, v in next, parameters do
            -- in case of $ref in schema, there's no other fields, so break and go on
            if k == "$ref" then
                local schema = self:ref(v)
                result = schema
                break
            else
                rawset(result, k, v)
            end
        end
        return result
    end

    function self:ref(str)
        local pathtab = str:match("#%/(.+)"):split("/")
        return fun.reduce(
            function(res, v)
                local field = next(res) and res[v] or self[v]

                if not field then
                    error(
                        sprintf("Field %s was not found in reference %s", v, str)
                    )
                end
                return field
            end,
            {},
            pathtab
        )
    end

    function self.validate_params(ctx)
        local errors = _V.validate(ctx)

        if next(errors) then
            return nil, errors
        end

        return true
    end

    function self.parse_path(p)
        local res = p
        for path_param in p:gmatch("{(%w+)}") do
            local sub = sprintf("{%s}", path_param)
            res = res:gsub(sub, ":"..path_param)
        end
        return res
    end

    setmetatable(obj, self)
    self.__index = self

    return obj
end

-- utility functions
function _U.bearer(ctx)
    local header = ctx.req.headers.authorization

    if not header then
        return
    end

    return header:match("Bearer (%w+)")
end

function _U.basic(ctx)
    local header = ctx.req.headers.authorization

    if not header then
        return
    end

    local creds = base64_decode(header:match("Basic (%w+)"))
    if not creds then
        return
    end
    return creds:match("(%w+):(%w+)")
end

function _U.apiKey(ctx, name)
    return ctx.req.headers[name:lower()]
end

local function not_implemented(self, tag, operationId)
    return self:render({
        status = 501,
        json = {
            error       = "Not Implemented",
            tag         = tag,
            operationId = operationId
        }
    })
end

local function bad_request(self)
    return self:render({
        status = 400,
        json = {
            error = "Bad Request"
        }
    })
end

function _U.bind_security(ctx)
    local security = ctx.endpoint.security
    if security ~= nil then
        local auth_handler
        if not ctx.httpd.options.security then
            return nil, "Security options are not specified for this server instance"
        end

        if type(ctx.httpd.options.security) == "table" then
            auth_handler = ctx.httpd.options.security[security.name]
        else
            auth_handler = ctx.httpd.options.security
        end

        if auth_handler then
            local scheme = security.options.scheme or security.options.type
            local auth_data, additional = _U[scheme](ctx, security.options.name)
            if not auth_data then
                return nil, "Authorization data not found"
            else
                local err
                ctx.authorization, err = auth_handler(ctx.req.path,  security.scope, auth_data, additional)

                if err then
                    return nil, err
                end
            end
        else
            return nil, "Security handler is not implemented"
        end
    end

    return
end

-- tweaked request handler
function _U.handler(self, ctx)
    local format = 'html'
    local pformat = string.match(ctx.req.path, '[.]([^.]+)$')

    if pformat ~= nil then
        format = pformat
    end

    local r = self:match(ctx.req.method, ctx.req.path)

    if r == nil then
        bad_request(ctx)

        return ctx.res
    else
        r.stash.format = format

        ctx.endpoint = r.endpoint
        ctx.tstash   = r.stash
    end

    ctx.headers = ctx.headers or {}

    local _, s_err = _U.bind_security(ctx)
    if s_err then
        local msg = self.security_error_handler(ctx, s_err)
        if ctx.res then
            return ctx.res
        end
        return msg
    end

    if ctx.endpoint.openapi_path then
        _, errors = ctx.httpd.openapi.validate_params(ctx)

        if errors then
            local msg = self.error_handler(ctx, errors)

            if ctx.res then
                return ctx.res
            end

            return msg
        end
    end

    if self.hooks.before_dispatch ~= nil then
        local _ = self.hooks.before_dispatch(ctx)

        if ctx.res then
            return ctx.res
        end
    end

    local status, err = pcall(r.endpoint.sub, ctx)

    if not status then
        local tag, op_id
        for _, val in next, _U.ni_patterns do
            tag, op_id = err:match(val)

            if tag ~= nil then
                break
            end
        end

        if tag or op_id then
            not_implemented(ctx, tag, op_id)
        else
            self.error_handler(ctx, err)
        end

        return ctx.res
    end

    if self.hooks.after_dispatch ~= nil then
        self.hooks.after_dispatch(ctx)
    end

    if not ctx.res then
        self.default(ctx, "No Content")
    end

    return ctx.res
end

function _U.httpd_default_handler(self, f)
    if type(f) ~= "function" then
        return self:render({
            status = 204,
            json = {
                error = f
            }
        })
    end

    local init = function(ctx, err)
        return f(ctx, err)
    end
    self.default = init
end

function _U.httpd_error_handler(self, f, ...)
    if type(f) ~= "function" then
        error(f)
    end

    local init = function(ctx, err)
        return f(ctx, err)
    end
    self.error_handler = init
end

function _U.httpd_security_error_handler(self, f)
    if type(f) ~= "function" then
        error(f)
    end

    local init = function(ctx, err)
        return f(ctx, err)
    end
    self.security_error_handler = init
end

_U.ni_patterns = {
    [[Can't load module "(.*)": "(.*)"]],
    [[Controller "(.*)" doesn't contain function "(.*)"]],
    [[require "(.*)" didn't return table]],
    [[Controller "(.*)" is not a function]]
}


-- validation functions
function _V.validate(ctx)
    local c, a = ctx.endpoint.controller, ctx.endpoint.action
    local ctype = ctx.req.headers['content-type']
    local req_path, method = ctx.endpoint.openapi_path, ctx.req.method:lower()

    if not req_path then
        return
    end

    if ctype then
        local with_charset = ctype:match("(%S+)[;]:?")

        if with_charset then
            ctype = with_charset
        end
    end

    local has, err = ctx.httpd.openapi:has_params(req_path, method, ctype)

    if err then
        return {err}
    end

    if not has then
        return {}
    end

    if not ctx.httpd.cache.params then
        ctx.httpd.cache.params = {}
    end

    local cache = ctx.httpd.cache.params[c]

    if not cache then
        ctx.httpd.cache.params[c] = {}
    end

    cache = not a and cache or ctx.httpd.cache.params[c][a]

    if not cache then
        if a then
            ctx.httpd.cache.params[c][a] = {}
            cache = ctx.httpd.cache.params[c][a]
        else
            ctx.httpd.cache.params[c] = {}
            cache = ctx.httpd.cache.params[c]
        end
    end

    if not next(cache) then
        local params, p_err = ctx.httpd.openapi:form_params(req_path, method, ctype)

        if p_err then
            error(p_err)
        end

        if action then
            ctx.httpd.cache.params[c][a] = params
        else
            ctx.httpd.cache.params[c] = params
        end
        cache = params
    end

    local res = {}

    if method ~= "get" and cache.body then
        local post = ctx:post_param()

        _V.runs = 0
        if cache.body then
            --[[
                ctx arg goes last as optional, 'cause this call may execute
                object validation as well as string or an array validation
            ]]
            if cache.body.type then
                res = _V[cache.body.type](post, cache.body, ctx)
            end

            if _V.runs <= 0 then
                res = next(res) and {body = res} or res
            end
        end
    end

    _V.validate_query(ctx, cache.query, res)
    return res or {}
end

function _V.validate_query(ctx, spec, res)
    local query = ctx:query_param()
    local stash = ctx.endpoint.stash

    if next(stash) then
        stash = fun.map(
            function(name)
                return name, ctx:stash(name)
            end,
            stash
        ):tomap()
    end

    if not next(spec) and (next(query) or next(stash)) then
        return fun.chain(query, stash):reduce(
            function(_res, key)
                _res[key] =_V.p_error("unknown")
                return _res
            end,
            res
        )
    else
        fun.chain(query, stash):reduce(
            function(_res, key)
                if not fun.any(function(val) return val.name == key end, spec) then
                    _res[key] = _V.p_error("unknown")
                end
                return _res
            end,
            res
        )
    end

    return fun.reduce(
        function(_res, param)
            local value
            if param['in'] == "query" then
                value = query[param.name]
            elseif param['in'] == "path" then
                value = stash[param.name]
            end

            if value == nil and not param.required then
                return _res
            end

            if not value then
                _res[param.name] = _V.p_error("missing")
                return _res
            end

            local vtype = param.schema.format or param.schema.type

            if not _V[vtype](value) then
                _res[param.name] = _V.p_error("invalid", vtype, type(value))
            end

            if param.schema.enum then
                local ok = _V.enum(value, param.schema.enum)

                if not ok and not param.schema.nullable then
                    _res[param.name] = _V.p_error("invalid", param.schema.enum, value)
                end
            end

            return _res
        end,
        res,
        spec
    )
end

function _V.object(val, spec, ctx)
    if not _V.is_object(val) then
        local first_run = (_V.runs == 0)
        return first_run and _V.p_error("invalid", "object", type(val)) or false
    end

    _V.runs = _V.runs + 1
    local required = spec.required or {}
    local obj = spec.properties

    local absent = fun.map(
        function(key, param)
            local k, v = next(param)
            if k == "$ref" then
                local reference = ctx.httpd.openapi:ref(v)
                if reference then
                    param = reference
                    required = reference.required or {}
                    obj[key] = param
                end
            end

            local is_required = fun.any(
                function(_v)
                    return _v == key
                end,
                required
            )

            if is_required and not val[key] then
                return key, _V.p_error("missing")
            end
            return key, nil
        end,
        obj
    ):tomap()

    return fun.reduce(
        function(res, key, param)
            if not obj[key] then
                rawset(res, key, _V.p_error("unknown"))
                return res
            end

            local ptype = obj[key].format or obj[key].type

            local r

            if ptype == "object" then
                r = _V[ptype](val[key], obj[key], ctx)
            else
                r = _V[ptype](param)
            end
            if not r then
                rawset(res, key, _V.p_error("invalid", ptype, type(param)))
                return res
            end

            if type(r) == "table" and next(r) then
                if not _V.is_object(r) then
                    rawset(res, key, r)
                    return res
                end

                local _t = {}
                for k, v in next, r do
                    rawset(_t, k, v)
                end
                rawset(res, key, _t)
            end

            return res
        end,
        absent,
        val
    )
end

function _V.is_object(obj)
    if type(obj) ~= "table" then
        return false
    end
    local k, v = next(obj)
    return type(k) == "string" and v ~= nil
end

function _V.string(s)
    return type(s) == "string"
end

_V.password = _V.string
_V.byte     = _V.string
_V.binary   = _V.string

function _V.integer(i)
    return type(i) == "number"
end

_V.double = _V.integer
_V.float  = _V.integer
_V.int32  = _V.integer
_V.int64  = _V.integer

function _V.email(email)
    if not _V.string(email) then
        return false
    end
    return email:match('[(%w+)%p*]+@[%w+%p*]+%.%a+$') ~= nil
end

function _V.uuid(str)
    local s, res = pcall(uuid.fromstr, str)
    return s and res ~= nil
end

function _V.array(t, param)
    local first_run = (_V.runs == 0)
    -- a clumsy hack
    if type(t) ~= "table" or _V.is_object(t) then
        return first_run and {
            details = {
                error    = "invalid",
                expected = "array",
                actual   = type(param)
            }
        } or false
    end

    return {}
end

function _V.enum(val, options)
    return fun.any(function(v) return val == v end, options)
end

function _V.date(str)
    -- lua can't match by length in any other way
    local ok = str:match("^(%d%d%d%d)-(%d%d)-(%d%d)$")
    return ok ~= nil
end

function _V.boolean(val)
    return val == true or val == false
end

_V['date-time'] = function(str)
    -- same here. needs some thinking maybe later
    local ok = str:match("^(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)[.(%d+):?]?")
    return ok ~= nil
end

function _V.p_error(alias, expected, actual)
    return {
        details = {
            error = alias,
            expected = expected,
            actual = actual
        }
    }
end

function _T.start(ctx)
    if fun.any(function(val) return val == "--test" end, arg) then
        return _T.run(ctx)
    end

    return _T.httpd_start(ctx)
end

function _T.set_env(ctx)
    log.info("RUNNING TESTS:\n")

    _T.test = tap.test("openapi-schema")
    local test_count = fun.reduce(
        function(res)
            res = res +1
            return res
        end,
        0,
        ctx.openapi.paths
    )

    _T.test:plan(test_count)

    local server_settings = assert(ctx.openapi.servers)
    server_settings = fun.filter(
        function(val)
            return val.description == "test"
        end,
        server_settings
    ):totable()[1]

    if not server_settings then
        error("Test server settings not set")
    end

    _T.server_settings = uri.parse(server_settings.url)

    return
end

function _T.run(ctx)
    -- set variables set before to respective modules
    json, tap, log, uri = require("json"), require("tap"), require("log"), require("net.url")

    -- set local http-client instance just for testing purposes and nothing else
    _T.client = require("http.client").new({5})

    -- sets the testing env
    _T.set_env(ctx)

    -- overrides server settings from openapi schema
    ctx.host = _T.server_settings.host
    ctx.port = _T.server_settings.port

    -- shutdown request loggin to not get unwanted io data
    ctx.options.log_requests = false

    -- starts the mock server
    _T.httpd_start(ctx)

    _T.run_path_tests(ctx)

    log.info("\nTesting complete. Shutting down...\n")
    _T.httpd_stop(ctx)
    os.exit(0)
end

-- decoding by response's content-type, maybe there'll be more of those later(xml or whatever)
function _T.json(resp)
    local status, decoded = pcall(json.decode, resp.body)

    if not status then
        return nil, "Invalid JSON data: ".. decoded
    end

    return decoded
end

function _T.send_request(args)
    return _T.client:request(unpack(args))
end

function _T.form_request(method, relpath, query, body, opts)
    -- reuse already parsed and existing test server options
    local full_path = table.deepcopy(_T.server_settings)
    full_path.path = relpath
    full_path.query = uri.buildQuery(query)

    body = method ~= "GET" and json.encode(body) or ""


    return {
        method,
        tostring(full_path),
        body,
        opts
    }
end

function _T.form_security(ctx, headers, options)
    -- there are also scopes in second value, but those are unneeded here
    local option = next(options)

    assert(ctx.openapi.components.securitySchemes, "securitySchemes component is not described")
    local err_msg = ("Schema for %s security does not exist in securitySchemes component"):format(option)

    local sec_schema = assert(ctx.openapi.components.securitySchemes[option], err_msg)

    local sec_type = sec_schema.scheme or sec_schema.type

    if sec_type == "bearer" then
        local value = ("Bearer %s"):format(_T.test_config.security[option])
        rawset(headers, "Authorization", value)
    end

    if sec_type == "apiKey" then
        local value = _T.test_config.security[option]
        rawset(headers, sec_schema.name, value)
    end

    if sec_type == "basic" then
        assert(_T.test_config.security[option], "Basic authorization data is not set in tests/config.lua")
        local username, password = _T.test_config.security[option].username, _T.test_config.security[option].password

        local value = ("Basic %s"):format(
            base64_encode(
                ("%s:%s"):format(username, password)
            )
        )

        rawset(headers, "Authorization", value)
    end
end

function _T.form_expected(ctx, schema)
    local is_properties = false
    local result = {}
    local ctype

    ::redo::
    for key, val in next, schema do
        if key == "$ref" then
            if not is_properties then
                schema = ctx.openapi:ref(val)
            else
                key, val = next(ctx.openapi:ref(val))
            end

            goto redo
        end

        if schema.content then
            ctype = next(schema.content)
            schema = schema.content[ctype].schema.properties
            is_properties = true
            goto redo
        end

        if is_properties then
            rawset(result, key, val.example)
        end
    end

    return result
end

function _T.run_path_tests(ctx)
    _T.test_config      = require("tests.config")


    for path, options in next, ctx.openapi.paths do
        for method, opts in next, options do
            local headers = {}
            local ctype

            if opts.security then
                for _, val in next, opts.security do
                    _T.form_security(ctx, headers, val)
                end
            end

            if opts.requestBody then
                ctype = next(opts.requestBody.content)

                local with_charset = ctype:match("(%S+)[;]:?")
                if with_charset then
                    ctype = with_charset
                end

                rawset(headers, "content-type", ctype)
            end

            local params = ctx.openapi:form_params(path, method, ctype)

            local body, query = {}, {}
            if method ~= "get" and params.body then
                body = fun.map(
                    function(name, vars)
                        --[[
                            check, whether this parameter is required
                             then assert that it has an example value set in openapi schema
                             throw an error otherwise
                        ]]
                        if fun.any(function(val) return val == name end,params.body.required) then
                            local msg = ("Example variable not set for the %q parameter in %s %s"):format(name, method, path)
                            assert(vars.example, msg)
                        end
                        return name, vars.example
                    end,
                    params.body.properties
                ):tomap()
            end

            if params.query then
                query = fun.map(
                    function(vars)
                        local schema_msg = ("Schema option not set for the %q parameter in %s %s"):format(vars.name, method, path)
                        assert(vars.schema, schema_msg)
                        if vars.required or vars['in'] == "path" then
                            local msg = ("Example variable not set for the %q parameter in %s %s"):format(vars.name, method, path)
                            assert(vars.schema.example, msg)
                        end

                        if vars['in'] == "query" then
                            return vars.name, vars.schema.example
                        else
                            local pattern = ("{%s}"):format(vars.name)
                            path = path:gsub(pattern, vars.schema.example)
                        end

                        return vars,name
                    end,
                    params.query
                ):tomap()
            end

            -- curl takes only uppercase method, responses with protocol error otherwise
            method = method:upper()

            local request_data = _T.form_request(method, path, query, body, {headers = headers})

            local resp = _T.send_request(request_data)

            _T.test:ok(resp.status == 200, ("%s %s OK STATUS"):format(method, path))

            local resp_body = _T.json(resp)
            local resp_schema = opts.responses[resp.status]
            _T.test:ok(resp_schema, ("%s RESPONSE SCHEMA EXISTS"):format(resp.status))

            local expected = _T.form_expected(ctx, resp_schema)
            _T.test:is_deeply(expected, resp_body, ("%s %s RESPONSE"):format(method, path))
        end
    end
end

return _M
