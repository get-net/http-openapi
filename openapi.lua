-- tnt modules
local base64_encode = require("digest").base64_encode
local base64_decode = require("digest").base64_decode
local uuid          = require("uuid")
local fio           = require("fio")
local fun           = require("fun")

-- lua modules
local neturl        = require("net.url")

-- helpers
local util   = require("gtn.util")

--[[
    set variables for test cases beforehand
    kinda lazy-loading
]]
local json, tap, uri

local function read_spec(spec_path)
    assert(
        fio.path.is_file(spec_path),
        ("Spec file %s does not exist"):format(spec_path)
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
        ("Specification file %s is not valid"):format(spec_path)
    )

    return res
end

local _M = {}
local _V = {}
local _U = {}
local _T = {}
local mt = {}

function mt:__call(httpd, spec_path, options)
    local openapi = self:new(read_spec(spec_path))

    if not app_config then
        util.read_config()
    end

    local server_settings = openapi:read_server()

    if not server_settings.socket then
        -- overrides server settings from openapi schema sets 8080 as a default port if not set
        httpd = httpd.new(server_settings.host, server_settings.port or 8080, app_config.server_options)
    else
        local out_port = server_settings.socketPath and ("/%s/%s"):format(server_settings.socketPath, server_settings.socket) or
            server_settings.socket
        httpd = httpd.new("unix/", out_port, app_config.server_options)
    end

    httpd.openapi = openapi
    httpd.openapi.server_settings = server_settings or {}

    local routes = openapi:parse_paths()

    for _, v in next, routes do
        httpd:route(v.options, v.controller)
    end

    httpd.options.handler = _U.handler

    httpd.default                 = _U.httpd_default_handler
    httpd.error_handler           = _U.httpd_error_handler
    httpd.security_error_handler  = _U.httpd_security_error_handler

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

    function self:read_server()
        if not self.servers then
            return {}
        end

        -- form server settings and unfold variables object
        local current = fun.filter(
            function(val)
                if app_config.is_test then
                    return val.description == "test"
                end
                return val.description == app_config.__name
            end,
            self.servers
        ):map(
            function(val)
                local server_params = util.read_path_parameters(val.url)

                if next(server_params) and not val.variables then
                    error(("Server variables are not set for %q environment: %s"):format(app_config.__name, val.url))
                end

                local parsed_url
                if val.variables then
                    val.variables = fun.map(
                        function(k, v)
                            return k, v.default
                        end,
                        val.variables
                    ):tomap()

                    for _, param in next, server_params do
                        local pattern = ("{%s}"):format(param)
                        local value = assert(
                            val.variables[param],
                            ("Variable %q is not set for %s server options"):format(param, app_config.__name)
                        )

                        value = value:strip("/")

                        val.url = val.url:gsub(pattern, value)
                    end

                    parsed_url = neturl.parse(val.url)

                    parsed_url = fun.reduce(
                        function(r, k, v)
                            r[k] = v
                            return r
                        end,
                        parsed_url,
                        val.variables
                    )
                else
                    parsed_url = neturl.parse(val.url)
                end

                return parsed_url
            end
        ):totable()

        local _, settings = next(current)

        if not settings then
            error(("\nServer settings for %s are not set.\n"):format(app_config.__name))
        end

        return settings
    end

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
                        controller = ("%s#%s"):format(tag, opts.operationId)
                    end

                    local auth = opts.security and self:parse_security_schemes(opts.security) or nil

                    local _path = self:form_path(
                        path,
                        method
                    )

                    table.insert(res, {
                        options = {
                            settings     = opts['x-settings'],
                            method       = method,
                            path         = util.parse_path(_path),
                            openapi_path = path,
                            security     = auth
                        },
                        controller = controller
                    })
                    return res
                end,
                result
            )
        end

        if self.security then
            self.global_security = self:parse_security_schemes(self.security)
        end

        return result
    end

    function self:parse_security_schemes(scheme)
        local _, v = next(scheme)
        local key, scope = next(v)
        local options
        if self.components.securitySchemes then
            options = self.components.securitySchemes[key]
            if not options then
                error(
                    ("Schema %s is not described in securitySchemes"):format(key)
                )
            end
        end
        return {
            name = key,
            scope = scope,
            options = options
        }
    end

    function self:has_params(path, method, ctype)
        if not self.paths[path] then
            return false, "Bad Request"
        end

        if not self.paths[path][method] then
            return false, ("%s method is not supported"):format(method:upper())
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
                return false, ("Content-type %s is not supported"):format(ctype)
            end
        end

        return true
    end

    function self:form_params(path, method, ctype)
        local opts = self.paths[path]

        if not opts then
            error(("Path options not found: %s"):format(path))
        end

        local body = opts[method].requestBody

        local query = opts[method].parameters

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
                        ("Field %s was not found in reference %s"):format(v, str)
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

    function self:form_path(relpath, method)
        method = method:lower()
        local opts = self.paths[relpath]

        if not opts then
            error(("options for %s not found"):format(relpath))
        end

        local settings = opts[method]['x-settings'] or {}

        if self.server_settings.path and not settings.fullPath then
            local res = self.join_path(self.server_settings.path, unpack(relpath:split("/")))
            return res
        end

        return relpath
    end

    function self.join_path(base, ...)
        if not type(base) == "string" then
            error("First argument must be a string")
        end

        local parsed = neturl.parse(base)

        parsed.path = fun.reduce(
            function(res, val)
                if #val > 0 then
                    if not res:endswith("/") and not val:startswith("/") then
                        res = res.."/"
                    end

                    if res:endswith("/") and val:startswith("/") then
                        val = val:sub(2, #val)
                    end

                    res = res .. val
                end

                return res
            end,
            parsed.path,
            {...}
        )

        return tostring(parsed:normalize())
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

function _U.apiKey(ctx, name, goes_in)
    if goes_in == "header" then
        return ctx.req.headers[name:lower()]
    elseif goes_in == "cookie" then
        local val = ctx.req.headers["cookie"]

        return val and val:match(("%s=([^;]*)"):format(name)) or ""
    end
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
    local security = ctx.endpoint.security or (ctx.endpoint.openapi_path and ctx.httpd.openapi.global_security)

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
            local auth_data, additional = _U[scheme](ctx, security.options.name, security.options['in'])
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
        -- in case of no actual parameters and no required ones
        if not next(val) and not spec.required then
            return {}
        end

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

function _T.set_manual_tests()
    _T.manual = {}

    if fio.path.exists("tests") then
        _T.manual = fun.filter(
            function(val)
                return val:startswith("test")
            end,
            fio.listdir("tests")
        ):totable()
    end
end

function _T.set_env(ctx)
    print("RUNNING TESTS:\n")

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

    if not ctx.openapi.server_settings then
        error("Test server settings not set")
    end

    --local server_settings = fun.filter(
    --    function(val)
    --        return val.description == "test"
    --    end,
    --    server_settings
    --):totable()[1]

    _T.server_settings = ctx.openapi.server_settings
    _T.set_manual_tests()

    return
end

function _T.run(ctx)
    -- set variables set before to respective modules
    json, tap, uri = require("json"), require("tap"), require("net.url")

    -- set local http-client instance just for testing purposes and nothing else
    _T.client = require("http.client").new({5})

    -- sets the testing env
    _T.set_env(ctx)

    -- shutdown request loggin to not get unwanted io data
    ctx.options.log_requests = false

    -- starts the mock server
    local _ = _T.httpd_start(ctx)

    if fio.path.exists("tests/before.lua") then
        print("\nRunning before script:\n")
        dofile("tests/before.lua")
    end

    _T.run_path_tests(ctx)

    _T.run_user_tests()

    if fio.path.exists("tests/after.lua") then
        print("\nRunning after script:\n")
        dofile("tests/after.lua")
    end

    print("\nTesting complete. Shutting down...\n")
    _T.httpd_stop(ctx)
    os.exit(0)
end

function _T.encode_query(opts)
    return fun.reduce(
        function(res, key, val)
            local str = ("%s=%s"):format(key, val)

            if #res > 0 then
                res = res .. ("&%s"):format(str)
            else
                res = str
            end

            return res
        end,
        "",
        opts
    )
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
    local settings = table.deepcopy(_T.server_settings)

    settings.path = relpath
    settings.port = _T.server_settings.port
    settings.path = settings.path:gsub("//", "/")
    settings.query = uri.buildQuery(query)

    if method ~= "GET" then
        if opts.headers['content-type'] == 'application/x-www-form-urlencoded' then
            body = _T.encode_query(body)
        else
            body = json.encode(body)
        end
    else
        body = ""
    end

    return {
        method,
        tostring(settings),
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

        if sec_schema['in'] == "cookie" then
            rawset(headers, "cookie", ("%s=%s"):format(sec_schema.name, value))
        else
            rawset(headers, sec_schema.name, value)
        end
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
        local s, k, path = pcall(next, val)

        if s and k == "$ref" and path then
            val = ctx.openapi:ref(path)
        end

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
            if schema.content[ctype].schema['$ref'] then
                schema = ctx.openapi:ref(schema.content[ctype].schema['$ref'])
                goto redo
            end

            schema = schema.content[ctype].schema.properties
            is_properties = true
            goto redo
        end

        -- -- it's bad
        if val.type == "object" and not val.example then
            local d = _T.form_expected(ctx, {
                content = {
                    [ctype] = {
                        schema = val
                    }
                }
            })

            val = {example = d}
        end

        -- yup, it's bad too
        if val.type == "array" and not val.example then
            local reffed = val.items['$ref']

            if reffed then
                local d = ctx.openapi:ref(reffed)
                d = _T.form_expected(ctx, {
                    content = {
                        [ctype] = {
                            schema = d
                        }
                    }
                })

                val = {example = {d}}
            end
        end

        if is_properties then
            rawset(result, key, val.example)
        end
    end

    return result
end

function _T.run_path_tests(ctx)
    _T.test_config      = require("tests.config")

    print("\nRunning automatic tests:\n")

    for path, options in next, ctx.openapi.paths do
        for method, opts in next, options do
            local settings = opts['x-settings'] or {}
            if not settings.skipTest then
                local headers = {}
                local ctype

                if opts.security then
                    for _, val in next, opts.security do
                        _T.form_security(ctx, headers, val)
                    end
                elseif ctx.openapi.security then
                    for _, val in next, ctx.openapi.security do
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

                local _path = ctx.openapi:form_path(
                    path,
                    method
                )

                local params = ctx.openapi:form_params(path, method, ctype, _path)

                local body, query = {}, {}

                if method ~= "get" and params.body then
                    params.body.required = params.body.required or {}
                    body = fun.map(
                        function(name, vars)
                            --[[
                                check, whether this parameter is required
                                 then assert that it has an example value set in openapi schema
                                 throw an error otherwise
                            ]]
                            if fun.any(function(val) return val == name end,params.body.required) then
                                local msg = ("Example variable not set for the %q parameter in %s %s"):format(name, method, _path)
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
                            local schema_msg = ("Schema option not set for the %q parameter in %s %s"):format(vars.name, method, _path)
                            assert(vars.schema, schema_msg)
                            if vars.required or vars['in'] == "path" then
                                local msg = ("Example variable not set for the %q parameter in %s %s"):format(vars.name, method, _path)
                                assert(vars.schema.example, msg)
                            end

                            if vars['in'] == "query" then
                                return vars.name, vars.schema.example
                            else
                                local pattern = ("{%s}"):format(vars.name)
                                _path = _path:gsub(pattern, vars.schema.example)
                            end

                            return vars,name
                        end,
                        params.query
                    ):tomap()
                end

                -- curl takes only uppercase method, responses with protocol error otherwise
                method = method:upper()

                local request_data = _T.form_request(method, _path, query, body, {headers = headers})

                local resp = _T.send_request(request_data)

                _T.test:ok(resp.status == settings.testStatus or 200, ("%s %s OK STATUS"):format(method, _path))

                local resp_body = _T.json(resp)
                local resp_schema = opts.responses[resp.status]

                _T.test:ok(resp_schema, ("%s %s %s RESPONSE SCHEMA EXISTS"):format(method, _path, resp.status))

                if resp_schema then
                    local expected = _T.form_expected(ctx, resp_schema)

                    _T.test:is_deeply(resp_body, expected, ("%s %s RESPONSE MATCH"):format(method, _path))
                else
                    print("Skipping response match. REASON: no schema\n")
                end
                print("\n")
            end
        end
    end
end

function _T.run_user_tests()
    if _T.manual and next(_T.manual) then
        print("Running user tests:\n")

        for _, val in next, _T.manual do
            if not val:match("test_before") then
                dofile(("tests/%s"):format(val))
            end
        end
    end
end

return _M
