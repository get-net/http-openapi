-- tnt modules
local base64_encode = require("digest").base64_encode
local base64_decode = require("digest").base64_decode
local fiber         = require('fiber')
local tsgi          = require("http.tsgi")
local uuid          = require("uuid")
local fio           = require("fio")
local fun           = require("fun")

local prometheus, metrics

-- lua modules
local neturl        = require("net.url")

-- http modules
local http_utils    = require('http.utils')
local lib           = require("http.lib")

-- helpers
local util          = require("gtn.util")

--[[
    set variables for test cases beforehand
    kinda lazy-loading
]]
local json, tap

local default_cors = {
    max_age = 3600,
    allow_credentials = true,
    allow_headers = {"Authorization, Content-Type"},
    allow_origin = {"*"}
}

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
local _P = {}
local _V = {}
local _U = {}
local _T = {}
local mt = {}

function mt:__call(httpd, router, spec_path, options)
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

    router = router.new(app_config.server)

    httpd:set_router(router)

    for k, v in next, options do
        if k == "cors" then
            assert(type(v) == "table", "CORS option must be a table")
            local _cors = default_cors

            for key, val in next, v do
                if not default_cors[key] then
                    error(("Unsupported CORS option %s"):format(key))
                end

                if type(val) ~= type(default_cors[key]) then
                    local msg = ("Invalid type for option %s. Expected %s got %s"):format(
                        k,
                        type(default_cors[key]),
                        type(v)
                    )
                    error(msg)
                end
                rawset(_cors, key, val)
            end

            v = _cors
        end

        rawset(httpd.options, k, v)
    end

    for _, v in next, routes do
        if v.options.security then
            router:use(
                _U.bind_security,
                {
                    preroute = true,
                    name     = "authenticate#"..v.controller,
                    method   = v.options.method,
                    path     = v.options.path
                }
            )
        end

        router:use(
            httpd.openapi.validate_params,
            {
                preroute = true,
                name     = "validate#"..v.controller,
                method   = v.options.method,
                path     = v.options.path
            }
        )

        if httpd.options.cors then
            router:use(
                _U.handle_cors,
                {
                    preroute = true,
                    name     = "cors#"..v.controller,
                    method   = "ANY",
                    path     = v.options.path
                }
            )
        end

        router:route(v.options, v.controller)
    end

    if options.metrics then
        _P.bind_metrics(httpd)
    end

    httpd.default                 = _U.httpd_default_handler
    httpd.error_handler           = _U.httpd_error_handler
    httpd.not_found_handler       = _U.httpd_not_found_handler
    httpd.bad_request_handler     = _U.httpd_bad_request_handler
    httpd.security_error_handler  = _U.httpd_security_error_handler

    _T.httpd_start = httpd.start
    _T.httpd_stop  = httpd.stop

    httpd.start = _T.start

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
            _query = query or {}
        }

        if body then
            if not ctype then
                return result
            end

            body = self:form_post(body.content[ctype].schema)
            result._body  = body
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
        local self = ctx:router()

        local r = self:match(ctx:method(), ctx:path())
        ctx.endpoint = r.endpoint
        ctx.stash    = r.stash

        _U.post_param(ctx)

        if not ctx.render_swap then
            _U.render(ctx)
        end

        if not ctx.handler_swap then
            _U.handler(ctx)
        end

        ctx.query_param = _U.query_param

        local errors = _V.validate(ctx)

        if next(errors) then
            local httpd = ctx['tarantool.http.httpd']

            return httpd.bad_request_handler(ctx, errors)
        end

        return tsgi.next(ctx)
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

function _P.bind_metrics(httpd)
    local router = assert(httpd:router(), "router is not set")
    local prefix = assert(httpd.options.metrics.prefix, "Please set 'prefix' options for your metrics config")
    local path = httpd.options.metrics.path
    local options = httpd.options.metrics.collect

    local status, _p = pcall(require, "prometheus")

    assert(status, "Prometheus module is not installed")

    prometheus = _p

    if options and type(options) == "table" then
        for _, opt in next, options do
            if opt.watch then
                opt.type = "counter"
            end

            local operation = assert(prometheus[opt.type], ("Invalid metric type %s"):format(opt.type))

            local _op = operation(("%s_%s"):format(prefix, opt.name), opt.description)

            if opt.type == "gauge" and opt.call then
                assert(type(opt.call == "function"), ("call option is not a function for %s"):format(opt.name))

                local handle = _P.fiber_operation

                fiber.create(handle, _op, opt.call, opt.step)
            end

            if opt.watch then
                local cont = function(env)
                    _op:inc(1)
                    return tsgi.next(env)
                end

                router:use(
                    cont,
                    {
                        name     = "metrics#"..opt.watch,
                        method   = opt.method,
                        path     = opt.watch
                    }
                )
            end
        end
    end

    metrics = {
        security_errors = prometheus.counter(("%s_security_errors"):format(prefix), "Security error counter"),
        errors          = prometheus.counter(("%s_unhandled_errors"):format(prefix), "Unhandled error counter")
    }

    router:route({
        path = path
    },
        prometheus.collect_http
    )
end

function _P.fiber_operation(operation, f, step)
    while true do
        local val = f()

        operation:set(val)
        fiber.sleep(step or 15)
    end
end


-- utility functions
function _U.bearer(ctx)
    local header = ctx:header("authorization")

    if not header then
        return
    end

    return header:match("Bearer (.*)")
end

function _U.basic(ctx)
    local header = ctx:header("authorization")

    if not header then
        return
    end

    local creds = base64_decode(header:match("Basic (.*)"))
    if not creds then
        return
    end
    return creds:match("(%w+):(%w+)")
end

function _U.apiKey(ctx, name, goes_in)
    if goes_in == "header" then
        local n = name:lower()
        return ctx:header(n)
    elseif goes_in == "cookie" then
        local val = ctx:header("cookie")

        return val and val:match(("%s=([^;]*)"):format(name)) or ""
    end
end

-- bad unescape fpr query parameters
function _U.cached_query_param(self, name)
    if name == nil then
        return self.query_params
    end
    return self.query_params[ name ]
end

function _U.query_param(self, name)
    if self:query() ~= nil and string.len(self:query()) == 0 then
        rawset(self, 'query_params', {})
    else
        local params = lib.params(self['QUERY_STRING'])
        local pres = {}
        for k, v in pairs(params) do
            pres[ http_utils.uri_unescape(k) ] = http_utils.uri_unescape(v, true)
        end
        rawset(self, 'query_params', pres)
    end

    rawset(self, 'query_param', _U.cached_query_param)
    return self:query_param(name)
end

-- overrides response render handling
function _U.render(self)
    local render_func = self.render
    self.render = function(ctx, input)
        local resp = render_func(ctx, input)

        resp.status = input.status

        if ctx.hdrs then
            for k, v in next, ctx.hdrs do
                resp.headers[k] = v
            end
        end

        if input.headers then
            for k, v in next, input.headers do
                resp.headers[k] = v
            end
        end

        return resp
    end
    self.render_swap = true
end

-- overrides route handler with this one
function _U.handler(self)
    local handler_func = self.endpoint.handler

    self.endpoint.handler = function(ctx)
        local status, resp = pcall(handler_func, ctx)

        local httpd = ctx['tarantool.http.httpd']

        if not status then
            local tag, op_id
            for _, val in next, _U.ni_patterns do
                tag, op_id = resp:match(val)

                if tag ~= nil then
                    break
                end
            end

            if tag or op_id then
                return util.not_implemented(ctx, tag, op_id)
            end

            return httpd.error_handler(ctx, resp)
        end
        if not resp then
            return httpd.default(ctx, "No Content")
        end

        return resp
    end
    self.handler_swap = true
end

local function request_multipart(self)
    local body = self:read_cached()

    local sep = "--"..self:header("content-type"):match("boundary=(.+)"):gsub("-", "%%-")
    local s, e = body:find(sep.."\r\n")
    local eor = false

    local t = {}

    while not eor do
        local _s, _e = body:find(sep, e)
        if body:endswith("--", _e, _e + 2) then
            eor = true
        end

        local param_part = body:match("%aontent%-%aisposition:.-; (.-)\r\n\r\n", e - 1)

        -- eh. simple fix
        if not param_part then
            param_part = body:match("CONTENT%-DISPOSITION:.-; (.-)\r\n\r\n", e - 1)
        end

        param_part = param_part:gsub(";", "")

        local mime_type = body:match("%aontent%-%aype: (.-)\r\n", e - 1)

        if not mime_type then
            mime_type = body:match("CONTENT%-TYPE: (.-)\r\n", e - 1)
        end

        local content = {}

        for key, val in param_part:gmatch("(.-)=\"(.-)\"") do
            rawset(content, key:strip(), val:strip())
        end

        local value = body:sub(e, _s - 1):match("\r\n\r\n(.-)\r\n$")

        rawset(
            t,
            content.name,
            content.filename and {data = value, headers = content, mime = mime_type} or value
        )

        s, e = _s, _e + 2
    end

    return t
end

-- solely to parse multipart
function _U.post_param(self)
    if self:content_type() == "multipart/form-data" then
        self.post_param = function(ctx, name)
            local params = request_multipart(ctx)

            return name and params[name] or params
        end
    end
end

function _U.handle_cors(ctx)
    local httpd = ctx['tarantool.http.httpd']
    local router = ctx:router()

    if not ctx.render_swap then
        _U.render(ctx)
    end

    ctx.hdrs = {}

    local req_method = ctx:header("access-control-request-method") or ctx:method()
    local req_headers = ctx:header("access-control-request-headers")

    if req_headers then
        req_headers = req_headers:split(",")
    end

    local route = router:match(req_method, ctx:path())

    if not route then
        if ctx:method() == "OPTIONS" then
            return ctx:render({
                status = 201,
                text = ""
            })
        end
        return httpd.bad_request_handler(ctx)
    end

    ctx.endpoint = route.endpoint
    ctx.stash    = route.stash

    if not ctx.handler_swap then
        _U.handler(ctx)
    end

    if fun.any(function(v) return v=="*" end, httpd.options.cors.allow_origin) then
        ctx.hdrs["access-control-allow-origin"] = "*"
    else
        if fun.any(function(v) return v==ctx:header("origin") end, httpd.options.cors.allow_origin) then
            ctx.hdrs["access-control-allow-origin"] = ctx:header("origin")
        end
    end

    ctx.hdrs['access-control-max-age'] = httpd.options.cors.max_age
    ctx.hdrs['access-control-allow-credentials'] = tostring(httpd.options.cors.allow_credentials)
    ctx.hdrs['access-control-allow-headers'] = table.concat(httpd.options.cors.allow_headers, ",")

    if ctx:method() == 'OPTIONS' then
        local methods
        if httpd.openapi then
            local path = httpd.openapi.paths[ctx.endpoint.openapi_path]

            if not path then
                return
            end

            methods = fun.map(
                function(k)
                    return k:upper()
                end,
                path
            ):totable()
        else
            methods = {ctx.endpoint.method}
        end

        if fun.any(function(val) return val == req_method end, methods) then
            ctx.hdrs['access-control-allow-methods'] = req_method
        end

        return ctx:render({
            status = 201,
            text = ""
        })
    end

    return tsgi.next(ctx)
end

function _U.bind_security(ctx)
    local self = ctx:router()

    local r = self:match(ctx:method(), ctx:path())
    ctx.endpoint = r.endpoint
    ctx.stash    = r.stash

    local httpd = ctx['tarantool.http.httpd']

    local security = ctx.endpoint.security or (ctx.endpoint.openapi_path and httpd.openapi.global_security)

    if security ~= nil then
        local auth_handler
        if not httpd.options.security then
            local resp = tsgi.next(ctx)
            return httpd.default(resp, "Security options are not specified for this server instance")
        end

        if type(httpd.options.security) == "table" then
            auth_handler = httpd.options.security[security.name]
        else
            auth_handler = httpd.options.security
        end

        if auth_handler then
            local scheme = security.options.scheme or security.options.type
            local auth_data, additional = _U[scheme](ctx, security.options.name, security.options['in'])
            if not auth_data then
                return httpd.security_error_handler(ctx, "Authorization data not found")
            else
                local err
                ctx.authorization, err = auth_handler(ctx:path(),  security.scope, auth_data, additional)

                if err then
                    return httpd.security_error_handler(ctx, err)
                end
            end
        else
            return httpd.security_error_handler(ctx, "Security handler is not implemented")
        end
    end

    return tsgi.next(ctx)
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

    self.default = function(ctx, err)
        return f(ctx, err)
    end
end

function _U.httpd_error_handler(self, f, ...)
    if type(f) ~= "function" then
        error(f)
    end

    self.error_handler = function(ctx, err)
        if metrics and metrics.errors then
            metrics.errors:inc(1)
        end

        return f(ctx, err)
    end
end

function _U.httpd_security_error_handler(self, f)
    if type(f) ~= "function" then
        error(f)
    end

    self.security_error_handler = function(ctx, err)
        if metrics and metrics.security_errors then
            metrics.security_errors:inc(1)
        end

        return f(ctx, err)
    end
end

function _U.httpd_bad_request_handler(self, f)
    if type(f) ~= "function" then
        return self:render({
            status = 400,
            json = {
                error = f
            }
        })
    end

    self.bad_request_handler = function(ctx, err)
        return f(ctx, err)
    end
end

function _U.httpd_not_found_handler(self, f, pattern)
    local router = self:router()

    if self.http_404_swap then
        return
    end

    if type(f) == "function" then
        router:route(
            {
                method = "ANY",
                path   = pattern or "/*path"
            },
            f
        )
        self.http_404_swap = true
        return
    end

    router:route({
        path = pattern or "/*path",
        file = "404.html"
    })
    self.http_404_swap = true
end

_U.ni_patterns = {
    [[Can't load module '(.*)': '(.*)']],
    [[Controller '(.*)' doesn't contain function '(.*)']],
    [[require '(.*)' didn't return table]],
    [[Controller '(.*)' is not a function]]
}


-- validation functions
function _V.validate(ctx)
    local c, a = ctx.endpoint.controller, ctx.endpoint.action

    local ctype = ctx:header("content-type")
    local req_path, method = ctx.endpoint.openapi_path, ctx:method():lower()

    if not req_path then
        return
    end

    if ctype then
        local with_charset = ctype:match("(%S+)[;]:?")

        if with_charset then
            ctype = with_charset
        end
    end

    local httpd = ctx['tarantool.http.httpd']

    local has, err = httpd.openapi:has_params(req_path, method, ctype)

    if err then
        return {err}
    end

    if not has then
        return {}
    end

    httpd.cache = httpd.cache or {}

    if not httpd.cache.params then
        httpd.cache.params = {}
    end

    local cache = httpd.cache.params[c]

    if not cache then
        httpd.cache.params[c] = {}
    end

    cache = not a and cache or httpd.cache.params[c][a]

    if not cache then
        if a then
            httpd.cache.params[c][a] = {}
            cache = httpd.cache.params[c][a]
        else
            httpd.cache.params[c] = {}
            cache = httpd.cache.params[c]
        end
    end

    if not next(cache) then
        local params, p_err = httpd.openapi:form_params(req_path, method, ctype)

        if p_err then
            error(p_err)
        end

        if action then
            httpd.cache.params[c][a] = params
        else
            httpd.cache.params[c] = params
        end
        cache = params
    end

    local res = {}

    if method ~= "get" and cache._body then
        local post = ctx:post_param()

        _V.runs = 0
        if cache._body then
            --[[
                ctx arg goes last as optional, 'cause this call may execute
                object validation as well as string or an array validation
            ]]

            if cache._body.type then
                res = _V[cache._body.type](post, cache._body, ctx)
            end

            if _V.runs <= 0 then
                res = next(res) and {body = res} or res
            end
        end
    end

    _V.validate_query(ctx, cache._query, res)
    return res or {}
end

function _V.validate_query(ctx, spec, res)
    local query = ctx:query_param()
    local stash = ctx.endpoint.stash

    if next(stash) then
        stash = fun.map(
            function(name)
                return name, stash[name]
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

    if not ctx.http_404_swap then
        ctx:not_found_handler()
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

    _T.server_settings = ctx.openapi.server_settings
    _T.set_manual_tests()

    return
end

function _T.run(ctx)
    if fun.any(function(val) return val == "coverage" end, arg)  then
        local app_router = ctx:router()

        local coverage_report = _T.coverage(app_router)

        print("FAILED TOTAL: ", coverage_report.count)
        if next(coverage_report.paths) then
            print("FAILED PATHS: ")
            print(table.concat(coverage_report.paths, "\n"))
        end

        os.exit(1)
    end

    -- set variables set before to respective modules
    json, tap = require("json"), require("tap")

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
    settings.query = neturl.buildQuery(query)

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

                if method ~= "get" and params._body then
                    params._body.required = params._body.required or {}
                    body = fun.map(
                        function(name, vars)
                            --[[
                                check, whether this parameter is required
                                 then assert that it has an example value set in openapi schema
                                 throw an error otherwise
                            ]]
                            if fun.any(function(val) return val == name end,params._body.required) then
                                local msg = ("Example variable not set for the %q parameter in %s %s"):format(name, method, _path)
                                assert(vars.example, msg)
                            end
                            return name, vars.example
                        end,
                        params._body.properties
                    ):tomap()
                end

                if params._query then
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
                        params._query
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

function _T.coverage(app_router)
    return fun.reduce(
        function(res, route)
            if route.openapi_path then
                local status, module = pcall(require, "controllers."..route.controller)

                local failed = false
                if not status then
                    failed = true
                elseif route.action and not type(module) == "table" then
                    failed = true
                elseif route.action and not module[route.action] then
                    failed = true
                end

                if failed then
                    res.count = res.count + 1
                    table.insert(res.paths, route.openapi_path)
                end
            end

            return res
        end,
        {
            count = 0,
            paths = {}
        },
        app_router.routes
    )
end

return _M
