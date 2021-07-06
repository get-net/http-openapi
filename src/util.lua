-- tnt modules
local base64_decode = require("digest").base64_decode
local http_utils    = require('http.utils')
local tsgi          = require("http.tsgi")
local fio           = require("fio")
local fun           = require("fun")
local lib           = require("http.lib")

local _M = {}

function _M.read_config()
    local env = arg[1] or "development"

    if env:startswith("--") then
        env = "development"
    end

    local status, conf = pcall(require, "config."..env)

    assert(
        status,
        ("Invalid environment %q. Try adding it to the config directory"):format(env)
    )
    conf.__name  = env

    _G.app_config = conf
    _G.app_config.is_test = fun.any(
        function(val)
            return val == "--test"
        end,
        arg
    )
end

function _M.read_path_parameters(path_str)
    local result = {}
    for val in path_str:gmatch("{(%w+)}") do
        table.insert(result, val)
    end
    return result
end

function _M.parse_path(p)
    local res = p
    for path_param in p:gmatch("{(%w+)}") do
        local sub = ("{%s}"):format(path_param)
        res = res:gsub(sub, ":"..path_param)
    end
    return res
end

-- basic responses
function _M.not_implemented(self, tag, operation_id)
    return self:render({
        status = 501,
        json = {
            error       = "Not Implemented",
            tag         = tag,
            operationId = operation_id
        }
    })
end

function _M.read_specfile(filepath)
    assert(
        fio.path.is_file(filepath),
        ("Spec file %s does not exist"):format(filepath)
    )

    local tab = filepath:split(".")
    local ext = tab[#tab]
    assert(ext == "yaml" or ext == "json", "Invalid openapi file extension")
    local decoder = require(ext)
    local file = fio.open(filepath, {"O_RDONLY"})

    local data = file:read()
    local status, res = pcall(decoder.decode, data)
    assert(
        status,
        ("Specification file %s is not valid"):format(filepath)
    )

    return res
end

--[[
    initial primary schema mutation. NOTE: this is not copying
    it changes the original schema
]]
function _M.join_schemas(primary, secondary, field)
    primary[field]   = primary[field] or {}
    secondary[field] = secondary[field] or {}

    primary[field] = fun.reduce(
        function(res, k ,v)
            -- does not override primary options with secondary ones
            if not res[k] then
                rawset(res, k ,v)
            end

            return res
        end,
        primary[field],
        secondary[field]
    )
end

function _M.bearer(ctx)
    local header = ctx:header("authorization")

    if not header then
        return
    end

    return header:match("Bearer (.*)")
end

function _M.basic(ctx)
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

function _M.apiKey(ctx, name, goes_in)
    if goes_in == "header" then
        local n = name:lower()
        return ctx:header(n)
    elseif goes_in == "cookie" then
        local val = ctx:header("cookie")

        return val and val:match(("%s=([^;]*)"):format(name)) or nil
    end
end

-- bad unescape fpr query parameters
function _M.cached_query_param(self, name)
    if name == nil then
        return self.query_params
    end
    return self.query_params[ name ]
end

function _M.query_param(self, name)
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

    rawset(self, 'query_param', _M.cached_query_param)
    return self:query_param(name)
end

-- overrides response render handling
function _M.render(self)
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

local ni_patterns = {
    [[Can't load module '(.*)': '(.*)']],
    [[Controller '(.*)' doesn't contain function '(.*)']],
    [[require '(.*)' didn't return table]],
    [[Controller '(.*)' is not a function]]
}

-- overrides route handler with this one
function _M.handler(self)
    local handler_func = self.endpoint.handler

    self.endpoint.handler_swap = true
    self.endpoint.handler = function(ctx)
        local status, resp = pcall(handler_func, ctx)

        local httpd = ctx['tarantool.http.httpd']

        if not status then
            local tag, op_id
            for _, val in next, ni_patterns do
                tag, op_id = resp:match(val)

                if tag ~= nil then
                    break
                end
            end

            if tag or op_id then
                return _M.not_implemented(ctx, tag, op_id)
            end

            return httpd.error_handler(ctx, resp)
        end
        if not resp then
            return httpd.default(ctx, "No Content")
        end

        return resp
    end
end

local function request_multipart(self)
    local body = self:read_cached()

    local sep = "--"..self:header("content-type"):match("boundary=(.+)"):gsub("-", "%%-")
    local _, e = body:find(sep.."\r\n")
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

        _, e = _s, _e + 2
    end

    return t
end

-- solely to parse multipart
function _M.post_param(ctx, name)
    local params = request_multipart(ctx)

    return name and params[name] or params
end

function _M.handle_cors(ctx)
    local httpd = ctx['tarantool.http.httpd']
    local router = ctx:router()

    if not ctx.render_swap then
        _M.render(ctx)
    end

    ctx.hdrs = {}

    local req_method = ctx:header("access-control-request-method") or ctx:method()

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

    if not ctx.endpoint.handler_swap then
        _M.handler(ctx)
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

function _M.bind_security(ctx)
    local self = ctx:router()

    local r = self:match(ctx:method(), ctx:path())
    ctx.endpoint = r.endpoint
    ctx.stash    = r.stash

    local httpd = ctx['tarantool.http.httpd']

    local security = ctx.endpoint.security or (ctx.endpoint.openapi_path and httpd.openapi.global_security)

    if security ~= nil and next(security) then
        local auth_handler
        if not httpd.options.security then
            return httpd.default(ctx, "Security options are not specified for this server instance")
        end

        if type(httpd.options.security) == "table" then
            auth_handler = httpd.options.security[security.name]
        else
            auth_handler = httpd.options.security
        end

        if auth_handler then
            if not security.options and ctx.endpoint.uid_schema then
                local _s  = httpd.openapi:get_secondary(ctx.endpoint.uid_schema)
                local _ps = assert(_s.paths[ctx.endpoint.openapi_path], "path unknown")
                local _ms = assert(_ps[ctx.endpoint.method:lower()], "unknown method")

                ctx.endpoint.security = httpd.openapi:parse_security_schemes(_ms.security)
                security = ctx.endpoint.security
            end

            local scheme = security.options.scheme or security.options.type
            local auth_data, additional = _M[scheme](ctx, security.options.name, security.options['in'])
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

function _M.httpd_default_handler(self, f)
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

function _M.httpd_error_handler(self, f)
    if type(f) ~= "function" then
        error(f)
    end

    self.error_handler = function(ctx, err)
        local httpd = ctx['tarantool.http.httpd']
        if httpd.error_metrics and next(httpd.error_metrics) then
            httpd.error_metrics.errors:inc(1)
        end

        return f(ctx, err)
    end
end

function _M.httpd_security_error_handler(self, f)
    if type(f) ~= "function" then
        error(f)
    end

    self.security_error_handler = function(ctx, err)
        local httpd = ctx['tarantool.http.httpd']
        if httpd.error_metrics and next(httpd.error_metrics) then
            httpd.error_metrics.security_errors:inc(1)
        end

        return f(ctx, err)
    end
end

function _M.httpd_bad_request_handler(self, f)
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

function _M.httpd_not_found_handler(ctx, f, match_pattern)
    local router = ctx:router()

    if ctx.http_404_swap then
        return
    end

    if f then
        local handler = function(self)
            local resp = type(f) == "function" and f(self) or self:render()
            resp.status = 404
            return resp
        end

        ctx.http_404_swap = true

        router:route(
            {
                method = "ANY",
                file   = "404.html",
                path   = match_pattern or "/*path"
            },
            handler
        )
    end
end

return _M
