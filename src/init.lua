-- tnt modules
local tsgi          = require("http.tsgi")
local uuid          = require("uuid")
local fio           = require("fio")
local fun           = require("fun")
local log           = require("log")

-- lua modules
local neturl_ok, neturl = pcall(require, "net.url")

if not neturl_ok then
    error("net-url not found, please install it with command: luarocks install net-url")
end

-- helpers
local validation    = require("gtn.openapi.validation")
local metrics       = require("gtn.openapi.metrics")
local testing       = require("gtn.openapi.testing")
local util          = require("gtn.openapi.util")

local default_cors = {
    max_age = 3600,
    allow_credentials = true,
    allow_headers = { "Authorization, Content-Type" },
    allow_origin = { "*" },
    specific = {}
}

local _M = {}
local mt = {}

local function bind_routes(httpd)
    local router = httpd:router()

    local routes = httpd.openapi:parse_paths()

    if httpd.openapi.__sschemas then
        -- set additional routes from secondary schemas and bind them
        local additional_routes = fun.reduce(
            function(res, _, _schema)
                local _paths  = _schema:parse_paths()

                table.insert(res, _paths)
                _schema.bound = true
                return res
            end,
            {},
            httpd.openapi.__sschemas
        )

        if next(additional_routes) then
            routes = fun.chain(routes, unpack(additional_routes)):totable()
        end

        httpd.openapi.bound = true
    end

    for _, v in next, routes do
        if v.options.security or httpd.openapi.global_security then
            router:use(
                util.bind_security,
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
            if httpd.options.cors.specific and next(httpd.options.cors.specific) then
                local current = fun.filter(function(val)
                    return val.path == v.options.path
                end, httpd.options.cors.specific):totable()
                if next(current) then
                    current = current[1]

                    if current.handler then
                        local _h = function(ctx)
                            if not ctx.render_swap then
                                util.render(ctx)
                            end
                            local _router = ctx:router()
                            local req_method = ctx:header("access-control-request-method") or ctx:method()

                            local route = _router:match(req_method, ctx:path())

                            if not route and not current.skip_method then
                                if ctx:method() == "OPTIONS" then
                                    return ctx:render({
                                        status = 201,
                                        text = ""
                                    })
                                end
                                return
                            end
                            ctx.hdrs = {
                                ["access-control-request-method"] = req_method
                            }

                            return current.handler(ctx)
                        end

                        router:use(
                            _h,
                            {
                                preroute = true,
                                name = "specific_cors#"..v.controller,
                                method = "OPTIONS",
                                path = v.options.path
                            }
                        )
                        goto skip
                    end
                end
            end
            router:use(
                util.handle_cors,
                {
                    preroute = true,
                    name     = "cors#"..v.controller,
                    method   = "OPTIONS",
                    path     = v.options.path
                }
            )
            ::skip::

            router:use(
                util.handle_cors,
                {
                    preroute = true,
                    name     = "cors#"..v.controller,
                    method   = v.options.method,
                    path     = v.options.path
                }
            )
        end

        router:route(v.options, v.controller)
    end
end

function mt:__call(httpd, router, spec_conf, options)
    local openapi
    if not _G.app_config then
        util.read_config()
    end

    local server_settings
    if type(spec_conf) == "string" then
        openapi = self:new(util.read_specfile(spec_conf))
        server_settings = openapi:read_server()
    end

    if type(spec_conf) == "table" then
        assert(validation.is_object(spec_conf), "schema options must be a hash map or a string")

        local base_path = assert(spec_conf.base_path, "base_path option is not set")
        local primary = assert(spec_conf.primary_schema, "primary_schema option is not set")
        local secondary_schemas = spec_conf.secondary_schemas or {}

        openapi = self:new(util.read_specfile(fio.pathjoin(base_path, primary)))

        -- moved this call here to have a possibility of setting relative schemas
        server_settings = openapi:read_server()

        for _, opts in next, secondary_schemas do
            openapi:add_schema(fio.pathjoin(base_path, opts.schema), opts.path, opts.relative)
        end
    end

    if not server_settings.socket then
        -- overrides server settings from openapi schema sets 8080 as a default port if not set
        httpd = httpd.new(server_settings.host, server_settings.port or 8080, _G.app_config.server_options)
    else
        local out_port = server_settings.socketPath and
            ("/%s/%s"):format(server_settings.socketPath, server_settings.socket) or
            server_settings.socket
        httpd = httpd.new("unix/", out_port, _G.app_config.server_options)
    end

    if options.debug then
        _G.app_config.server_options.display_errors = false
        _G.app_config.server_options.log_requests = false
        _G.app_config.server_options.log_errors = false
        if log.cfg then
            log.cfg({level = 3})
        end
    else
        if options.log then
            assert(type(options.log.file) == "string", "log.file option should be string")

            if options.log.file then
                if not fio.path.lexists(options.log.file) then
                    local pathtab = options.log.file:split("/")

                    if #pathtab > 1 then
                        local dirs = table.concat(fun.take(#pathtab - 1, pathtab):totable(), "/")
                        fio.mktree(dirs)
                    end
                end
            end
            if log.cfg then
                log.cfg({log = options.log.file, level = options.log.level})
            end
        end
        _G.app_config.server_options.log_requests = true
        _G.app_config.server_options.log_errors = true
    end

    httpd.openapi = openapi

    router = router.new(_G.app_config.server)

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
                        type(val)
                    )
                    error(msg)
                end
                rawset(_cors, key, val)
            end

            v = _cors
        end

        if k == "strict" then
            validation.strict = v
        end

        rawset(httpd.options, k, v)
    end

    httpd.bind_paths = bind_routes

    httpd:bind_paths()

    if options.metrics then
        metrics.bind_metrics(httpd)
    end

    httpd.default                 = util.httpd_default_handler
    httpd.error_handler           = util.httpd_error_handler
    httpd.not_found_handler       = util.httpd_not_found_handler
    httpd.bad_request_handler     = util.httpd_bad_request_handler
    httpd.security_error_handler  = util.httpd_security_error_handler

    testing.httpd_start = httpd.start
    testing.httpd_stop  = httpd.stop

    httpd.start = testing.start

    return httpd
end

setmetatable(_M, mt)

-- main openapi handler prototype
function _M:new(spec, base_path, uid_schema)
    local obj = spec or {}
    obj.server_settings = {
        path = base_path
    }
    obj.uid_schema = uid_schema
    obj.bound      = false

    --[[
        those methods set only for primary schema, setting secondary schemas to secondary schemas
        might cause some painful nesting for now
    ]]
    if not base_path and not uid_schema then
        -- just some inner paths to bind child schemas
        function self:add_schema(filepath, _path, relative)
            local _schema = util.read_specfile(filepath)

            if not _path then
                util.join_schemas(self, _schema, "paths")
                util.join_schemas(self, _schema, "components")
                return
            end

            -- generate uid for secondary schema
            local uid = uuid.str()
            self.__sschemas = self.__sschemas or {}

            if relative then
                if self.server_settings and self.server_settings.path then
                    _path = fio.pathjoin(self.server_settings.path, _path)
                end
            end

            local _obj = _M:new(_schema, _path, uid)
            rawset(self.__sschemas, uid, _obj)
        end

        function self:get_secondary(uid)
            return self.__sschemas[uid]
        end

        function self:get_secondary_list()
            -- to avoid mutations
            return _G.table.deepcopy(self.__sschemas)
        end

        function self:read_server()
            if not self.servers then
                return {}
            end

            -- form server settings and unfold variables object
            local current = fun.filter(
                function(val)
                    if _G.app_config.is_test then
                        return val.description == "test"
                    end
                    return val.description == _G.app_config.__name
                end,
                self.servers
            ):map(
                function(val)
                    local server_params = util.read_path_parameters(val.url)

                    if next(server_params) and not val.variables then
                        error(
                            ("Server variables are not set for %q environment: %s")
                                :format(_G.app_config.__name, val.url)
                        )
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
                                ("Variable %q is not set for %s server options"):format(param, _G.app_config.__name)
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
                error(("\nServer settings for %s are not set.\n"):format(_G.app_config.__name))
            end

            self.server_settings = settings

            return settings
        end
    end

    function self:parse_paths()
        local parsed = {}

        if self.bound then
            return parsed
        end

        fun.reduce(
            function(_r, path, methods)
                fun.map(
                    function(method, opts)
                        local options = _G.table.deepcopy(opts)
                        options.method = method
                        path = self.base_path and fio.pathjoin(self.base_path, path) or path
                        return options
                    end,
                    methods
                ):reduce(
                    function(res, opts)
                        opts.tags = opts.tags or { "default" }

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

                        -- set fullPath option for secondary schemas with path option set
                        if self.base_path then
                            opts['x-settings'] = opts['x-settings'] or {}
                            opts['x-settings'].fullPath = true
                        end

                        local _path = self:form_path(
                            path,
                            method
                        )

                        table.insert(res, {
                            options = {
                                settings = opts['x-settings'],
                                method = method,
                                path = util.parse_path(_path),
                                openapi_path = path,
                                uid_schema = self.uid_schema,
                                security = auth
                            },
                            controller = controller
                        })
                        return res
                    end,
                    parsed
                )

                rawset(_r, path, methods)

                return _r
            end,
            self.paths,
            self.paths
        )

        if self.security then
            self.global_security = self:parse_security_schemes(self.security)
        end

        return parsed
    end

    function self:parse_security_schemes(scheme)
        local _, v = next(scheme)

        if not v then
            return {}
        end

        local key, scope = next(v)
        local options
        if self.components and self.components.securitySchemes then
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
                return false, ("Content-Type %s is not supported"):format(ctype)
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

    function self:ref(str, uid)
        if uid then
            local _schema = self:get_secondary(uid)

            return _schema:ref(str)
        end

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
        local router = ctx:router()

        local r = router:match(ctx:method(), ctx:path())
        ctx.endpoint = r.endpoint
        ctx.stash    = r.stash

        if ctx:content_type() == "multipart/form-data" then
            ctx.post_param = util.post_param
        end

        if not ctx.render_swap then
            util.render(ctx)
        end

        if not ctx.endpoint.handler_swap then
            util.handler(ctx)
        end

        local errors = validation.validate(ctx)

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

        if self.server_settings and self.server_settings.path and not settings.fullPath then
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

return _M
