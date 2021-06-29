-- lua modules
local neturl        = require("net.url")

-- tnt modules
local base64_encode = require("digest").base64_encode
local json          = require("json")
local fun           = require("fun")
local fio           = require("fio")
local tap           = require("tap")

local _M = {}

-- automatic testing functions
function _M.start(ctx)
    if fun.any(function(val) return val == "--test" end, arg) then
        return _M.run(ctx)
    end

    if ctx.http_404_swap then
        ctx:not_found_handler()
    end

    return _M.httpd_start(ctx)
end

function _M.set_manual_tests()
    _M.manual = {}

    if fio.path.exists("tests") then
        _M.manual = fun.filter(
            function(val)
                return val:startswith("test")
            end,
            fio.listdir("tests")
        ):totable()
    end
end

function _M.set_env(ctx)
    print("RUNNING TESTS:\n")

    _M.test = tap.test("openapi-schema")
    local test_count = fun.reduce(
        function(res)
            res = res +1
            return res
        end,
        0,
        ctx.openapi.paths
    )

    _M.test:plan(test_count)

    if not ctx.openapi.server_settings then
        error("Test server settings not set")
    end

    _M.server_settings = ctx.openapi.server_settings
    _M.set_manual_tests()

    return
end

function _M.run(ctx)
    if fun.any(function(val) return val == "coverage" end, arg)  then
        local app_router = ctx:router()

        local coverage_report = _M.coverage(app_router)

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
    _M.client = require("http.client").new({5})

    -- sets the testing env
    _M.set_env(ctx)

    -- shutdown request loggin to not get unwanted io data
    ctx.options.log_requests = false

    -- starts the mock server
    local _ = _M.httpd_start(ctx)

    if fio.path.exists("tests/before.lua") then
        print("\nRunning before script:\n")
        dofile("tests/before.lua")
    end

    _M.run_path_tests(ctx)

    _M.run_user_tests()

    if fio.path.exists("tests/after.lua") then
        print("\nRunning after script:\n")
        dofile("tests/after.lua")
    end

    print("\nTesting complete. Shutting down...\n")
    _M.httpd_stop(ctx)
    os.exit(0)
end

function _M.encode_query(opts)
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
function _M.json(resp)
    local status, decoded = pcall(json.decode, resp.body)

    if not status then
        return nil, "Invalid JSON data: ".. decoded
    end

    return decoded
end

function _M.send_request(args)
    return _M.client:request(unpack(args))
end

function _M.form_request(method, relpath, query, body, opts)
    -- reuse already parsed and existing test server options
    local settings = _G.table.deepcopy(_M.server_settings)

    settings.path = relpath
    settings.port = _M.server_settings.port
    settings.path = settings.path:gsub("//", "/")
    settings.query = neturl.buildQuery(query)

    if method ~= "GET" then
        if opts.headers['content-type'] == 'application/x-www-form-urlencoded' then
            body = _M.encode_query(body)
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

function _M.form_security(ctx, headers, options)
    -- there are also scopes in second value, but those are unneeded here
    local option = next(options)

    assert(ctx.openapi.components.securitySchemes, "securitySchemes component is not described")
    local err_msg = ("Schema for %s security does not exist in securitySchemes component"):format(option)

    local sec_schema = assert(ctx.openapi.components.securitySchemes[option], err_msg)

    local sec_type = sec_schema.scheme or sec_schema.type

    if sec_type == "bearer" then
        local value = ("Bearer %s"):format(_M.test_config.security[option])
        rawset(headers, "Authorization", value)
    end

    if sec_type == "apiKey" then
        local value = _M.test_config.security[option]

        if sec_schema['in'] == "cookie" then
            rawset(headers, "cookie", ("%s=%s"):format(sec_schema.name, value))
        else
            rawset(headers, sec_schema.name, value)
        end
    end

    if sec_type == "basic" then
        assert(_M.test_config.security[option], "Basic authorization data is not set in tests/config.lua")
        local username, password = _M.test_config.security[option].username, _M.test_config.security[option].password

        local value = ("Basic %s"):format(
            base64_encode(
                ("%s:%s"):format(username, password)
            )
        )

        rawset(headers, "Authorization", value)
    end
end

function _M.form_expected(ctx, schema)
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
            local d = _M.form_expected(ctx, {
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
                d = _M.form_expected(ctx, {
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
            rawset(result, key, {value = val.example, type = val.type})
        end
    end

    return result
end

_M.openapi_value_map = {
    string = "isstring",
    number = "isnumber",
    integer = "isnumber",
    boolean = "isboolean",
    array = "istable",
    object = "isobject"
}

function _M.run_path_tests(ctx)
    _M.test_config      = require("tests.config")

    print("\nRunning automatic tests:\n")

    local schemas = {
        ctx.openapi
    }

    local secondary = ctx.openapi:get_secondary_list()

    if secondary then
        fun.reduce(
            function(res, _, _schema)
                table.insert(res, _schema)
                return res
            end,
            schemas,
            secondary
        )
    end

    for _, schema in next, schemas do
        for path, options in next, schema.paths do
            for method, opts in next, options do
                local settings = opts['x-settings'] or {}
                if not settings.skipTest then
                    local headers = {}
                    local ctype

                    if opts.security then
                        for _, val in next, opts.security do
                            _M.form_security(ctx, headers, val)
                        end
                    elseif ctx.openapi.security then
                        for _, val in next, ctx.openapi.security do
                            _M.form_security(ctx, headers, val)
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

                    local _path = schema:form_path(
                        path,
                        method
                    )

                    local params = schema:form_params(path, method, ctype, _path)

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
                                if fun.any(
                                    function(val)
                                        return settings.strict and (val == name)
                                    end,
                                    params._body.required
                                ) then
                                    local msg = ("Example variable not set for the %q parameter in %s %s")
                                        :format(name, method, _path)
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
                                local schema_msg = ("Schema option not set for the %q parameter in %s %s")
                                    :format(vars.name, method, _path)

                                assert(vars.schema, schema_msg)
                                if vars.required or vars['in'] == "path" then
                                    local msg = ("Example variable not set for the %q parameter in %s %s")
                                        :format(vars.name, method, _path)
                                    assert(vars.schema.example, msg)
                                end

                                if vars['in'] == "query" then
                                    return vars.name, vars.schema.example
                                else
                                    local pattern = ("{%s}"):format(vars.name)
                                    _path = _path:gsub(pattern, vars.schema.example)
                                end

                                return vars
                            end,
                            params._query
                        ):tomap()
                    end

                    -- curl takes only uppercase method, responses with protocol error otherwise
                    method = method:upper()

                    local request_data = _M.form_request(method, _path, query, body, {headers = headers})

                    local resp = _M.send_request(request_data)

                    _M.test:ok(resp.status == settings.testStatus or 200, ("%s %s OK STATUS"):format(method, _path))

                    local resp_body = _M.json(resp)
                    local resp_schema = opts.responses[resp.status]

                    _M.test:ok(resp_schema, ("%s %s %s RESPONSE SCHEMA EXISTS"):format(method, _path, resp.status))

                    if resp_schema then
                        local expected = _M.form_expected(ctx, resp_schema)

                        for k, v in next, expected do
                            if settings.strict then
                                _M.test:is_deeply(v.value, resp_body[k], ("%s %s RESPONSE MATCH"):format(method, _path))
                            else
                                local val_type = v.type
                                _M.test:isstring(val_type, ("type is set for variable %q"):format(k))

                                if val_type then
                                    local call_method = _M.openapi_value_map[val_type]

                                    -- some poor decisions
                                    local calls = _G.getmetatable(_M.test)
                                    calls.__index[call_method](
                                        _M.test, resp_body[k],
                                        ("value %q should be of the type %q"):format(k, val_type)
                                    )
                                end
                            end
                        end
                    else
                        print("Skipping response match. REASON: no schema\n")
                    end
                    print("\n")
                end
            end
        end
    end
end

function _M.run_user_tests()
    if _M.manual and next(_M.manual) then
        print("Running user tests:\n")

        for _, val in next, _M.manual do
            if not val:match("test_before") then
                dofile(("tests/%s"):format(val))
            end
        end
    end
end

function _M.coverage(app_router)
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