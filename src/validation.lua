-- tnt modules
local uuid = require("uuid")
local fun  = require("fun")

local _M = {}

--[[
    deafault strict validation option is false, letting it to pass
    the unknown parameters invalidations
]]
_M.strict = false

-- validation functions
function _M.validate(ctx)
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

    local schema = ctx.endpoint.uid_schema and
        httpd.openapi:get_secondary(ctx.endpoint.uid_schema) or httpd.openapi

    local has, err = schema:has_params(req_path, method, ctype)

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
        local params, p_err = schema:form_params(req_path, method, ctype)

        if p_err then
            error(p_err)
        end

        if a then
            httpd.cache.params[c][a] = params
        else
            httpd.cache.params[c] = params
        end
        cache = params
    end

    local res = {}

    if method ~= "get" and cache._body then
        local status, post = pcall(ctx.post_param, ctx)

        if not status then
            return {
                body = {
                    details = "failed to read the request body",
                    expected = ctype
                }
            }
        end

        _M.runs = 0
        if cache._body then
            --[[
                ctx arg goes last as optional, 'cause this call may execute
                object validation as well as string or an array validation
            ]]

            if cache._body.type then
                res = _M[cache._body.type](post, cache._body, ctx)
            end

            if _M.runs <= 0 then
                res = next(res) and {body = res} or res
            end
        end
    end

    _M.validate_query(ctx, cache._query, res)
    return res or {}
end

function _M.validate_query(ctx, spec, res)
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

    if not next(spec) and (next(query) or next(stash)) and _M.strict then
        return fun.chain(query, stash):reduce(
            function(_res, key)
                _res[key] =_M.p_error("unknown")
                return _res
            end,
            res
        )
    else
        fun.chain(query, stash):reduce(
            function(_res, key)
                if not fun.any(function(val) return val.name == key end, spec) and _M.strict then
                    _res[key] = _M.p_error("unknown")
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
                value = ctx.stash[param.name]
            end

            if value == nil and not param.required then
                return _res
            end

            if not value then
                _res[param.name] = _M.p_error("missing")
                return _res
            end

            local vtype = param.schema.format or param.schema.type

            if not _M[vtype](value) then
                _res[param.name] = _M.p_error("invalid", vtype, type(value))
            end

            if param.schema.enum then
                local ok = _M.enum(value, param.schema.enum)

                if not ok and not param.schema.nullable then
                    _res[param.name] = _M.p_error("invalid", param.schema.enum, value)
                end
            end

            return _res
        end,
        res,
        spec
    )
end

function _M.array(t, spec, ctx)
    local first_run = (_M.runs == 0)

    if type(t) ~= "table" or _M.is_object(t) then
        return first_run and {
            details = {
                error    = "invalid",
                expected = "array",
                actual   = type(t)
            }
        } or false
    end

    spec = spec.items
    local pkey, pval = next(spec)

    if pkey == "$ref" then
        local httpd = ctx['tarantool.http.httpd']
        local uid_schema = ctx.endpoint.uid_schema

        local reference = httpd.openapi:ref(pval, uid_schema)
        if reference then
            spec = reference
        end
    end

    local res = fun.reduce(
        function(res, val)
            local ptype = spec.format or spec.type

            local r
            if ptype == "object" then
                r = _M[ptype](val, spec, ctx)
            else
                r = _M[ptype](val)
            end

            if not r then
                table.insert(res, _M.p_error("invalid", ptype, type(val)))
                return res
            end

            if type(r) == "table" and next(r) then
                if not _M.is_object(r) then
                    table.insert(res, r)
                    return res
                end

                local _t = {}
                for k, v in next, r do
                    rawset(_t, k, v)
                end
                table.insert(res, _t)
            end

            return res
        end,
        {},
        t
    )

    return res
end

function _M.object(val, spec, ctx)
    if not _M.is_object(val) then
        if type(val) ~= "table" then
            return _M.p_error("invalid", "object", type(val))
        end

        -- in case of no actual parameters and no required ones
        if not next(val) and not spec.required then
            return {}
        end

        local first_run = (_M.runs == 0)
        return first_run and _M.p_error("invalid", "object", type(val)) or false
    end

    _M.runs = _M.runs + 1
    local required = spec.required or {}
    local obj = spec.properties

    local absent = fun.map(
        function(key, param)
            local k, v = next(param)
            if k == "$ref" then
                local httpd = ctx['tarantool.http.httpd']
                local uid_schema = ctx.endpoint.uid_schema

                -- fetches secondary schema's refs
                local reference = httpd.openapi:ref(v, uid_schema)
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
                return key, _M.p_error("missing")
            end
            return key, nil
        end,
        obj
    ):tomap()

    return fun.reduce(
        function(res, key, param)
            if not obj[key] then
                if _M.strict then
                    rawset(res, key, _M.p_error("unknown"))
                end
                return res
            end

            local ptype = obj[key].format or obj[key].type

            local r

            if ptype == "object" or ptype == "array" then
                r = _M[ptype](val[key], obj[key], ctx)
            else
                r = _M[ptype](param, ctx)
            end
            if not r then
                rawset(res, key, _M.p_error("invalid", ptype, type(param)))
                return res
            end

            if type(r) == "table" and next(r) then
                if not _M.is_object(r) then
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

function _M.is_object(obj)
    if type(obj) ~= "table" then
        return false
    end
    local k, v = next(obj)
    return type(k) == "string" and v ~= nil
end

function _M.string(s)
    return type(s) == "string"
end

_M.password = _M.string
_M.byte     = _M.string
_M.binary   = _M.string

function _M.integer(i)
    return type(i) == "number"
end

_M.number = _M.integer
_M.double = _M.integer
_M.float  = _M.integer
_M.int32  = _M.integer
_M.int64  = _M.integer

function _M.email(email)
    if not _M.string(email) then
        return false
    end
    return email:match('[(%w+)%p*]+@[%w+%p*]+%.%a+$') ~= nil
end

function _M.uuid(str)
    local s, res = pcall(uuid.fromstr, str)
    return s and res ~= nil
end

function _M.enum(val, options)
    return fun.any(function(v) return val == v end, options)
end

function _M.date(str)
    -- lua can't match by length in any other way
    local ok = str:match("^(%d%d%d%d)-(%d%d)-(%d%d)$")
    return ok ~= nil
end

function _M.boolean(val)
    return val == true or val == false
end

_M['date-time'] = function(str)
    -- same here. needs some thinking maybe later
    local ok = str:match("^(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)[.(%d+):?]?") or
        str:match("^(%d%d%d%d)-(%d%d)-(%d%d) (%d%d):(%d%d):(%d%d)[.(%d+):?]?")
    return ok ~= nil
end

-- template for filetype validation
local fileformat = {
    type     = "object",
    required = {"data"},
    properties = {
        data = {
            type = "string"
        },
        headers = {
            type = "object",
            properties = {
                filename = {
                    type = "string"
                },
                name = {
                    type = "string"
                }
            }
        },
        mime = {
            type = "string"
        }
    }
}

function _M.binary(obj, ctx)
    return _M.object(obj, fileformat, ctx)
end

_M.byte = _M.binary

function _M.p_error(alias, expected, actual)
    return {
        details = {
            error = alias,
            expected = expected,
            actual = actual
        }
    }
end

return _M