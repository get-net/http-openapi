local fun = require("fun")

local _M = {}

function _M.read_config()
    local env = arg[1] or "staging"

    if env:startswith("--") then
        env = "staging"
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

_M.read_config()

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

return _M
