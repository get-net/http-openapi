-- tnt modules
local fiber = require('fiber')
local tsgi  = require("http.tsgi")

local _M = {}

-- prometheus handlers
function _M.bind_metrics(httpd)
    local router = assert(httpd:router(), "router is not set")
    local prefix = assert(httpd.options.metrics.prefix, "Please set 'prefix' options for your metrics config")
    local path = httpd.options.metrics.path
    local options = httpd.options.metrics.collect

    local metrics_status, metrics = pcall(require, "metrics")
    assert(metrics_status, "metrics library is not installed")

    local prometheus_status, prometheus = pcall(require, "metrics.plugins.prometheus")

    assert(prometheus_status, "prometheus plugin was not found")

    if options and type(options) == "table" then
        for _, opt in next, options do
            if opt.watch then
                opt.type = "counter"
            end

            local operation = assert(metrics[opt.type], ("Invalid metric type %s"):format(opt.type))

            local _op = operation(("%s_%s"):format(prefix, opt.name), opt.description)

            if opt.type == "gauge" and opt.call then
                assert(type(opt.call == "function"), ("call option is not a function for %s"):format(opt.name))

                local handle = _M.fiber_operation

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

    httpd.error_metrics = {
        security_errors = metrics.counter(("%s_security_errors"):format(prefix), "Security error counter"),
        errors          = metrics.counter(("%s_unhandled_errors"):format(prefix), "Unhandled error counter")
    }

    if path then
        router:route({
            path = path
        },
            prometheus.collect_http
        )
    end
end

function _M.fiber_operation(operation, f, step)
    while true do
        local val = f()

        operation:set(val)
        fiber.sleep(step or 15)
    end
end

return _M