-- tnt modules
local tap  = require("tap")

local util = require("src.util")

local testing = tap.test("util module")

testing:plan(4)

local parsed_path = "http://example.com/:test/:test1/:test2"

local mock_header_function = function(self, name)
    return self[name]
end

local mock_bearer_ctx = {
    authorization = "Bearer test",
    header = mock_header_function
}

local mock_basic_ctx = {
    authorization = "Basic dGVzdDp0ZXN0",
    header = mock_header_function
}

local mock_api_key_ctx = {
    ["API-KEY"] = "test",
    cookie = "SomeValue=Wrong; Test=Test",
    header = mock_header_function
}

local mock_cached_query_param = {
    query_params = {
        test = "test"
    }
}

testing:is_deeply(
    util.read_path_parameters("http://example.com/{test}/{test1}/{test2}"),
    {"test", "test1", "test2"},
    "read_path_parameters true"
)

testing:is(
    util.parse_path("http://example.com/{test}/{test1}/{test2}"),
    parsed_path,
    "parse_path true"
)

testing:is(
    util.bearer(mock_bearer_ctx),
    "test",
    "bearer true"
)

local basic_username, basic_password =  util.basic(mock_basic_ctx)
testing:is(
    basic_username,
    "test",
    "basic username"
)
testing:is(
    basic_password,
    "test",
    "basic password"
)

testing:is(
    util.apiKey(mock_api_key_ctx, "Test", "cookie"),
    "Test",
    "cookie true"
)

testing:is_deeply(
    util.cached_query_param(mock_cached_query_param, "test"),
    "test",
    "cached_query_param named"
)

testing:is_deeply(
    util.cached_query_param(mock_cached_query_param),
    {test = "test"},
   "cached_query_param unnamed"
)