-- tnt modules
local tap        = require("tap")

local validation = require("src.validation")

local testing = tap.test("vaidation module")

testing:plan(21)

local enum_test_value = {"test", "test1", "test2"}
local p_error_format = {
    details = {
        error    = "test",
        expected = "test1",
        actual   = "test2"
    }
}

testing:ok(validation.is_object({}) == false, "is_object empty array")
testing:ok(validation.is_object({1}) == false,"is_object array")
testing:ok(validation.is_object({k = 1}) == true, "is_object object")

testing:ok(validation.string(false) == false, "string false")
testing:ok(validation.string("ok") == true, "string true")

testing:ok(validation.integer(false) == false, "integer false")
testing:ok(validation.integer(1) == true, "integer true")

testing:ok(validation.email("testing") == false, "email false")
testing:ok(validation.email("example@example.com") == true, "email true")

testing:ok(validation.uuid("abcdef") == false, "uuid false")
testing:ok(validation.uuid("66d9ca63-551e-4538-b59f-9f0f29522d70") == true, "uuid true")

testing:ok(validation.enum("test3", enum_test_value) == false, "enum false")
testing:ok(validation.enum( "test", enum_test_value) == true, "enum true")
testing:ok(validation.enum("test", "olegue") == false, "enum wrong type")

testing:ok(validation.date("123-123-123") == false, "date false")
testing:ok(validation.date("2021-07-05") == true, "date true")

testing:ok(validation.boolean(1) == false, "boolean false")
testing:ok(validation.boolean(true) == true, "boolean true")

testing:ok(validation['date-time']("123-123-123 20:20:20") == false, "date-time false")
testing:ok(validation['date-time']("2021-07-05 16:15:22") == true, "date-time true")

testing:is_deeply(
    validation.p_error("test", "test1", "test2"),
    p_error_format,
    "p_error format true"
)