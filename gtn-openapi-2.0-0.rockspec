package = "gtn-openapi"
version = "2.0-0"
source = {
   url = "git://github.com/get-net/http-openapi.git",
   tag = "2.0-0"
}
description = {
   summary  = "Tarantool http-server OpenAPI support wrapper",
   homepage = "https://github.com/get-net/http-openapi",
   license = "BSD"
}
dependencies = {
   "lua >= 5.1"
}
build = {
   type = "builtin",

   modules = {
      ['gtn.openapi.init'] = "src/init.lua",
      ['gtn.openapi.validation'] = "src/validation.lua",
      ['gtn.openapi.metrics'] = "src/metrics.lua",
      ['gtn.openapi.testing'] = "src/testing.lua",
      ['gtn.openapi.util'] = "src/util.lua"
   }
}