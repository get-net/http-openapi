package = "gtn-openapi"
version = "scm-3"
source = {
   url = "git://github.com/get-net/http-openapi.git"
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
