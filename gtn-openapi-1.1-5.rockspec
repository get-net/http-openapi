package = "gtn-openapi"
version = "1.1-5"
source = {
   url = "git://github.com/get-net/http-openapi.git",
   tag = "1.1-5"
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
      ['gtn.openapi'] = "openapi.lua",
      ['gtn.util'] = "util.lua"
   }
}
