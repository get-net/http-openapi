package = "gtn-openapi"
version = "1.1-2"
source = {
   url    = "git://github.com/get-net/http-openapi.git",
   tag    = "1.1-2"
}
description = {
   summary  = "Tarantool http-server OpenAPI support wrapper",
   homepage = "https://github.com/get-net/http-openapi",
   license = "BSD"
}
dependencies = {
   "lua >= 5.1",
   "net-url"
}
build = {
   type = "builtin",

   modules = {
      ['gtn.openapi'] = "openapi.lua",
      ['gtn.util'] = "util.lua"
   }
}
