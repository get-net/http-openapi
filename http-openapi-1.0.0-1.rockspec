package = "http-openapi"
version = "1.0.0-1"
source = {
   url    = "git://github.com/get-net/http-openapi.git",
   branch = "master",
   tag    = "master"
}
description = {
   summary  = "Tarantool http-server OpenAPI support wrapper",
   homepage = "https://github.com/get-net/http-openapi",
   license = "BSD"
}
dependencies = {
   'lua >= 5.1'
}
build = {
   type = "builtin",

   modules = {
      ['http.cors'] = "cors.lua",
      ['http.openapi'] = "openapi.lua"
   }
}