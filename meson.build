project('dhm', 'c')

gmp_dep = dependency('gmp')
uv_dep = dependency('libuv')
sodium_dep = dependency('libsodium')

executable('dhm', 'dhm.c', dependencies: [gmp_dep, uv_dep, sodium_dep])
