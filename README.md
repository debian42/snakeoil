# snakeoil remover
windows, remove snakeoil (certs)

## build
`mkdir build`  
`cd build`  

### build 64Bit
`cmake -A x64 ..`  

### build 32Bit
`cmake -AWIN32 ..`  

### build release
`cmake --build . --config Release`  