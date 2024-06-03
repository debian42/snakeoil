cmake_minimum_required (VERSION 3.6)
project (snakeoil)
add_executable(snakeoil "")
set_property(TARGET snakeoil PROPERTY CXX_STANDARD 11)

target_sources(snakeoil PRIVATE src/snakeoil.cpp src/conscolor.h src/fileiter.h)

target_compile_options(snakeoil PRIVATE
     $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:-Wall>
     $<$<CXX_COMPILER_ID:MSVC>:/W4>)
