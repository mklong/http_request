CMAKE_MINIMUM_REQUIRED(VERSION 2.8.7 FATAL_ERROR)

set(CMAKE_VERBOSE_MAKEFILE ON)

# package information
SET(PACKAGE_NAME      "http_request")
SET(PACKAGE_VERSION   "0.1.0")
SET(PACKAGE_STRING    "${PACKAGE_NAME} ${PACKAGE_VERSION}")
SET(PACKAGE_TARNAME   "${PACKAGE_NAME}-${PACKAGE_VERSION}")
SET(PACKAGE_BUGREPORT "https://github.com/mklong/http_request/issues")

PROJECT(${PACKAGE_NAME} C CXX )

set(CMAKE_C_FLAGS "-pipe  -O -W -Wall -Wpointer-arith -Wno-unused-parameter -Werror -g -O0")
set(CMAKE_CXX_FLAGS "-fpermissive")

MESSAGE( STATUS ${CMAKE_C_FLAGS} )
MESSAGE( STATUS ${CMAKE_CXX_FLAGS} )

set(LIBNGX_INCLUDE ${http_request_SOURCE_DIR}/../libngx/src)
MESSAGE( STATUS ${LIBNGX_INCLUDE} )

include_directories(${LIBNGX_INCLUDE})

#ADD_SUBDIRECTORY(src/http_requst)

add_library(http_parser STATIC http_parser/http_parser.c)
add_library(http_request STATIC http_request.cpp)