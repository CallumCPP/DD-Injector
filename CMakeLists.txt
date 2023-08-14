cmake_minimum_required(VERSION 3.4)

project(DD-Injector)
add_executable(DD-Injector main.cpp)

SET_TARGET_PROPERTIES(DD-Injector PROPERTIES LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\"")