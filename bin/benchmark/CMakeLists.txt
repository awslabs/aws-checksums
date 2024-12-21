project(checksum-profile C)

file(GLOB PROFILE_SRC
        "*.c"
        )

set(PROFILE_PROJECT_NAME checksum-profile)
add_executable(${PROFILE_PROJECT_NAME} ${PROFILE_SRC})
aws_set_common_properties(${PROFILE_PROJECT_NAME})


target_include_directories(${PROFILE_PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

target_link_libraries(${PROFILE_PROJECT_NAME} PRIVATE aws-checksums)

if (BUILD_SHARED_LIBS AND NOT WIN32)
    message(INFO " checksum-profile will be built with shared libs, but you may need to set LD_LIBRARY_PATH=${CMAKE_INSTALL_PREFIX}/lib to run the application")
endif()

install(TARGETS ${PROFILE_PROJECT_NAME}
        EXPORT ${PROFILE_PROJECT_NAME}-targets
        COMPONENT Runtime
        RUNTIME
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT Runtime)
