cmake_minimum_required (VERSION 3.1)
project (aws-checksums)

file(GLOB AWS_CHECKSUMS_HEADERS
     "include/aws/checksums/*.h"
)

file(GLOB AWS_CHECKSUMS_PRIV_HEADERS
     "include/aws/checksums/private/*.h"
)

file(GLOB AWS_CHECKSUMS_SRC
    "source/*.c"
)

file(GLOB AWS_ARCH_SRC
    "source/intel/*.c"
    "source/arm/*.c"
)

if(WIN32)

     if(MSVC)
         file(GLOB AWS_CHECKSUMS_VISUALC_SOURCE
             "source/visualc/*.c"
         )        

         source_group("Header Files\\aws\\checksums" FILES ${AWS_CHECKSUMS_HEADERS})

         source_group("Source Files" FILES ${AWS_CHECKSUMS_SRC})
         source_group("Source Files\\visualc" FILES ${AWS_CHECKSUMS_VISUALC_SOURCE})
         source_group("Source Files\\arch" FILES ${AWS_ARCH_SRC})
          
         file(GLOB AWS_CHECKSUMS_PLATFORM_SOURCE
             ${AWS_CHECKSUMS_VISUALC_SOURCE}
         )
     endif()
endif()

file(GLOB CHECKSUMS_HEADERS
    ${AWS_CHECKSUMS_HEADERS}
    ${AWS_CHECKSUMS_PRIV_HEADERS}
)

file(GLOB CHECKSUMS_SRC
    ${AWS_CHECKSUMS_SRC}
    ${AWS_CHECKSUMS_PLATFORM_SOURCE}
    ${AWS_ARCH_SRC}
)

if(BUILD_SHARED_LIBS)
    set(LIBTYPE SHARED)
    if(WIN32)
        add_definitions("-DUSE_IMPORT_EXPORT")
    endif()
else()
    set(LIBTYPE STATIC)
endif()

add_library(aws-checksums ${LIBTYPE} ${CHECKSUMS_HEADERS} ${CHECKSUMS_SRC})
set_target_properties(aws-checksums PROPERTIES LINKER_LANGUAGE C)
set(CMAKE_C_FLAGS_DEBUGOPT "")
set_property(TARGET aws-checksums PROPERTY C_STANDARD 99)

if(BUILD_SHARED_LIBS AND WIN32)
    target_compile_definitions(aws-checksums PRIVATE "-DAWS_CHECKSUMS_EXPORTS")    
endif()

if(BUILD_JNI_BINDINGS)
find_package(JNI)
    include_directories(${JNI_INCLUDE_DIRS})
	set(PLATFORM_LIBS ${PLATFORM_LIBS} ${JNI_LIBRARIES})
	target_compile_definitions(aws-checksums PRIVATE "-DBUILD_JNI_BINDINGS")    

endif()

if(CMAKE_BUILD_TYPE STREQUAL "" OR CMAKE_BUILD_TYPE MATCHES DEBUG)
    target_compile_definitions(aws-checksums PRIVATE "-DDEBUG_BUILD")
endif()

target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
  
target_link_libraries(aws-checksums ${PLATFORM_LIBS})

file(GLOB TEST_SRC "tests/*.c")
file(GLOB TEST_HDRS "tests/*.h")
file(GLOB TESTS ${TEST_HDRS} ${TEST_SRC})
  
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/tests)
add_executable(aws-checksums-tests ${TESTS})
target_link_libraries(aws-checksums-tests aws-checksums)
set_target_properties(aws-checksums-tests PROPERTIES LINKER_LANGUAGE C)

include(CTest)
enable_testing()
add_test(crc32c aws-checksums-tests crc32c)
add_test(crc32 aws-checksums-tests crc32)


install (FILES ${AWS_CHECKSUMS_HEADERS} DESTINATION "include/aws/checksums")
install (
         TARGETS ${PROJECT_NAME}
         EXPORT "${PROJECT_NAME}-targets"
         ARCHIVE DESTINATION lib
         LIBRARY DESTINATION lib
         COMPONENT library     
)
install(EXPORT "${PROJECT_NAME}-targets" FILE "${PROJECT_NAME}-targets.cmake" DESTINATION bin)
export(EXPORT "${PROJECT_NAME}-targets" FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-targets.cmake")
