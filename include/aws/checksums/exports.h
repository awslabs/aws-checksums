#ifndef AWS_CHECKSUMS_EXPORTS_H
#define AWS_CHECKSUMS_EXPORTS_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#if defined(USE_WINDOWS_DLL_SEMANTICS) || defined(_WIN32)
#    ifdef USE_IMPORT_EXPORT
#        ifdef AWS_CHECKSUMS_EXPORTS
#            define AWS_CHECKSUMS_API __declspec(dllexport)
#        else
#            define AWS_CHECKSUMS_API __declspec(dllimport)
#        endif /* AWS_CHECKSUMS_EXPORTS */
#    else
#        define AWS_CHECKSUMS_API
#    endif /* USE_IMPORT_EXPORT */
#else      /* defined (USE_WINDOWS_DLL_SEMANTICS) || defined (_WIN32) */
#    if ((__GNUC__ >= 4) || defined(__clang__))
#        define AWS_CHECKSUMS_API __attribute__((visibility("default")))
#    else
#        define AWS_CHECKSUMS_API
#    endif /* __GNUC__ >= 4 || defined(__clang__) */
#endif     /* defined (USE_WINDOWS_DLL_SEMANTICS) || defined (_WIN32) */

#endif /* AWS_CHECKSUMS_EXPORTS_H */
