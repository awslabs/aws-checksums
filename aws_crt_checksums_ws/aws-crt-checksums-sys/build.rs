use aws_crt_c_flags::{CRTModuleBuildInfo, HeaderType};
use std::path::Path;

fn main() {
    let mut build_info = CRTModuleBuildInfo::new("aws-crt-checksums-sys");
    build_info.module_links_dependency("aws-c-common");

    let include_path = Path::new("../../include/aws");
    build_info.include_dir(include_path, HeaderType::Public);

    build_info
        .file(Path::new("../../source/crc.c"))
        .file(Path::new("../../source/crc_sw.c"));

    let mut impl_found = false;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if build_info.follows_msvc_semantics() {
            build_info.file(Path::new(
                "../../source/intel/visualc/visualc_crc32c_sse42.c",
            ));
        } else {
            build_info.file(Path::new("../../source/intel/asm/crc32c_sse42_asm.c"));
        }
        impl_found = true;
    }

    #[cfg(target_arch = "aarch64")]
    {
        build_info.file(Path::new("../../source/arm/crc32c_arm.c"));

        if !build_info.follows_msvc_semantics() {
            build_info.private_cflag("-march=armv8-a+crc");
        }
        impl_found = true;
    }

    #[cfg(all(target_arch = "arm"))]
    {
        if !build_info.follows_msvc_semantics() {
            if build_info
                .try_compile(
                    "#include <arm_acle.h>
            int main() {
            int crc = __crc32d(0, 1);
            return 0;
            }",
                )
                .is_ok()
            {
                build_info
                    .private_cflag("-march=armv8-a+crc")
                    .private_define("AWS_ARM32_CRC", "1");
                build_info.file(Path::new("../../source/arm/crc32c_arm.c"));
                impl_found = true;
            }
        }
    }

    if !impl_found {
        build_info.file(Path::new("../../source/generic/crc32c_null.c"));
    }

    build_info.build();
}
