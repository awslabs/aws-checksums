/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

package software.amazon.awschecksums;


public class AWSChecksumsLoader {
    static boolean loaded = false;

    static {
        reload();
    }

    public static boolean isAvailable() {
        return loaded;
    }

    public static void reload() {
        if (!loaded) {
            try {
                System.loadLibrary("aws-checksums");
                loaded = true;
            } catch (UnsatisfiedLinkError e) {
                // unable to load
                loaded = false;
            }
        }
    }
}
