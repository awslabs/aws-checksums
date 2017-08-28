package software.amazon.awschecksums;

import java.nio.ByteBuffer;
import java.util.zip.Checksum;

/**
 * computes CRC32 using hw acceleration if possible.
 */
public class AWSCRC32 extends AWSCRCAbstract {

    @Override
    protected int computeCrc(byte[] data, int pos, int length, int previousCrc) {
        return crc32(data, pos, length, previousCrc);
    }

    @Override
    protected int computeCrcDirect(ByteBuffer data, int pos, int length, int previousCrc) {
        return crc32Direct(data, pos, length, previousCrc);
    }

    private native int crc32(byte[] data, int offset, int length, int previousCrc);

    private native int crc32Direct(ByteBuffer data, int offset, int length, int previousCrc);
}
