package software.amazon.awschecksums;

import java.nio.ByteBuffer;
import java.util.zip.Checksum;

/**
 * Compuates CRC32C using hw accelerated instructions if possible.
 */
public class AWSCRC32C extends AWSCRCAbstract {
    
    @Override
    protected int computeCrc(byte[] data, int pos, int length, int previousCrc) {
        return crc32c(data, pos, length, previousCrc);
    }

    @Override
    protected int computeCrcDirect(ByteBuffer data, int pos, int length, int previousCrc) {
        return crc32cDirect(data, pos, length, previousCrc);
    }

    private native int crc32c(byte[] data, int offset, int length, int previousCrc);
    private native int crc32cDirect(ByteBuffer data, int offset, int length, int previousCrc);
}
