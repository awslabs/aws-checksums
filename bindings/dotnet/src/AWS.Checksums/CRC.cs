using System;
using System.Security.Cryptography;

namespace AWS.Checksums
{
    public abstract class CRC : HashAlgorithm
    {
        private uint currentCrc = 0;
        private uint lastComputedCRC = 0;
        private bool resetCalled = false;

        public override void Initialize()
        {
            resetCalled = true;
        }

        protected override void Dispose(bool disposing)
        {
            //no unmanaged resources here.
        }

        public byte[] LastComputedCRCAsBigEndian
        {
            get
            {
                if (BitConverter.IsLittleEndian)
                {
                    byte[] crcLE = HashFinal();
                    Array.Reverse(crcLE);
                    return crcLE;
                }
                else
                {
                    return HashFinal();
                }
            }
        }

        public abstract uint ComputeRunning(byte[] buffer, int length, uint previousCrc);
        
        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(currentCrc);
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if(resetCalled)
            {
                currentCrc = 0;
                resetCalled = false;
            }

            if (ibStart == 0)
            {
                currentCrc = ComputeRunning(array, cbSize, currentCrc);
            }
            else
            {
                byte[] array_cpy = new byte[cbSize];
                Buffer.BlockCopy(array, ibStart, array_cpy, 0, cbSize);
                currentCrc = ComputeRunning(array_cpy, cbSize, currentCrc);
            }
        }
    }
    public class CRC32C : CRC
    {
        public override uint ComputeRunning(byte[] buffer, int length, uint previousCrc)
        {
            return NativeInterop.AWSCRCNative.CRC32C(buffer, length, previousCrc);
        }

    }

    public class CRC32 : CRC
    {
        public override uint ComputeRunning(byte[] buffer, int length, uint previousCrc)
        {
            return NativeInterop.AWSCRCNative.CRC32(buffer, length, previousCrc);
        }
    }
}
