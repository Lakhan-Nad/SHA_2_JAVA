package test;

import com.lakhan_nad.*;

public class TEST{
		public static void main(String[] args){
				byte[] x = new byte[] {(byte) 0xf4, (byte) 0xf5, (byte) 0x67, (byte) 0x90, (byte) 0x11, (byte) 0x23, (byte) 0xf4, (byte) 0xf5, (byte) 0x67, (byte) 0x90, (byte) 0x11, (byte) 0x23, (byte) 0xf4, (byte) 0xf5, (byte) 0x67, (byte) 0x90, (byte) 0x11, (byte) 0x23
								, (byte) 0xf4, (byte) 0xf5, (byte) 0x67, (byte) 0x90, (byte) 0x11, (byte) 0x23};
				SHA256 sha = new SHA256();
				sha.getOriginalString(x);
				int[] result = sha.hash();
				for (var b : result) {
						System.out.print(String.format("%08x", b));
				}
				System.out.println();
				SHA224 sha2 = new SHA224();
				sha2.getOriginalString(x);
				result = sha2.hash();
				for (var b : result) {
						System.out.print(String.format("%08x", b));
				}
				System.out.println();
				SHA512 sha3 = new SHA512();
				sha3.getOriginalString(x);
				long[] result2 = sha3.hash();
				for (var b : result2) {
						System.out.print(String.format("%016x", b));
				}
				System.out.println();
				SHA384 sha4 = new SHA384();
				sha4.getOriginalString(x);
				result2 = sha4.hash();
				for (var b : result2) {
						System.out.print(String.format("%016x", b));
				}
				System.out.println();
				SHA512_256 sha5 = new SHA512_256();
				sha5.getOriginalString(x);
				result = sha5.hash();
				for (var b : result) {
						System.out.print(String.format("%08x", b));
				}
				System.out.println();
				SHA512_224 sha6 = new SHA512_224();
				sha6.getOriginalString(x);
				result = sha6.hash();
				for (var b : result) {
						System.out.print(String.format("%08x", b));
				}
		}
}
