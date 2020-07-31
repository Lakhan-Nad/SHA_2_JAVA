package test;

import com.lakhan_nad.*;

public class TEST{
		public static void main(String[] args){
				byte[] x = new byte[] {(byte) 0xf4, (byte) 0xf5, (byte) 0x67, (byte) 0x90, (byte) 0x11, (byte) 0x23, (byte) 0xf4, (byte) 0xf5, (byte) 0x67, (byte) 0x90, (byte) 0x11, (byte) 0x23, (byte) 0xf4, (byte) 0xf5, (byte) 0x67, (byte) 0x90, (byte) 0x11, (byte) 0x23
								, (byte) 0xf4, (byte) 0xf5, (byte) 0x67, (byte) 0x90, (byte) 0x11, (byte) 0x23};
				// SHA256
				System.out.println(SHA256.hash(x));
				// SHA224
				System.out.println(SHA224.hash(x));
				// SHA512
				System.out.println(SHA512.hash(x));
				// SHA384
				System.out.println(SHA384.hash(x));
				// SHA512/256
				System.out.println(SHA512_256.hash(x));
				// SHA512/224
				System.out.println(SHA512_224.hash(x));
		}
}
