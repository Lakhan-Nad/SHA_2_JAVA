package test;

import com.lakhan_nad.*;

public class TEST{
		public static void main(String[] args){
				byte[] x = new byte[0];
				if(args.length > 0){
						x = args[0].getBytes();
				}
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
