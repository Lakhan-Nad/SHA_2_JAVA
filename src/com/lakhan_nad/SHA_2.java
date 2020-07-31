package com.lakhan_nad;

// Exposing Static APIS

public class SHA_2{
		public static SHA256 sha256(){
				return new SHA256();
		}

		public static SHA224 sha224(){
				return new SHA224();
		}

		public static SHA384 sha384(){
				return new SHA384();
		}

		public static SHA512 sha512(){
				return new SHA512();
		}

		public static SHA512_224 sha512_224(){
				return new SHA512_224();
		}

		public static SHA512_256 sha512_256(){
				return new SHA512_256();
		}
}