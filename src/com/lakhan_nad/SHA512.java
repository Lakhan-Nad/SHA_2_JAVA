package com.lakhan_nad;

public class SHA512{
		private static final long[] hashes = new long[] {0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
						0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L};
		private boolean finalized;
		private SHA64Ctx ctx;

		public SHA512(){
				ctx = new SHA64Ctx(hashes);
				finalized = false;
		}

		public void getOriginalString(byte[] message){
				ctx.message = message;
		}

		public long[] hash(){
				if (this.finalized) {
						return null;
				}
				ctx.shaUpdate();
				ctx.shaFinal();
				long[] hashed = ctx.h.clone();
				ctx = null;
				finalized = true;
				return hashed;
		}
}
