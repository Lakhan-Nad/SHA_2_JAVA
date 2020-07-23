package com.lakhan_nad;

public class SHA224{
		private static final int[] hashes = new int[] {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4};

		private boolean finalized;
		private SHA32Ctx ctx;

		public SHA224(){
				ctx = new SHA32Ctx(hashes);
				finalized = false;
		}

		public void getOriginalString(byte[] message){
				ctx.message = message;
		}

		public int[] hash(){
				if (this.finalized) {
						return null;
				}
				ctx.shaUpdate();
				ctx.shaFinal();
				int[] hashed = new int[7];
				// Only append first 7 chunks
				System.arraycopy(ctx.h, 0, hashed, 0, 7);
				ctx = null;
				finalized = true;
				return hashed;
		}
}
