package com.lakhan_nad;

public class SHA256{
		private static final int[] hashes = new int[] {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f
						, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
		private boolean finalized;
		private SHA32Ctx ctx;

		public SHA256(){
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
				int[] hashed = ctx.h.clone();
				ctx = null;
				finalized = true;
				return hashed;
		}
}
