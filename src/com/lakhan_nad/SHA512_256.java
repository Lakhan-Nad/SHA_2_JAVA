package com.lakhan_nad;

public class SHA512_256{
		private static final long[] hashes = new long[] {0x22312194FC2BF72CL, 0x9F555FA3C84C64C2L, 0x2393B86B6F53B151L, 0x963877195940EABDL,
						0x96283EE2A88EFFE3L, 0xBE5E1E2553863992L, 0x2B0199FC2C85B8AAL, 0x0EB72DDC81C52CA2L};
		private boolean finalized;
		private SHA64Ctx ctx;

		public SHA512_256(){
				ctx = new SHA64Ctx(hashes);
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
				int[] hashed = new int[8];
				for (int i = 0; i < 4; i++) {
						hashed[i * 2] = (int) (ctx.h[i] >>> 32);
						hashed[i * 2 + 1] = (int) (ctx.h[i]);
				}
				ctx = null;
				finalized = true;
				return hashed;
		}
}


