package com.lakhan_nad;

public class SHA512_256{
		private static final long[] hashes = new long[] {0x22312194FC2BF72CL, 0x9F555FA3C84C64C2L, 0x2393B86B6F53B151L, 0x963877195940EABDL,
						0x96283EE2A88EFFE3L, 0xBE5E1E2553863992L, 0x2B0199FC2C85B8AAL, 0x0EB72DDC81C52CA2L};
		private static final int DIGEST_SIZE = 32;
		private static final int BLOCK_SIZE = 128;

		private final SHA64Ctx ctx;
		private boolean finalized;

		public SHA512_256(){
				this.ctx = new SHA64Ctx(hashes);
				this.finalized = false;
		}

		public SHA512_256(byte[] message){
				this.ctx = new SHA64Ctx(hashes);
				this.finalized = false;
				this.ctx.processMessage(message);
		}

		public void update(byte[] message){
				if(!this.finalized){
						this.ctx.processMessage(message);
				}
		}

		public void finals(){
				this.ctx.shaFinal();
				this.finalized = true;
		}

		public byte[] getDigest(){
				byte[] cpy = new byte[32];
				this.ctx.getHashBytes(cpy,32);
				return cpy;
		}

		public String getHexDigest(){
				return ctx.getHexString(32);
		}

		public void resetDigest(){
				this.ctx.resetContext(hashes);
				this.finalized = false;
		}

		public static String hash(byte[] message){
				SHA64Ctx ctx = new SHA64Ctx(hashes);
				ctx.processMessage(message);
				ctx.shaFinal();
				return ctx.getHexString(32);
		}
}


