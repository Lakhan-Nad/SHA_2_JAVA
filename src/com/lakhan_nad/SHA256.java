package com.lakhan_nad;

public class SHA256{
		private static final int[] hashes = new int[] {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f
						, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
		private static final int DIGEST_SIZE = 32;
		private static final int BLOCK_SIZE = 64;

		private final SHA32Ctx ctx;
		private boolean finalized;

		public SHA256(){
				this.ctx = new SHA32Ctx(hashes);
				this.finalized = false;
		}

		public SHA256(byte[] message){
				this.ctx = new SHA32Ctx(hashes);
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
				SHA32Ctx ctx = new SHA32Ctx(hashes);
				ctx.processMessage(message);
				ctx.shaFinal();
				return ctx.getHexString(32);
		}
}
