package com.lakhan_nad;

public class SHA224{
		private static final int[] hashes = new int[] {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4};
		private static final int DIGEST_SIZE = 28;
		private static final int BLOCK_SIZE = 64;

		private final SHA32Ctx ctx;
		private boolean finalized;

		public SHA224(){
				this.ctx = new SHA32Ctx(hashes);
				this.finalized = false;
		}

		public SHA224(byte[] message){
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
				byte[] cpy = new byte[28];
				this.ctx.getHashBytes(cpy,28);
				return cpy;
		}

		public String getHexDigest(){
				return ctx.getHexString(28);
		}

		public void resetDigest(){
				this.ctx.resetContext(hashes);
				this.finalized = false;
		}

		public static String hash(byte[] message){
				SHA32Ctx ctx = new SHA32Ctx(hashes);
				ctx.processMessage(message);
				ctx.shaFinal();
				return ctx.getHexString(28);
		}
}
