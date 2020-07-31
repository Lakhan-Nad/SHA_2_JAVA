package com.lakhan_nad;

public class SHA384{
		private static final long[] hashes = new long[] {0xcbbb9d5dc1059ed8L, 0x629a292a367cd507L, 0x9159015a3070dd17L, 0x152fecd8f70e5939L,
						0x67332667ffc00b31L, 0x8eb44a8768581511L, 0xdb0c2e0d64f98fa7L, 0x47b5481dbefa4fa4L};
		private static final int DIGEST_SIZE = 48;
		private static final int BLOCK_SIZE = 128;

		private final SHA64Ctx ctx;
		private boolean finalized;

		public SHA384(){
				this.ctx = new SHA64Ctx(hashes);
				this.finalized = false;
		}

		public SHA384(byte[] message){
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
				byte[] cpy = new byte[48];
				this.ctx.getHashBytes(cpy,48);
				return cpy;
		}

		public String getHexDigest(){
				return ctx.getHexString(48);
		}

		public void resetDigest(){
				this.ctx.resetContext(hashes);
				this.finalized = false;
		}

		public static String hash(byte[] message){
				SHA64Ctx ctx = new SHA64Ctx(hashes);
				ctx.processMessage(message);
				ctx.shaFinal();
				return ctx.getHexString(48);
		}
}
