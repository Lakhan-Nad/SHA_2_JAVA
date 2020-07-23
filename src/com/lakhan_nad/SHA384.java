package com.lakhan_nad;

public class SHA384{
		private static final long[] hashes = new long[] {0xcbbb9d5dc1059ed8L, 0x629a292a367cd507L, 0x9159015a3070dd17L, 0x152fecd8f70e5939L,
						0x67332667ffc00b31L, 0x8eb44a8768581511L, 0xdb0c2e0d64f98fa7L, 0x47b5481dbefa4fa4L};
		private boolean finalized;
		private SHA64Ctx ctx;

		public SHA384(){
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
				long[] hashed = new long[6];
				System.arraycopy(ctx.h, 0, hashed, 0, 6);
				ctx = null;
				finalized = true;
				return hashed;
		}
}
