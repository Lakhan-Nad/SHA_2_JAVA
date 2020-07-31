package com.lakhan_nad;

public class SHA512{
		private static final long[] hashes = new long[] {0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
						0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L};
		private static final int DIGEST_SIZE = 64;
		private static final int BLOCK_SIZE = 128;

		private final SHA64Ctx ctx;
		private boolean finalized;

		public SHA512(){
				this.ctx = new SHA64Ctx(hashes);
				this.finalized = false;
		}

		public SHA512(byte[] message){
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
				byte[] cpy = new byte[64];
				this.ctx.getHashBytes(cpy,64);
				return cpy;
		}

		public String getHexDigest(){
				return ctx.getHexString(64);
		}

		public void resetDigest(){
				this.ctx.resetContext(hashes);
				this.finalized = false;
		}

		public static String hash(byte[] message){
				SHA64Ctx ctx = new SHA64Ctx(hashes);
				ctx.processMessage(message);
				ctx.shaFinal();
				return ctx.getHexString(64);
		}
}
