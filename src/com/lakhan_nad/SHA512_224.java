package com.lakhan_nad;

public class SHA512_224{
		private static final long[] hashes = new long[] {0x8C3D37C819544DA2L, 0x73E1996689DCD4D6L, 0x1DFAB7AE32FF9C82L, 0x679DD514582F9FCFL,
						0x0F6D2B697BD44DA8L, 0x77E36F7304C48942L, 0x3F9D85A86A1D36C8L, 0x1112E6AD91D692A1L};
		private static final int DIGEST_SIZE = 28;
		private static final int BLOCK_SIZE = 128;

		private final SHA64Ctx ctx;
		private boolean finalized;

		public SHA512_224(){
				this.ctx = new SHA64Ctx(hashes);
				this.finalized = false;
		}

		public SHA512_224(byte[] message){
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
				SHA64Ctx ctx = new SHA64Ctx(hashes);
				ctx.processMessage(message);
				ctx.shaFinal();
				return ctx.getHexString(28);
		}
}

