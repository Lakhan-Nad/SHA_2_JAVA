package com.lakhan_nad;

public class SHA512_224{
		private static final long[] hashes = new long[] {0x8C3D37C819544DA2L, 0x73E1996689DCD4D6L, 0x1DFAB7AE32FF9C82L, 0x679DD514582F9FCFL,
						0x0F6D2B697BD44DA8L, 0x77E36F7304C48942L, 0x3F9D85A86A1D36C8L, 0x1112E6AD91D692A1L};
		private boolean finalized;
		private SHA64Ctx ctx;

		public SHA512_224(){
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
				int[] hashed = new int[7];
				for (int i = 0; i < 3; i++) {
						hashed[i * 2] = (int) (ctx.h[i] >>> 32);
						hashed[i * 2 + 1] = (int) (ctx.h[i]);
				}
				hashed[6] = (int) (ctx.h[3] >>> 32);
				ctx = null;
				finalized = true;
				return hashed;
		}
}

