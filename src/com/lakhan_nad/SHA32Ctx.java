package com.lakhan_nad;

class SHA32Ctx{
		private static final int[] constants = new int[] {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
						0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
						0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
						0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
						0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
						0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
						0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
						0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
		private static final byte one = (byte) 0b10000000;

		// Working Variables
		int[] h;
		int[] w;
		int dataLen;
		long lenRead;
		int done;
		byte[] message;

		private SHA32Ctx(){
				this.reset();
		}

		// Constructor
		SHA32Ctx(int[] hashes){
				h = hashes.clone();
				this.reset();
		}

		private static int sigmaBig0(int n){
				return (((n >>> 2) | (n << (32 - 2))) ^ ((n >>> 13) | (n << (32 - 13))) ^ ((n >>> 22) | (n << (32 - 22))));
		}

		private static int sigmaBig1(int n){
				return ((n >>> 6) | (n << (32 - 6))) ^ ((n >>> 11) | (n << (32 - 11))) ^ ((n >>> 25) | (n << (32 - 25)));
		}

		private static int sigmaSmall0(int n){
				return (((n >>> 7) | (n << (32 - 7))) ^ ((n >>> 18) | (n << (32 - 18))) ^ (n >>> 3));
		}

		private static int sigmaSmall1(int n){
				return (((n >>> 17) | (n << (32 - 17))) ^ ((n >>> 19) | (n << (32 - 19))) ^ (n >>> 10));
		}

		private static int ch(int x, int y, int z){
				return (x & y) ^ ((~x) & z);
		}

		private static int maj(int x, int y, int z){
				return (x & y) ^ (x & z) ^ (y & z);
		}

		private void reset(){
				this.dataLen = 0;
				this.lenRead = 0;
				this.w = new int[16];
				this.done = 0;
				this.message = null;
		}

		public void shaUpdate(){
				SHA32Ctx ctx = this;
				if (ctx.message == null) {
						return;
				}
				byte[] message = ctx.message;
				ctx.lenRead += message.length;
				for (int i = 0, j = 4; i < message.length; i += 4, j += 4) {
						if (j <= message.length) {
								ctx.w[ctx.dataLen] = 0;
								ctx.w[ctx.dataLen] = (ctx.w[ctx.dataLen] << 8) + (message[i] & 0xff);
								ctx.w[ctx.dataLen] = (ctx.w[ctx.dataLen] << 8) + (message[i + 1] & 0xff);
								ctx.w[ctx.dataLen] = (ctx.w[ctx.dataLen] << 8) + (message[i + 2] & 0xff);
								ctx.w[ctx.dataLen] = (ctx.w[ctx.dataLen] << 8) + (message[i + 3] & 0xff);
								ctx.dataLen++;
						} else {
								ctx.done = message.length - i;
								if (ctx.done == 3) {
										ctx.w[ctx.dataLen] = 0;
										ctx.w[ctx.dataLen] = (ctx.w[ctx.dataLen] << 8) + (message[i] & 0xff);
										ctx.w[ctx.dataLen] = (ctx.w[ctx.dataLen] << 8) + (message[i + 1] & 0xff);
										ctx.w[ctx.dataLen] = (ctx.w[ctx.dataLen] << 8) + (message[i + 2] & 0xff);
								} else if (ctx.done == 2) {
										ctx.w[ctx.dataLen] = 0;
										ctx.w[ctx.dataLen] = (ctx.w[ctx.dataLen] << 8) + (message[i] & 0xff);
										ctx.w[ctx.dataLen] = (ctx.w[ctx.dataLen] << 8) + (message[i + 1] & 0xff);
								} else if (ctx.done == 1) {
										ctx.w[ctx.dataLen] = 0;
										ctx.w[ctx.dataLen] = (ctx.w[ctx.dataLen] << 8) + (message[i] & 0xff);
								}
						}
						if (ctx.dataLen == 16) {
								ctx.shaTransform();
								ctx.dataLen = 0;
						}
				}
				ctx.message = null;
		}

		public void processMessage(byte[] message){
				SHA32Ctx ctx = this;
				if (ctx.message != null) {
						shaUpdate();
				}
				ctx.message = message;
				ctx.shaUpdate();
		}

		public void shaFinal(){
				SHA32Ctx ctx = this;
				if (ctx.done % 4 == 0) {
						ctx.done = 0;
						ctx.w[ctx.dataLen] = 0;
				}
				ctx.w[ctx.dataLen] = (ctx.w[ctx.dataLen] << 8) + (one & 0xff);
				ctx.done++;
				while (ctx.done < 4) {
						ctx.w[ctx.dataLen] = (ctx.w[ctx.dataLen] << 8);
						ctx.done++;
				}
				ctx.dataLen++;
				if (ctx.dataLen > 14) {
						ctx.w[ctx.dataLen] = 0;
						ctx.shaTransform();
						ctx.dataLen = 0;
				}
				while (ctx.dataLen < 14) {
						ctx.w[ctx.dataLen] = 0;
						ctx.dataLen++;
				}
				long messageLength = ctx.lenRead * 8;
				ctx.w[15] = ((int) messageLength);
				ctx.w[14] = ((int) (messageLength >>> 32));
				ctx.shaTransform();
				ctx.reset();
		}

		private void shaTransform(){
				SHA32Ctx ctx = this;
				int a, b, c, d, e, f, g, h;
				a = ctx.h[0];
				b = ctx.h[1];
				c = ctx.h[2];
				d = ctx.h[3];
				e = ctx.h[4];
				f = ctx.h[5];
				g = ctx.h[6];
				h = ctx.h[7];
				int temp1, temp2;
				for (int j = 0; j < 64; j++) {
						if (j >= 16) {
								ctx.w[j % 16] = ctx.w[j % 16] + sigmaSmall0(ctx.w[(j - 15) % 16]) + ctx.w[(j - 7) % 16] + sigmaSmall1(ctx.w[(j - 2) % 16]);
						}
						temp1 = h + sigmaBig1(e) + ch(e, f, g) + constants[j] + ctx.w[j % 16];
						temp2 = sigmaBig0(a) + maj(a, b, c);
						h = g;
						g = f;
						f = e;
						e = d + temp1;
						d = c;
						c = b;
						b = a;
						a = temp1 + temp2;
				}
				ctx.h[0] += a;
				ctx.h[1] += b;
				ctx.h[2] += c;
				ctx.h[3] += d;
				ctx.h[4] += e;
				ctx.h[5] += f;
				ctx.h[6] += g;
				ctx.h[7] += h;
		}
}
