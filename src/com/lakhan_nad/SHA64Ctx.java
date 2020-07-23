package com.lakhan_nad;

import java.math.BigInteger;

class SHA64Ctx{
		private static final long[] constants = new long[] {0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL, 0x3956c25bf348b538L,
						0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L, 0xd807aa98a3030242L, 0x12835b0145706fbeL,
						0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L, 0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L,
						0xc19bf174cf692694L, 0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
						0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L, 0x983e5152ee66dfabL,
						0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L, 0xc6e00bf33da88fc2L, 0xd5a79147930aa725L,
						0x06ca6351e003826fL, 0x142929670a0e6e70L, 0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL,
						0x53380d139d95b3dfL, 0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL,
						0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L, 0xd192e819d6ef5218L,
						0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L, 0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L,
						0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L, 0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L,
						0x682e6ff3d6b2b8a3L, 0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
						0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL, 0xca273eceea26619cL,
						0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L, 0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L,
						0x113f9804bef90daeL, 0x1b710b35131c471bL, 0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL,
						0x431d67c49c100d4cL, 0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L};
		private static final byte one = (byte) 0b10000000;

		// Working Variables
		long[] h;
		long[] w;
		int dataLen;
		int done;
		long lenRead;
		byte[] message;

		private SHA64Ctx(){
				this.reset();
		}

		// Constructor
		SHA64Ctx(long[] hashes){
				this.h = hashes.clone();
				this.reset();
		}

		private static long sigmaBig0(long n){
				return (((n >>> 28) | (n << (64 - 28))) ^ ((n >>> 34) | (n << (64 - 34))) ^ ((n >>> 39) | (n << (64 - 39))));
		}

		private static long sigmaBig1(long n){
				return ((n >>> 14) | (n << (64 - 14))) ^ ((n >>> 18) | (n << (64 - 18))) ^ ((n >>> 41) | (n << (64 - 41)));
		}

		private static long sigmaSmall0(long n){
				return (((n >>> 1) | (n << (64 - 1))) ^ ((n >>> 8) | (n << (64 - 8))) ^ (n >>> 7));
		}

		private static long sigmaSmall1(long n){
				return (((n >>> 19) | (n << (64 - 19))) ^ ((n >>> 61) | (n << (64 - 61))) ^ (n >>> 6));
		}

		private static long ch(long x, long y, long z){
				return (x & y) ^ ((~x) & z);
		}

		private static long maj(long x, long y, long z){
				return (x & y) ^ (x & z) ^ (y & z);
		}

		private static long byteArrToLong(byte[] data, int start, int end){
				long v = 0;
				for (int i = 0; i < 8 && start < end; i++) {
						v = (v << 8) + (data[start] & 0xff);
						start++;
				}
				return v;
		}

		private void reset(){
				this.dataLen = 0;
				this.done = 0;
				this.lenRead = 0;
				this.w = new long[16];
				this.message = null;
		}

		public void shaUpdate(){
				SHA64Ctx ctx = this;
				if (ctx.message == null) {
						return;
				}
				byte[] message = ctx.message;
				int z;
				ctx.lenRead += message.length;
				for (int i = 0, j = 8; i < message.length; i += 8, j += 8) {
						z = Math.min(j, message.length);
						ctx.w[ctx.dataLen] = byteArrToLong(message, i, z);
						if (j == z) {
								ctx.dataLen++;
						} else {
								ctx.done = z - i;
						}
				}
				ctx.message = null;
		}

		public void processMessage(byte[] message){
				SHA64Ctx ctx = this;
				if (ctx.message != null) {
						shaUpdate();
				}
				ctx.message = message;
				ctx.shaUpdate();
		}

		public void shaFinal(){
				SHA64Ctx ctx = this;
				if (ctx.done % 8 == 0) {
						ctx.w[ctx.dataLen] = 0;
						ctx.done = 0;
				}
				ctx.w[ctx.dataLen] = (ctx.w[ctx.dataLen] << 8) + (one & 0xff);
				ctx.done++;
				while (ctx.done < 8) {
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
				BigInteger b = new BigInteger(Long.toString(ctx.lenRead));
				byte[] arr = b.multiply(BigInteger.valueOf(8L)).toByteArray();
				int j = Math.min(arr.length, 8);
				int z = Math.max(8, arr.length);
				ctx.w[15] = byteArrToLong(arr, 0, j);
				ctx.w[14] = byteArrToLong(arr, 8, z);
				ctx.shaTransform();
				ctx.reset();
		}

		private void shaTransform(){
				SHA64Ctx ctx = this;
				long a, b, c, d, e, f, g, h;
				a = ctx.h[0];
				b = ctx.h[1];
				c = ctx.h[2];
				d = ctx.h[3];
				e = ctx.h[4];
				f = ctx.h[5];
				g = ctx.h[6];
				h = ctx.h[7];
				long temp1, temp2;
				for (int j = 0; j < 80; j++) {
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
