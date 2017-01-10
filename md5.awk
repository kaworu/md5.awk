#!/usr/bin/awk -f

BEGIN {
	_ord_init();
	_bitwise_init();
	_md5_init();
}

{
	# we need to remember the file order.
	if (nfiles == 0 || files[nfiles] != FILENAME)
		files[++nfiles] = FILENAME;
	content[FILENAME] = content[FILENAME] $0 "\n";
}

END {
	for (i = 1; i <= nfiles; i++) {
		fn = files[i];
		printf("MD5(%s)= %s\n", fn, md5(content[fn]));
	}
}

function md5(input,
	     nbytes, chars, i, bytes, words, nwords, hi, lo, state, a, b, c, d,
	     j, x, digest, ret) {
	# convert the input into an array of bytes using ord() on each char.
	nbytes = split(input, chars, "");
	for (i = 1; i <= nbytes; i++)
		bytes[i] = ord(chars[i]);
	# convert the array of bytes into an array of 32 bits words.
	# NOTE: words is 0-indexed.
	for (i = 1; i <= nbytes; i += 4) {
		hi = bw_or(bw_lshift(bytes[i + 3], 8), bytes[i + 2]);
		lo = bw_or(bw_lshift(bytes[i + 1], 8), bytes[i + 0]);
		words[nwords++] = bw_or(bw_lshift(hi, 16), lo);
	}
	# Step 1. Append Padding Bits
	if (nbytes % 4 == 0) {
		# the input size is congruent modulo 32, we need a new word to
		# store the first '1' padding bit.
		words[nwords++] = 128; # 0x80
	} else {
		# append a '1' bit in the bytes just after the last input byte.
		words[nwords - 1] = bw_or(words[nwords - 1], bw_lshift(128, (nbytes % 4) * 8));
	}
	# fill the remaining bytes with 0 until we're just shy two words of
	# having 16-Word Blocks.
	while ((nwords % 16) != 14)
		words[nwords++] = 0;
	# Step 2. Append Length
	hi = bw_rshift(nbytes * 8, 32);
	lo = (nbytes * 8) - bw_lshift(hi, 32);
	words[nwords++] = lo;
	words[nwords++] = mod32(hi);
	# Step 3. Initialize MD Buffer
	state[0] = 1732584193; # 0x67452301
	state[1] = 4023233417; # 0xefcdab89
	state[2] = 2562383102; # 0x98badcfe
	state[3] =  271733878; # 0x10325476
	# Step 4. Process Message in 16-Word Blocks
	# Process each 16-word block.
	for (i = 0; i < nwords; i += 16) {
		# Copy block i into x.
		for (j = 0; j < 16; j++)
			x[j] = words[i + j];
		a = state[0]; b = state[1]; c = state[2]; d = state[3];
		# Round 1
		a = FF(a, b, c, d, x[ 0], S11, 3614090360); # 0xd76aa478
		d = FF(d, a, b, c, x[ 1], S12, 3905402710); # 0xe8c7b756
		c = FF(c, d, a, b, x[ 2], S13,  606105819); # 0x242070db
		b = FF(b, c, d, a, x[ 3], S14, 3250441966); # 0xc1bdceee
		a = FF(a, b, c, d, x[ 4], S11, 4118548399); # 0xf57c0faf
		d = FF(d, a, b, c, x[ 5], S12, 1200080426); # 0x4787c62a
		c = FF(c, d, a, b, x[ 6], S13, 2821735955); # 0xa8304613
		b = FF(b, c, d, a, x[ 7], S14, 4249261313); # 0xfd469501
		a = FF(a, b, c, d, x[ 8], S11, 1770035416); # 0x698098d8
		d = FF(d, a, b, c, x[ 9], S12, 2336552879); # 0x8b44f7af
		c = FF(c, d, a, b, x[10], S13, 4294925233); # 0xffff5bb1
		b = FF(b, c, d, a, x[11], S14, 2304563134); # 0x895cd7be
		a = FF(a, b, c, d, x[12], S11, 1804603682); # 0x6b901122
		d = FF(d, a, b, c, x[13], S12, 4254626195); # 0xfd987193
		c = FF(c, d, a, b, x[14], S13, 2792965006); # 0xa679438e
		b = FF(b, c, d, a, x[15], S14, 1236535329); # 0x49b40821

		# Round 2
		a = GG(a, b, c, d, x[ 1], S21, 4129170786); # 0xf61e2562
		d = GG(d, a, b, c, x[ 6], S22, 3225465664); # 0xc040b340
		c = GG(c, d, a, b, x[11], S23,  643717713); # 0x265e5a51
		b = GG(b, c, d, a, x[ 0], S24, 3921069994); # 0xe9b6c7aa
		a = GG(a, b, c, d, x[ 5], S21, 3593408605); # 0xd62f105d
		d = GG(d, a, b, c, x[10], S22,   38016083); # 0x2441453
		c = GG(c, d, a, b, x[15], S23, 3634488961); # 0xd8a1e681
		b = GG(b, c, d, a, x[ 4], S24, 3889429448); # 0xe7d3fbc8
		a = GG(a, b, c, d, x[ 9], S21,  568446438); # 0x21e1cde6
		d = GG(d, a, b, c, x[14], S22, 3275163606); # 0xc33707d6
		c = GG(c, d, a, b, x[ 3], S23, 4107603335); # 0xf4d50d87
		b = GG(b, c, d, a, x[ 8], S24, 1163531501); # 0x455a14ed
		a = GG(a, b, c, d, x[13], S21, 2850285829); # 0xa9e3e905
		d = GG(d, a, b, c, x[ 2], S22, 4243563512); # 0xfcefa3f8
		c = GG(c, d, a, b, x[ 7], S23, 1735328473); # 0x676f02d9
		b = GG(b, c, d, a, x[12], S24, 2368359562); # 0x8d2a4c8a

		# Round 3
		a = HH(a, b, c, d, x[ 5], S31, 4294588738); # 0xfffa3942
		d = HH(d, a, b, c, x[ 8], S32, 2272392833); # 0x8771f681
		c = HH(c, d, a, b, x[11], S33, 1839030562); # 0x6d9d6122
		b = HH(b, c, d, a, x[14], S34, 4259657740); # 0xfde5380c
		a = HH(a, b, c, d, x[ 1], S31, 2763975236); # 0xa4beea44
		d = HH(d, a, b, c, x[ 4], S32, 1272893353); # 0x4bdecfa9
		c = HH(c, d, a, b, x[ 7], S33, 4139469664); # 0xf6bb4b60
		b = HH(b, c, d, a, x[10], S34, 3200236656); # 0xbebfbc70
		a = HH(a, b, c, d, x[13], S31,  681279174); # 0x289b7ec6
		d = HH(d, a, b, c, x[ 0], S32, 3936430074); # 0xeaa127fa
		c = HH(c, d, a, b, x[ 3], S33, 3572445317); # 0xd4ef3085
		b = HH(b, c, d, a, x[ 6], S34,   76029189); # 0x4881d05
		a = HH(a, b, c, d, x[ 9], S31, 3654602809); # 0xd9d4d039
		d = HH(d, a, b, c, x[12], S32, 3873151461); # 0xe6db99e5
		c = HH(c, d, a, b, x[15], S33,  530742520); # 0x1fa27cf8
		b = HH(b, c, d, a, x[ 2], S34, 3299628645); # 0xc4ac5665

		# Round 4
		a = II(a, b, c, d, x[ 0], S41, 4096336452); # 0xf4292244
		d = II(d, a, b, c, x[ 7], S42, 1126891415); # 0x432aff97
		c = II(c, d, a, b, x[14], S43, 2878612391); # 0xab9423a7
		b = II(b, c, d, a, x[ 5], S44, 4237533241); # 0xfc93a039
		a = II(a, b, c, d, x[12], S41, 1700485571); # 0x655b59c3
		d = II(d, a, b, c, x[ 3], S42, 2399980690); # 0x8f0ccc92
		c = II(c, d, a, b, x[10], S43, 4293915773); # 0xffeff47d
		b = II(b, c, d, a, x[ 1], S44, 2240044497); # 0x85845dd1
		a = II(a, b, c, d, x[ 8], S41, 1873313359); # 0x6fa87e4f
		d = II(d, a, b, c, x[15], S42, 4264355552); # 0xfe2ce6e0
		c = II(c, d, a, b, x[ 6], S43, 2734768916); # 0xa3014314
		b = II(b, c, d, a, x[13], S44, 1309151649); # 0x4e0811a1
		a = II(a, b, c, d, x[ 4], S41, 4149444226); # 0xf7537e82
		d = II(d, a, b, c, x[11], S42, 3174756917); # 0xbd3af235
		c = II(c, d, a, b, x[ 2], S43,  718787259); # 0x2ad7d2bb
		b = II(b, c, d, a, x[ 9], S44, 3951481745); # 0xeb86d391

		state[0] = mod32(state[0] + a);
		state[1] = mod32(state[1] + b);
		state[2] = mod32(state[2] + c);
		state[3] = mod32(state[3] + d);
	}

	for (i = j = 0; j < 16; j += 4) {
		digest[j] = bw_and(state[i], 255); # 0xff
		digest[j+1] = bw_and(bw_rshift(state[i],  8), 255);
		digest[j+2] = bw_and(bw_rshift(state[i], 16), 255);
		digest[j+3] = bw_and(bw_rshift(state[i++], 24), 255);
	}
	for (i = 0; i < 16; i++)
		ret = sprintf("%s%02x", ret, digest[i]);
	return ret;
}

function F(x, y, z) {
	return bw_or(bw_and(x, y), bw_and(not(x), z));
}
function G(x, y, z) {
	return bw_or(bw_and(x, z), bw_and(y, not(z)));
}
function H(x, y, z) {
	return bw_xor(x, bw_xor(y, z));
}
function I(x, y, z) {
	return bw_xor(y, bw_or(x, not(z)));
}

function ROTATE_LEFT(x, n) {
	return bw_or(mod32(bw_lshift(x, n)), bw_rshift(x, 32 - n));
}

function FF(a, b, c, d, x, s, ac) {
	a = mod32(a + F(b, c, d) + x + ac);
	a = ROTATE_LEFT(a, s);
	a = mod32(a + b);
	return a;
}
function GG(a, b, c, d, x, s, ac) {
	a = mod32(a + G(b, c, d) + x + ac);
	a = ROTATE_LEFT(a, s);
	a = mod32(a + b);
	return a;
}
function HH(a, b, c, d, x, s, ac) {
	a = mod32(a + H(b, c, d) + x + ac);
	a = ROTATE_LEFT(a, s);
	a = mod32(a + b);
	return a;
}
function II(a, b, c, d, x, s, ac) {
	a = mod32(a + I(b, c, d) + x + ac);
	a = ROTATE_LEFT(a, s);
	a = mod32(a + b);
	return a;
}

function mod32(x) {
	return x - int(x / pow2[32]) * pow2[32];
}

function not(x) {
	return bw_xor(x, 4294967295); # 0xffffffff
}

function bw_rshift(x, n) {
	return int(x / pow2[n]);
}
function bw_lshift(x, n) {
	return mod32(x * pow2[n]);
}
function bw_and(x, y,
	    i, r) {
	for (i = 0; i < 32; i += 4) {
		r = r / pow2[4] + andlookup[(x%16)*16+(y%16)] * pow2[28];
		x = int(x / pow2[4]);
		y = int(y / pow2[4]);
	}
	return r;
}
function bw_or(x, y,
	    i, r) {
	for (i = 0; i < 32; i += 4) {
		r = r / pow2[4] + orlookup[(x%16)*16+(y%16)] * pow2[28];
		x = int(x / pow2[4]);
		y = int(y / pow2[4]);
	}
	return r;
}
function bw_xor(x, y) {
	return (x + y - 2 * bw_and(x, y));
}

function _md5_init() {
	# MD5 shift constants setup.
	S11 = 7;
	S12 = 12;
	S13 = 17;
	S14 = 22;
	S21 = 5;
	S22 = 9;
	S23 = 14;
	S24 = 20;
	S31 = 4;
	S32 = 11;
	S33 = 16;
	S34 = 23;
	S41 = 6;
	S42 = 10;
	S43 = 15;
	S44 = 21;
}

function _bitwise_init() {
	# power of 2 table, inspired by http://stackoverflow.com/a/2982963
	for (pow2[0] = i = 1; i <= 32; i++)
		pow2[i] = 2 * pow2[i - 1];
	# table for and() and or(), see andlookup.c and orlookup.c
	andlookup[  0] =  0; orlookup[  0] =  0;
	andlookup[  1] =  0; orlookup[  1] =  1;
	andlookup[  2] =  0; orlookup[  2] =  2;
	andlookup[  3] =  0; orlookup[  3] =  3;
	andlookup[  4] =  0; orlookup[  4] =  4;
	andlookup[  5] =  0; orlookup[  5] =  5;
	andlookup[  6] =  0; orlookup[  6] =  6;
	andlookup[  7] =  0; orlookup[  7] =  7;
	andlookup[  8] =  0; orlookup[  8] =  8;
	andlookup[  9] =  0; orlookup[  9] =  9;
	andlookup[ 10] =  0; orlookup[ 10] = 10;
	andlookup[ 11] =  0; orlookup[ 11] = 11;
	andlookup[ 12] =  0; orlookup[ 12] = 12;
	andlookup[ 13] =  0; orlookup[ 13] = 13;
	andlookup[ 14] =  0; orlookup[ 14] = 14;
	andlookup[ 15] =  0; orlookup[ 15] = 15;
	andlookup[ 16] =  0; orlookup[ 16] =  1;
	andlookup[ 17] =  1; orlookup[ 17] =  1;
	andlookup[ 18] =  0; orlookup[ 18] =  3;
	andlookup[ 19] =  1; orlookup[ 19] =  3;
	andlookup[ 20] =  0; orlookup[ 20] =  5;
	andlookup[ 21] =  1; orlookup[ 21] =  5;
	andlookup[ 22] =  0; orlookup[ 22] =  7;
	andlookup[ 23] =  1; orlookup[ 23] =  7;
	andlookup[ 24] =  0; orlookup[ 24] =  9;
	andlookup[ 25] =  1; orlookup[ 25] =  9;
	andlookup[ 26] =  0; orlookup[ 26] = 11;
	andlookup[ 27] =  1; orlookup[ 27] = 11;
	andlookup[ 28] =  0; orlookup[ 28] = 13;
	andlookup[ 29] =  1; orlookup[ 29] = 13;
	andlookup[ 30] =  0; orlookup[ 30] = 15;
	andlookup[ 31] =  1; orlookup[ 31] = 15;
	andlookup[ 32] =  0; orlookup[ 32] =  2;
	andlookup[ 33] =  0; orlookup[ 33] =  3;
	andlookup[ 34] =  2; orlookup[ 34] =  2;
	andlookup[ 35] =  2; orlookup[ 35] =  3;
	andlookup[ 36] =  0; orlookup[ 36] =  6;
	andlookup[ 37] =  0; orlookup[ 37] =  7;
	andlookup[ 38] =  2; orlookup[ 38] =  6;
	andlookup[ 39] =  2; orlookup[ 39] =  7;
	andlookup[ 40] =  0; orlookup[ 40] = 10;
	andlookup[ 41] =  0; orlookup[ 41] = 11;
	andlookup[ 42] =  2; orlookup[ 42] = 10;
	andlookup[ 43] =  2; orlookup[ 43] = 11;
	andlookup[ 44] =  0; orlookup[ 44] = 14;
	andlookup[ 45] =  0; orlookup[ 45] = 15;
	andlookup[ 46] =  2; orlookup[ 46] = 14;
	andlookup[ 47] =  2; orlookup[ 47] = 15;
	andlookup[ 48] =  0; orlookup[ 48] =  3;
	andlookup[ 49] =  1; orlookup[ 49] =  3;
	andlookup[ 50] =  2; orlookup[ 50] =  3;
	andlookup[ 51] =  3; orlookup[ 51] =  3;
	andlookup[ 52] =  0; orlookup[ 52] =  7;
	andlookup[ 53] =  1; orlookup[ 53] =  7;
	andlookup[ 54] =  2; orlookup[ 54] =  7;
	andlookup[ 55] =  3; orlookup[ 55] =  7;
	andlookup[ 56] =  0; orlookup[ 56] = 11;
	andlookup[ 57] =  1; orlookup[ 57] = 11;
	andlookup[ 58] =  2; orlookup[ 58] = 11;
	andlookup[ 59] =  3; orlookup[ 59] = 11;
	andlookup[ 60] =  0; orlookup[ 60] = 15;
	andlookup[ 61] =  1; orlookup[ 61] = 15;
	andlookup[ 62] =  2; orlookup[ 62] = 15;
	andlookup[ 63] =  3; orlookup[ 63] = 15;
	andlookup[ 64] =  0; orlookup[ 64] =  4;
	andlookup[ 65] =  0; orlookup[ 65] =  5;
	andlookup[ 66] =  0; orlookup[ 66] =  6;
	andlookup[ 67] =  0; orlookup[ 67] =  7;
	andlookup[ 68] =  4; orlookup[ 68] =  4;
	andlookup[ 69] =  4; orlookup[ 69] =  5;
	andlookup[ 70] =  4; orlookup[ 70] =  6;
	andlookup[ 71] =  4; orlookup[ 71] =  7;
	andlookup[ 72] =  0; orlookup[ 72] = 12;
	andlookup[ 73] =  0; orlookup[ 73] = 13;
	andlookup[ 74] =  0; orlookup[ 74] = 14;
	andlookup[ 75] =  0; orlookup[ 75] = 15;
	andlookup[ 76] =  4; orlookup[ 76] = 12;
	andlookup[ 77] =  4; orlookup[ 77] = 13;
	andlookup[ 78] =  4; orlookup[ 78] = 14;
	andlookup[ 79] =  4; orlookup[ 79] = 15;
	andlookup[ 80] =  0; orlookup[ 80] =  5;
	andlookup[ 81] =  1; orlookup[ 81] =  5;
	andlookup[ 82] =  0; orlookup[ 82] =  7;
	andlookup[ 83] =  1; orlookup[ 83] =  7;
	andlookup[ 84] =  4; orlookup[ 84] =  5;
	andlookup[ 85] =  5; orlookup[ 85] =  5;
	andlookup[ 86] =  4; orlookup[ 86] =  7;
	andlookup[ 87] =  5; orlookup[ 87] =  7;
	andlookup[ 88] =  0; orlookup[ 88] = 13;
	andlookup[ 89] =  1; orlookup[ 89] = 13;
	andlookup[ 90] =  0; orlookup[ 90] = 15;
	andlookup[ 91] =  1; orlookup[ 91] = 15;
	andlookup[ 92] =  4; orlookup[ 92] = 13;
	andlookup[ 93] =  5; orlookup[ 93] = 13;
	andlookup[ 94] =  4; orlookup[ 94] = 15;
	andlookup[ 95] =  5; orlookup[ 95] = 15;
	andlookup[ 96] =  0; orlookup[ 96] = 6;
	andlookup[ 97] =  0; orlookup[ 97] = 7;
	andlookup[ 98] =  2; orlookup[ 98] = 6;
	andlookup[ 99] =  2; orlookup[ 99] = 7;
	andlookup[100] =  4; orlookup[100] = 6;
	andlookup[101] =  4; orlookup[101] = 7;
	andlookup[102] =  6; orlookup[102] = 6;
	andlookup[103] =  6; orlookup[103] = 7;
	andlookup[104] =  0; orlookup[104] = 14;
	andlookup[105] =  0; orlookup[105] = 15;
	andlookup[106] =  2; orlookup[106] = 14;
	andlookup[107] =  2; orlookup[107] = 15;
	andlookup[108] =  4; orlookup[108] = 14;
	andlookup[109] =  4; orlookup[109] = 15;
	andlookup[110] =  6; orlookup[110] = 14;
	andlookup[111] =  6; orlookup[111] = 15;
	andlookup[112] =  0; orlookup[112] =  7;
	andlookup[113] =  1; orlookup[113] =  7;
	andlookup[114] =  2; orlookup[114] =  7;
	andlookup[115] =  3; orlookup[115] =  7;
	andlookup[116] =  4; orlookup[116] =  7;
	andlookup[117] =  5; orlookup[117] =  7;
	andlookup[118] =  6; orlookup[118] =  7;
	andlookup[119] =  7; orlookup[119] =  7;
	andlookup[120] =  0; orlookup[120] = 15;
	andlookup[121] =  1; orlookup[121] = 15;
	andlookup[122] =  2; orlookup[122] = 15;
	andlookup[123] =  3; orlookup[123] = 15;
	andlookup[124] =  4; orlookup[124] = 15;
	andlookup[125] =  5; orlookup[125] = 15;
	andlookup[126] =  6; orlookup[126] = 15;
	andlookup[127] =  7; orlookup[127] = 15;
	andlookup[128] =  0; orlookup[128] =  8;
	andlookup[129] =  0; orlookup[129] =  9;
	andlookup[130] =  0; orlookup[130] = 10;
	andlookup[131] =  0; orlookup[131] = 11;
	andlookup[132] =  0; orlookup[132] = 12;
	andlookup[133] =  0; orlookup[133] = 13;
	andlookup[134] =  0; orlookup[134] = 14;
	andlookup[135] =  0; orlookup[135] = 15;
	andlookup[136] =  8; orlookup[136] =  8;
	andlookup[137] =  8; orlookup[137] =  9;
	andlookup[138] =  8; orlookup[138] = 10;
	andlookup[139] =  8; orlookup[139] = 11;
	andlookup[140] =  8; orlookup[140] = 12;
	andlookup[141] =  8; orlookup[141] = 13;
	andlookup[142] =  8; orlookup[142] = 14;
	andlookup[143] =  8; orlookup[143] = 15;
	andlookup[144] =  0; orlookup[144] =  9;
	andlookup[145] =  1; orlookup[145] =  9;
	andlookup[146] =  0; orlookup[146] = 11;
	andlookup[147] =  1; orlookup[147] = 11;
	andlookup[148] =  0; orlookup[148] = 13;
	andlookup[149] =  1; orlookup[149] = 13;
	andlookup[150] =  0; orlookup[150] = 15;
	andlookup[151] =  1; orlookup[151] = 15;
	andlookup[152] =  8; orlookup[152] =  9;
	andlookup[153] =  9; orlookup[153] =  9;
	andlookup[154] =  8; orlookup[154] = 11;
	andlookup[155] =  9; orlookup[155] = 11;
	andlookup[156] =  8; orlookup[156] = 13;
	andlookup[157] =  9; orlookup[157] = 13;
	andlookup[158] =  8; orlookup[158] = 15;
	andlookup[159] =  9; orlookup[159] = 15;
	andlookup[160] =  0; orlookup[160] = 10;
	andlookup[161] =  0; orlookup[161] = 11;
	andlookup[162] =  2; orlookup[162] = 10;
	andlookup[163] =  2; orlookup[163] = 11;
	andlookup[164] =  0; orlookup[164] = 14;
	andlookup[165] =  0; orlookup[165] = 15;
	andlookup[166] =  2; orlookup[166] = 14;
	andlookup[167] =  2; orlookup[167] = 15;
	andlookup[168] =  8; orlookup[168] = 10;
	andlookup[169] =  8; orlookup[169] = 11;
	andlookup[170] = 10; orlookup[170] = 10;
	andlookup[171] = 10; orlookup[171] = 11;
	andlookup[172] =  8; orlookup[172] = 14;
	andlookup[173] =  8; orlookup[173] = 15;
	andlookup[174] = 10; orlookup[174] = 14;
	andlookup[175] = 10; orlookup[175] = 15;
	andlookup[176] =  0; orlookup[176] = 11;
	andlookup[177] =  1; orlookup[177] = 11;
	andlookup[178] =  2; orlookup[178] = 11;
	andlookup[179] =  3; orlookup[179] = 11;
	andlookup[180] =  0; orlookup[180] = 15;
	andlookup[181] =  1; orlookup[181] = 15;
	andlookup[182] =  2; orlookup[182] = 15;
	andlookup[183] =  3; orlookup[183] = 15;
	andlookup[184] =  8; orlookup[184] = 11;
	andlookup[185] =  9; orlookup[185] = 11;
	andlookup[186] = 10; orlookup[186] = 11;
	andlookup[187] = 11; orlookup[187] = 11;
	andlookup[188] =  8; orlookup[188] = 15;
	andlookup[189] =  9; orlookup[189] = 15;
	andlookup[190] = 10; orlookup[190] = 15;
	andlookup[191] = 11; orlookup[191] = 15;
	andlookup[192] =  0; orlookup[192] = 12;
	andlookup[193] =  0; orlookup[193] = 13;
	andlookup[194] =  0; orlookup[194] = 14;
	andlookup[195] =  0; orlookup[195] = 15;
	andlookup[196] =  4; orlookup[196] = 12;
	andlookup[197] =  4; orlookup[197] = 13;
	andlookup[198] =  4; orlookup[198] = 14;
	andlookup[199] =  4; orlookup[199] = 15;
	andlookup[200] =  8; orlookup[200] = 12;
	andlookup[201] =  8; orlookup[201] = 13;
	andlookup[202] =  8; orlookup[202] = 14;
	andlookup[203] =  8; orlookup[203] = 15;
	andlookup[204] = 12; orlookup[204] = 12;
	andlookup[205] = 12; orlookup[205] = 13;
	andlookup[206] = 12; orlookup[206] = 14;
	andlookup[207] = 12; orlookup[207] = 15;
	andlookup[208] =  0; orlookup[208] = 13;
	andlookup[209] =  1; orlookup[209] = 13;
	andlookup[210] =  0; orlookup[210] = 15;
	andlookup[211] =  1; orlookup[211] = 15;
	andlookup[212] =  4; orlookup[212] = 13;
	andlookup[213] =  5; orlookup[213] = 13;
	andlookup[214] =  4; orlookup[214] = 15;
	andlookup[215] =  5; orlookup[215] = 15;
	andlookup[216] =  8; orlookup[216] = 13;
	andlookup[217] =  9; orlookup[217] = 13;
	andlookup[218] =  8; orlookup[218] = 15;
	andlookup[219] =  9; orlookup[219] = 15;
	andlookup[220] = 12; orlookup[220] = 13;
	andlookup[221] = 13; orlookup[221] = 13;
	andlookup[222] = 12; orlookup[222] = 15;
	andlookup[223] = 13; orlookup[223] = 15;
	andlookup[224] =  0; orlookup[224] = 14;
	andlookup[225] =  0; orlookup[225] = 15;
	andlookup[226] =  2; orlookup[226] = 14;
	andlookup[227] =  2; orlookup[227] = 15;
	andlookup[228] =  4; orlookup[228] = 14;
	andlookup[229] =  4; orlookup[229] = 15;
	andlookup[230] =  6; orlookup[230] = 14;
	andlookup[231] =  6; orlookup[231] = 15;
	andlookup[232] =  8; orlookup[232] = 14;
	andlookup[233] =  8; orlookup[233] = 15;
	andlookup[234] = 10; orlookup[234] = 14;
	andlookup[235] = 10; orlookup[235] = 15;
	andlookup[236] = 12; orlookup[236] = 14;
	andlookup[237] = 12; orlookup[237] = 15;
	andlookup[238] = 14; orlookup[238] = 14;
	andlookup[239] = 14; orlookup[239] = 15;
	andlookup[240] =  0; orlookup[240] = 15;
	andlookup[241] =  1; orlookup[241] = 15;
	andlookup[242] =  2; orlookup[242] = 15;
	andlookup[243] =  3; orlookup[243] = 15;
	andlookup[244] =  4; orlookup[244] = 15;
	andlookup[245] =  5; orlookup[245] = 15;
	andlookup[246] =  6; orlookup[246] = 15;
	andlookup[247] =  7; orlookup[247] = 15;
	andlookup[248] =  8; orlookup[248] = 15;
	andlookup[249] =  9; orlookup[249] = 15;
	andlookup[250] = 10; orlookup[250] = 15;
	andlookup[251] = 11; orlookup[251] = 15;
	andlookup[252] = 12; orlookup[252] = 15;
	andlookup[253] = 13; orlookup[253] = 15;
	andlookup[254] = 14; orlookup[254] = 15;
	andlookup[255] = 15; orlookup[255] = 15;
}

# adapted from
# https://www.gnu.org/software/gawk/manual/html_node/Ordinal-Functions.html
function _ord_init(i) {
	for (i = 0; i < 256; i++)
		_ord_[sprintf("%c", i)] = i;
}

function ord(s) {
	# only first character is of interest
	return _ord_[substr(s, 1, 1)];
}
