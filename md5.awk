# NOTE: this script needs GNU awk, because it uses bitwise operators
# (i.e. xor(), compl() & al.).

BEGIN {
	_ord_init();
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
	     nbytes, chars, i, bytes, words, nwords, hi, lo, state, a,
	     b, c, d, j, x, digest, ret) {
	# convert the input into an array of bytes using ord() on each char.
	nbytes = split(input, chars, "");
	for (i = 1; i <= nbytes; i++)
		bytes[i] = ord(chars[i]);
	# convert the array of bytes into an array of 32 bits words.
	# NOTE: words is 0-indexed.
	for (i = 1; i <= nbytes; i += 4) {
		hi = or(lshift(bytes[i + 3], 8), bytes[i + 2]);
		lo = or(lshift(bytes[i + 1], 8), bytes[i + 0]);
		words[nwords++] = or(lshift(hi, 16), lo);
	}
	# Step 1. Append Padding Bits
	if (nbytes % 4 == 0) {
		# the input size is congruent modulo 32, we need a new word to
		# store the first '1' padding bit.
		words[nwords++] = 128; # 0x80
	} else {
		# append a '1' bit in the bytes just after the last input byte.
		words[nwords - 1] = or(words[nwords - 1], lshift(128, (nbytes % 4) * 8));
	}
	# fill the remaining bytes with 0 until we're just shy two words of
	# having 16-Word Blocks.
	while ((nwords % 16) != 14)
		words[nwords++] = 0;
	# Step 2. Append Length
	hi = rshift(nbytes * 8, 32);
	lo = (nbytes * 8) - lshift(hi, 32);
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
		digest[j] = and(state[i], 255); # 0xff
		digest[j+1] = and(rshift(state[i],  8), 255);
		digest[j+2] = and(rshift(state[i], 16), 255);
		digest[j+3] = and(rshift(state[i++], 24), 255);
	}
	for (i = 0; i < 16; i++)
		ret = sprintf("%s%02x", ret, digest[i]);
	return ret;
}

function F(x, y, z) {
	return or(and(x, y), and(not(x), z));
}
function G(x, y, z) {
	return or(and(x, z), and(y, not(z)));
}
function H(x, y, z) {
	return xor(x, xor(y, z));
}
function I(x, y, z) {
	return xor(y, or(x, not(z)));
}

function ROTATE_LEFT(x, n) {
	return or(mod32(lshift(x, n)), rshift(x, 32 - n));
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
	return and(x, 4294967295); # 0xffffffff
}

function not(x) {
	return mod32(compl(x));
}

function _md5_init()
{
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

# from https://www.gnu.org/software/gawk/manual/html_node/Ordinal-Functions.html
function _ord_init(i)
{
	for (i = 0; i < 256; i++)
		_ord_[sprintf("%c", i)] = i;
}

function ord(s)
{
	# only first character is of interest
	return _ord_[substr(s, 1, 1)];
}
