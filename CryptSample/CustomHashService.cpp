#include "CustomHashService.h"

CustomHashService::CustomHashService() {

}

VOID NTAPI CustomHashService::MD5Init(MD5_CTX* ctx)
{
	ctx->buf[0] = 0x67452301;
	ctx->buf[1] = 0xefcdab89;
	ctx->buf[2] = 0x98badcfe;
	ctx->buf[3] = 0x10325476;

	ctx->i[0] = ctx->i[1] = 0;
}

VOID NTAPI CustomHashService::MD5Update(MD5_CTX* ctx, const unsigned char* buf, unsigned int len)
{
	register unsigned int t;

	/* Update bitcount */
	t = ctx->i[0];

	if ((ctx->i[0] = t + (len << 3)) < t)
		ctx->i[1]++;        /* Carry from low to high */

	ctx->i[1] += len >> 29;
	t = (t >> 3) & 0x3f;

	/* Handle any leading odd-sized chunks */
	if (t)
	{
		unsigned char* p = (unsigned char*)ctx->in + t;
		t = 64 - t;

		if (len < t)
		{
			memcpy(p, buf, len);
			return;
		}

		memcpy(p, buf, t);
		byteReverse(ctx->in, 16);

		MD5Transform(ctx->buf, (unsigned int*)ctx->in);

		buf += t;
		len -= t;
	}

	/* Process data in 64-byte chunks */
	while (len >= 64)
	{
		memcpy(ctx->in, buf, 64);
		byteReverse(ctx->in, 16);

		MD5Transform(ctx->buf, (unsigned int*)ctx->in);

		buf += 64;
		len -= 64;
	}

	/* Handle any remaining bytes of data. */
	memcpy(ctx->in, buf, len);
}

VOID NTAPI CustomHashService::MD5Final(MD5_CTX* ctx)
{
	unsigned int count;
	unsigned char* p;

	/* Compute number of bytes mod 64 */
	count = (ctx->i[0] >> 3) & 0x3F;

	/* Set the first char of padding to 0x80.  This is safe since there is
	   always at least one byte free */
	p = ctx->in + count;
	*p++ = 0x80;

	/* Bytes of padding needed to make 64 bytes */
	count = 64 - 1 - count;

	/* Pad out to 56 mod 64 */
	if (count < 8)
	{
		/* Two lots of padding:  Pad the first block to 64 bytes */
		memset(p, 0, count);
		byteReverse(ctx->in, 16);
		MD5Transform(ctx->buf, (unsigned int*)ctx->in);

		/* Now fill the next block with 56 bytes */
		memset(ctx->in, 0, 56);
	}
	else
	{
		/* Pad block to 56 bytes */
		memset(p, 0, count - 8);
	}

	byteReverse(ctx->in, 14);

	/* Append length in bits and transform */
	((unsigned int*)ctx->in)[14] = ctx->i[0];
	((unsigned int*)ctx->in)[15] = ctx->i[1];

	MD5Transform(ctx->buf, (unsigned int*)ctx->in);
	byteReverse((unsigned char*)ctx->buf, 4);
	memcpy(ctx->digest, ctx->buf, 16);
	memset(ctx->in, 0, sizeof(ctx->in));
}