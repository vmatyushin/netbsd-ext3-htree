#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/vnode.h>

#include <ufs/ufs/dir.h>
#include <ufs/ufs/ufs_extern.h>

#include <ufs/ext2fs/ext2fs_extern.h>
#include <ufs/ext2fs/ext2fs_dinode.h>
#include <ufs/ext2fs/ext2fs_dir.h>
#include <ufs/ext2fs/ext2fs_htree.h>

/* MD4 functions */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define FF(a, b, c, d, x, s) { \
	(a) += F ((b), (c), (d)) + (x); \
	(a) = ROTATE_LEFT ((a), (s)); \
}

#define GG(a, b, c, d, x, s) { \
	(a) += G ((b), (c), (d)) + (x) + (uint32_t) 0x5A827999UL; \
	(a) = ROTATE_LEFT ((a), (s)); \
}

#define HH(a, b, c, d, x, s) { \
	(a) += H ((b), (c), (d)) + (x) + (uint32_t) 0x6ED9EBA1UL; \
	(a) = ROTATE_LEFT ((a), (s)); \
}

static void
ext2fs_half_md4(uint32_t hash[4], uint32_t data[8])
{
	uint32_t a = hash[0], b = hash[1], c = hash[2], d = hash[3];

	/* Round 1 */
	FF(a, b, c, d, data[0],  3);
	FF(d, a, b, c, data[1],  7);
	FF(c, d, a, b, data[2], 11);
	FF(b, c, d, a, data[3], 19);
	FF(a, b, c, d, data[4],  3);
	FF(d, a, b, c, data[5],  7);
	FF(c, d, a, b, data[6], 11);
	FF(b, c, d, a, data[7], 19);

	/* Round 2 */
	GG(a, b, c, d, data[1],  3);
	GG(d, a, b, c, data[3],  5);
	GG(c, d, a, b, data[5],  9);
	GG(b, c, d, a, data[7], 13);
	GG(a, b, c, d, data[0],  3);
	GG(d, a, b, c, data[2],  5);
	GG(c, d, a, b, data[4],  9);
	GG(b, c, d, a, data[6], 13);

	/* Round 3 */
	HH(a, b, c, d, data[3],  3);
	HH(d, a, b, c, data[7],  9);
	HH(c, d, a, b, data[2], 11);
	HH(b, c, d, a, data[6], 15);
	HH(a, b, c, d, data[1],  3);
	HH(d, a, b, c, data[5],  9);
	HH(c, d, a, b, data[0], 11);
	HH(b, c, d, a, data[4], 15);

	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
}

static void
ext2fs_tea(uint32_t hash[4], uint32_t data[4])
{
	int n = 16;
	int i = 1;
	uint32_t sum = 0;
	uint32_t tea_delta = 0x9E3779B9;
	uint32_t h0 = hash[0], h1 = hash[1];

	while (n > 0) {
		sum = i * tea_delta;
		h0 += ((h1<<4)+data[0]) ^ (h1+sum) ^ ((h1>>5)+data[1]);
		h1 += ((h0<<4)+data[2]) ^ (h0+sum) ^ ((h0>>5)+data[3]);
		n--;
		i++;
	}

	hash[0] += h0;
	hash[1] += h1;
}

static uint32_t
ext2fs_legacy_hash(const char *name, int len, int unsigned_char)
{
	uint32_t h0, h1 = 0x12A3FE2D, h2 = 0x37ABE8F9;
	uint32_t mult = 0x6D22F5;
	const unsigned char *u_name = (const unsigned char *) name;
	const signed char *s_name = (const signed char *) name;
	int val, i;
	
	for (i = 0; i < len; i++) {
		if (unsigned_char)
			val = (int) *u_name++;
		else
			val = (int) *s_name++;
		
		h0 = h2 + (h1 ^ (val * mult));
		if (h0 & 0x80000000)
			h0 -= 0x7FFFFFFF;
		h2 = h1;
		h1 = h0;
	}
	
	h1 <<= 1;
	return (h1);
}

static void
ext2fs_prep_hashbuf(const char *src, int slen,
		    uint32_t *dst, int dlen,
		    int unsigned_char)
{
	uint32_t padding = slen | (slen << 8) | (slen << 16) | (slen << 24);
	uint32_t buf_val;
	int len, k;
	int buf_byte;
	const unsigned char *u_buf = (const unsigned char *) src;
	const signed char *s_buf = (const signed char *) src;

	if (slen > dlen)
		len = dlen;
	else
		len = slen;

	buf_val = padding;

	for (k = 0; k < len; k++) {
		if (unsigned_char)
			buf_byte = (int) u_buf[k];
		else
			buf_byte = (int) s_buf[k];

		if ((k % 4) == 0)
			buf_val = padding;

		buf_val <<= 8;
		buf_val += buf_byte;

		if ((k % 4) == 3) {
			*dst++ = buf_val;
			dlen -= sizeof(uint32_t);
			buf_val = padding;
		}
	}

	dlen -= sizeof(uint32_t);
	if (dlen >= 0)
		*dst++ = buf_val;

	dlen -= sizeof(uint32_t);
	while (dlen >= 0) {
		*dst++ = padding;
		dlen -= sizeof(uint32_t);
	}
}

int
ext2fs_htree_hash(const char *name, int len,
		  uint32_t *hash_seed, int hash_version,
		  uint32_t *hash_major, uint32_t *hash_minor)
{
	uint32_t hash_buf[4];
	uint32_t data[8];
	uint32_t major = 0, minor = 0;
	int unsigned_char = 0;

	if ((!name) || (!hash_major))
		return (-1);
	
	if ((len < 1) || (len > 255))
		goto hash_error;

	hash_buf[0] = 0x67452301;
	hash_buf[1] = 0xEFCDAB89;
	hash_buf[2] = 0x98BADCFE;
	hash_buf[3] = 0x10325476;

	if (hash_seed)
		memcpy(hash_buf, hash_seed, sizeof(hash_buf));

	switch (hash_version) {
	case EXT2_HTREE_TEA_UNSIGNED:
		unsigned_char = 1;
	case EXT2_HTREE_TEA:
		while (len > 0) {
			ext2fs_prep_hashbuf(name, len, data, 16, unsigned_char);
			ext2fs_tea(hash_buf, data);
			len -= 16;
			name += 16;
		}
		major = hash_buf[0];
		minor = hash_buf[1];
		break;
	case EXT2_HTREE_LEGACY_UNSIGNED:
		unsigned_char = 1;
	case EXT2_HTREE_LEGACY:
		major = ext2fs_legacy_hash(name, len, unsigned_char);
		break;
	case EXT2_HTREE_HALF_MD4_UNSIGNED:
		unsigned_char = 1;
	case EXT2_HTREE_HALF_MD4:
		while (len > 0) {
			ext2fs_prep_hashbuf(name, len, data, 32, unsigned_char);
			ext2fs_half_md4(hash_buf, data);
			len -= 32;
			name += 32;
		}
		major = hash_buf[1];
		minor = hash_buf[2];
		break;
	default:
		goto hash_error;
	}

	major &= ~1;
	if (major == (EXT2_HTREE_EOF << 1))
		major = (EXT2_HTREE_EOF - 1) << 1;
	*hash_major = major;
	if (hash_minor)
		*hash_minor = minor;

	return (0);

hash_error:
	*hash_major = 0;
	if (hash_minor)
		*hash_minor = 0;
	return (-1);
}
