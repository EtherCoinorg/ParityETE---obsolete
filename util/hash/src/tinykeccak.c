#include <stdint.h>
#include <string.h>

/** libkeccak-tiny
 *
 * A single-file implementation of SHA-3 and SHAKE.
 *
 * Implementor: David Leon Gil
 * License: CC0, attribution kindly requested. Blame taken too,
 * but not liability.
 */

#define decshake(bits) \
  int shake##bits(uint8_t*, size_t, const uint8_t*, size_t);

#define deckeccak(bits) \
  int keccak_##bits(uint8_t*, size_t, const uint8_t*, size_t);

decshake(128)
decshake(256)
deckeccak(224)
deckeccak(256)
deckeccak(384)
deckeccak(512)

/******** The Keccak-f[1600] permutation ********/

/*** Constants. ***/
static const uint8_t rho[24] = \
  { 1,  3,   6, 10, 15, 21,
	28, 36, 45, 55,  2, 14,
	27, 41, 56,  8, 25, 43,
	62, 18, 39, 61, 20, 44};
static const uint8_t pi[24] = \
  {10,  7, 11, 17, 18, 3,
	5, 16,  8, 21, 24, 4,
   15, 23, 19, 13, 12, 2,
   20, 14, 22,  9, 6,  1};
static const uint64_t RC[24] = \
  {1ULL, 0x8082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
   0x808bULL, 0x80000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
   0x8aULL, 0x88ULL, 0x80008009ULL, 0x8000000aULL,
   0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
   0x8000000000008002ULL, 0x8000000000000080ULL, 0x800aULL, 0x800000008000000aULL,
   0x8000000080008081ULL, 0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL};

/*** Helper macros to unroll the permutation. ***/
#define rol(x, s) (((x) << s) | ((x) >> (64 - s)))
#define REPEAT6(e) e e e e e e
#define REPEAT24(e) REPEAT6(e e e e)
#define REPEAT5(e) e e e e e
#define FOR5(v, s, e) \
  v = 0;            \
  REPEAT5(e; v += s;)

/*** Keccak-f[1600] ***/
static inline void keccakf(void* state) {
  uint64_t* a = (uint64_t*)state;
  uint64_t b[5] = {0};
  uint64_t t = 0;
  uint8_t x, y;
  int i;

  for (i = 0; i < 24; i++) {
	// Theta
	FOR5(x, 1,
		 b[x] = 0;
		 FOR5(y, 5,
			  b[x] ^= a[x + y]; ))
	FOR5(x, 1,
		 FOR5(y, 5,
			  a[y + x] ^= b[(x + 4) % 5] ^ rol(b[(x + 1) % 5], 1); ))
	// Rho and pi
	t = a[1];
	x = 0;
	REPEAT24(b[0] = a[pi[x]];
			 a[pi[x]] = rol(t, rho[x]);
			 t = b[0];
			 x++; )
	// Chi
	FOR5(y,
	   5,
	   FOR5(x, 1,
			b[x] = a[y + x];)
	   FOR5(x, 1,
			a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]); ))
	// Iota
	a[0] ^= RC[i];
  }
}

/******** The FIPS202-defined functions. ********/

/*** Some helper macros. ***/

#define _(S) do { S } while (0)
#define FOR(i, ST, L, S) \
  _({size_t i; for (i = 0; i < L; i += ST) { S; }})
#define mkapply_ds(NAME, S)                                          \
  static inline void NAME(uint8_t* dst,                              \
						  const uint8_t* src,                        \
						  size_t len) {                              \
	FOR(i, 1, len, S);                                               \
  }
#define mkapply_sd(NAME, S)                                          \
  static inline void NAME(const uint8_t* src,                        \
						  uint8_t* dst,                              \
						  size_t len) {                              \
	FOR(i, 1, len, S);                                               \
  }

mkapply_ds(xorin, dst[i] ^= src[i])  // xorin
mkapply_sd(setout, dst[i] = src[i])  // setout

#define P keccakf
#define Plen 200

// Fold P*F over the full blocks of an input.
#define foldP(I, L, F) \
  while (L >= rate) {  \
	F(a, I, rate);     \
	P(a);              \
	I += rate;         \
	L -= rate;         \
  }

/** The sponge-based hash construction. **/
static inline int hash(uint8_t* out, size_t outlen,
					   const uint8_t* in, size_t inlen,
					   size_t rate, uint8_t delim) {
  if ((out == NULL) || ((in == NULL) && inlen != 0) || (rate >= Plen)) {
	return -1;
  }
  uint8_t a[Plen] = {0};
  // Absorb input.
  foldP(in, inlen, xorin);
  // Xor in the DS and pad frame.
  a[inlen] ^= delim;
  a[rate - 1] ^= 0x80;
  // Xor in the last block.
  xorin(a, in, inlen);
  // Apply P
  P(a);
  // Squeeze output.
  foldP(out, outlen, setout);
  setout(a, out, outlen);
  memset(a, 0, 200);
  return 0;
}

/*** Helper macros to define SHA3 and SHAKE instances. ***/
#define defshake(bits)                                            \
  int shake##bits(uint8_t* out, size_t outlen,                    \
				  const uint8_t* in, size_t inlen) {              \
	return hash(out, outlen, in, inlen, 200 - (bits / 4), 0x1f);  \
  }
#define defkeccak(bits)                                             \
  int keccak_##bits(uint8_t* out, size_t outlen,                    \
				  const uint8_t* in, size_t inlen) {              \
	if (outlen > (bits/8)) {                                      \
	  return -1;                                                  \
	}                                                             \
	return hash(out, outlen, in, inlen, 200 - (bits / 4), 0x01);  \
  }

/*** FIPS202 SHAKE VOFs ***/
defshake(128)
defshake(256)

/*** FIPS202 SHA3 FOFs ***/
defkeccak(224)
defkeccak(256)
defkeccak(384)
defkeccak(512)

/* ------------------------- progpow.c ------------------------- */
typedef int bool;

#define ETHASH_REVISION (23)
#define ETHASH_DATASET_BYTES_INIT (1073741824U) // 2**30
#define ETHASH_DATASET_BYTES_GROWTH 8388608U  // 2**23
#define ETHASH_CACHE_BYTES_INIT (1073741824U) // 2**24
#define ETHASH_CACHE_BYTES_GROWTH 131072U  // 2**17
#define ETHASH_EPOCH_LENGTH 30000U
#define ETHASH_MIX_BYTES 128
#define ETHASH_HASH_BYTES 64
#define ETHASH_DATASET_PARENTS 256
#define ETHASH_CACHE_ROUNDS 3
#define ETHASH_ACCESSES 64

// compile time settings
#define NODE_WORDS (64/4)
#define MIX_WORDS (ETHASH_MIX_BYTES/4)
#define MIX_NODES (MIX_WORDS / NODE_WORDS)

typedef union node {
	uint8_t bytes[NODE_WORDS * 4];
	uint32_t words[NODE_WORDS];
	uint64_t double_words[NODE_WORDS / 2];
} node;

typedef struct {
	void* cache;
	uint64_t cache_size;
	uint64_t block_number;
} ethash_light;

typedef struct ethash_light* ethash_light_t;

typedef union
{
    uint64_t words[4];
    uint32_t hwords[8];
    uint8_t bytes[32];
}ethash_hash256;

static 
uint32_t bswap32(uint32_t s)
{
    return ((s&0xff) <<24 | (s&0xff00) <<8 | (s&0xff0000) >> 8 |
            (s&0xff000000) >> 24);
}

/****************keccakf800***************************/
 /* Implementation based on:
        https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
        converted from 64->32 bit words*/
const uint32_t prog_keccakf_rndc[24] = {
        0x00000001, 0x00008082, 0x0000808a, 0x80008000, 0x0000808b, 0x80000001,
        0x80008081, 0x00008009, 0x0000008a, 0x00000088, 0x80008009, 0x8000000a,
        0x8000808b, 0x0000008b, 0x00008089, 0x00008003, 0x00008002, 0x00000080,
        0x0000800a, 0x8000000a, 0x80008081, 0x00008080, 0x80000001, 0x80008008
};

#define ROTL(x,n,w) (((x) << (n)) | ((x) >> ((w) - (n))))
#define ROTL32(x,n) ROTL(x,n,32)        /* 32 bits word */

void keccak_f800_round(uint32_t st[25], const int r)
{
    const uint32_t keccakf_rotc[24] = {
        1,  3,  6,  10, 15, 21, 28, 4, 13, 23, 2,  14,
        27, 9, 24, 8,  25, 11, 30, 18, 7, 29, 20, 12 
    };

        const uint32_t keccakf_piln[24] = {
                10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
                15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
        };

        uint32_t t, bc[5];
        /* Theta*/
        uint32_t i = 0, j = 0;
        for (i = 0; i < 5; i++)
                bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

        i = 0;
        for (i = 0; i < 5; i++) {
                t = bc[(i + 4) % 5] ^ ROTL32(bc[(i + 1) % 5], 1);
                j = 0;
                for (j = 0; j < 25; j += 5)
                        st[j + i] ^= t;
        }

        /*Rho Pi*/
        i = 0;
        t = st[1];
        for (i = 0; i < 24; i++) {
                uint32_t jj = keccakf_piln[i];
                bc[0] = st[jj];
                st[jj] = ROTL32(t, keccakf_rotc[i]);
                t = bc[0];
        }

        /* Chi*/
        j = 0;
        for (j = 0; j < 25; j += 5) {
                i = 0;
                for (i = 0; i < 5; i++)
                        bc[i] = st[j + i];
                i = 0;
                for (i = 0; i < 5; i++)
                        st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        /* Iota*/
        st[0] ^= prog_keccakf_rndc[r];
}

static
uint64_t keccak_f800(const ethash_hash256* header, const uint64_t seed,
 const uint32_t *result)
{
    uint32_t st[25];

    for (int i = 0; i < 25; i++)
        st[i] = 0;
    for (int i = 0; i < 8; i++)
        st[i] = header->hwords[i];
    st[8] = (uint32_t)seed;
    st[9] = (uint32_t)(seed >> 32);
    st[10] = result[0];
    st[11] = result[1];
    st[12] = result[2];
    st[13] = result[3];

    for (int r = 0; r < 21; r++) {
        keccak_f800_round(st, r);
    }
    // last round can be simplified due to partial output
    keccak_f800_round(st, 21);

    return (uint64_t)st[0] << 32 | st[1];//should be return (uint64_t)st[0] << 32 | st[1];
}

static
void keccak_f800_arr(uint32_t* out, const ethash_hash256* header,
 const uint64_t seed, const uint32_t *result)
{
    uint32_t st[25];

    for (int i = 0; i < 25; i++)
        st[i] = 0;
    for (int i = 0; i < 8; i++)
        st[i] = header->hwords[i];
    st[8] = (uint32_t)seed;
    st[9] = (uint32_t)(seed >> 32);
    st[10] = result[0];
    st[11] = result[1];
    st[12] = result[2];
    st[13] = result[3];

    for (int r = 0; r < 21; r++) {
        keccak_f800_round(st, r);
    }
    // last round can be simplified due to partial output
    keccak_f800_round(st, 21);

    for (int i = 0; i < 8; ++i)
        out[i] = st[i];
}

/*********************keccak*******************/
#define to_le64(X) X
/** Loads 64-bit integer from given memory location as little-endian number. */
static inline uint64_t load_le(const uint8_t* data)
{
    /* memcpy is the best way of expressing the intention. Every compiler will
       optimize is to single load instruction if the target architecture
       supports unaligned memory access (GCC and clang even in O0).
       This is great trick because we are violating C/C++ memory alignment
       restrictions with no performance penalty. */
    uint64_t word;
    memcpy(&word, data, sizeof(word));
    return to_le64(word);
}

typedef union 
{
    uint64_t words[4];
    uint32_t hwords[8];
    uint8_t bytes[32];
} hash256;

typedef union 
{
    uint64_t words[8];
    uint32_t half_words[16];
    uint8_t bytes[64];
} hash512;

typedef union 
{
        hash512 hashes[4];
        uint64_t words[32];
        uint32_t hwords[64];
        uint8_t bytes[256];
} hash2048;

// progpow implementation
typedef struct 
{
    int epoch_number;
    int light_cache_num_items;
    hash512* light_cache;
    int full_dataset_num_items;
} epoch_context;


typedef struct {
	uint32_t z, w, jsr, jcong;
} kiss99_t;

#define ETHASH_NUM_DATASET_ACCESSES 64
#define full_dataset_item_parents 256
#define PROGPOW_LANES			32
#define PROGPOW_REGS			16
#define PROGPOW_CACHE_BYTES             (16*1024)
#define PROGPOW_CNT_MEM                 ETHASH_NUM_DATASET_ACCESSES
#define PROGPOW_CNT_CACHE               8
#define PROGPOW_CNT_MATH		8
#define PROGPOW_CACHE_WORDS  (PROGPOW_CACHE_BYTES / sizeof(uint32_t))
#define PROGPOW_EPOCH_START (531)

#define ROTL(x,n,w) (((x) << (n)) | ((x) >> ((w) - (n))))
#define ROTL32(x,n) ROTL(x,n,32)        /* 32 bits word */

#define ROTR(x,n,w) (((x) >> (n)) | ((x) << ((w) - (n))))
#define ROTR32(x,n) ROTR(x,n,32)        /* 32 bits word */

static hash2048* fix_endianness32(hash2048 *h) { return h;}
static uint32_t fix_endianness(uint32_t h) { return h;}

// Helper to get the next value in the per-program random sequence
#define rnd()    (kiss99(&prog_rnd))
// Helper to pick a random mix location
#define mix_src() (rnd() % PROGPOW_REGS)
// Helper to access the sequence of mix destinations
#define mix_dst() (mix_seq[(mix_seq_cnt++)%PROGPOW_REGS])

#define min_(a,b) ((a<b) ? a : b)

typedef struct ethash_h256 { uint8_t b[32]; } ethash_h256_t;

typedef struct ethash_return_value {
	ethash_h256_t result;
	ethash_h256_t mix_hash;
	bool success;
} ethash_return_value_t;

//#define mul_hi(a, b) __umulhi(a, b)
uint32_t mul_hi (uint32_t a, uint32_t b){
    uint64_t result = (uint64_t) a * (uint64_t) b;
    return  (uint32_t) (result>>32);
}
//#define clz(a) __clz(a)
uint32_t clz (uint32_t a){
    uint32_t result = 0;
    for(int i=31;i>=0;i--){
        if(((a>>i)&1) == 0)
            result ++;
        else
            break;
    }
    return result;
}
//#define popcount(a) __popc(a)
uint32_t popcount(uint32_t a) {
        uint32_t result = 0;
        for (int i = 31; i >= 0; i--) {
                if (((a >> i) & 1) == 1)
                        result++;
        }
        return result;
}

// KISS99 is simple, fast, and passes the TestU01 suite
// https://en.wikipedia.org/wiki/KISS_(algorithm)
// http://www.cse.yorku.ca/~oz/marsaglia-rng.html
uint32_t kiss99(kiss99_t * st)
{
    uint32_t znew = (st->z = 36969 * (st->z & 65535) + (st->z >> 16));
    uint32_t wnew = (st->w = 18000 * (st->w & 65535) + (st->w >> 16));
    uint32_t MWC = ((znew << 16) + wnew);
    uint32_t SHR3 = (st->jsr ^= (st->jsr << 17), st->jsr ^= (st->jsr >> 13), st->jsr ^= (st->jsr << 5));
    uint32_t CONG = (st->jcong = 69069 * st->jcong + 1234567);
    return ((MWC^CONG) + SHR3);
}

uint32_t fnv1a(uint32_t *h, uint32_t d)
{
  return *h = (*h ^ d) * 0x1000193;
}

#define FNV_PRIME 0x01000193

static uint32_t fnv_hash(uint32_t const x, uint32_t const y)
{
	return x * FNV_PRIME ^ y;
}
#define fnv(a,b) fnv_hash(a,b)

void fill_mix(
	uint64_t seed,
	uint32_t lane_id,
	uint32_t mix[PROGPOW_REGS]
)
{
    // Use FNV to expand the per-warp seed to per-lane
    // Use KISS to expand the per-lane seed to fill mix
    uint32_t fnv_hash = 0x811c9dc5;
    kiss99_t st;
	  st.z = fnv1a(&fnv_hash, (uint32_t)seed);
	  st.w = fnv1a(&fnv_hash, (uint32_t)(seed >> 32));
    st.jsr = fnv1a(&fnv_hash, lane_id);
    st.jcong = fnv1a(&fnv_hash, lane_id);
    for (int i = 0; i < PROGPOW_REGS; i++)
        mix[i] = kiss99(&st);
}

void swap(uint32_t *a, uint32_t *b)
{
	uint32_t t = *a;
	*a = *b;
	*b = t;
}

// Merge new data from b into the value in a
// Assuming A has high entropy only do ops that retain entropy
// even if B is low entropy
// (IE don't do A&B)
void merge(uint32_t *a, uint32_t b, uint32_t r)
{
	switch (r % 4)
	{
	case 0: *a = (*a * 33) + b; break;
	case 1: *a = (*a ^ b) * 33; break;
	case 2: *a = ROTL32(*a, ((r >> 16) % 32)) ^ b; break;
	case 3: *a = ROTR32(*a, ((r >> 16) % 32)) ^ b; break;
	}
}

// Random math between two input values
uint32_t math(uint32_t a, uint32_t b, uint32_t r)
{       
	switch (r % 11)
	{
	case 0: return a + b; break;
	case 1: return a * b; break;
	case 2: return mul_hi(a, b); break;
	case 3: return min_(a, b); break;
	case 4: return ROTL32(a, b); break;
	case 5: return ROTR32(a, b); break;
	case 6: return a & b; break;
	case 7: return a | b; break;
	case 8: return a ^ b; break;
	case 9: return clz(a) + clz(b); break;
	case 10: return popcount(a) + popcount(b); break;
	default: return 0;
	}
	return 0;
}

static 
void keccak512_64(const uint8_t data[64])
{
    keccak_512(data, 64, data, 64);
}

static void fnv_512(hash512* u, const hash512* v)
{
    for (size_t i = 0; i < sizeof(*u) / sizeof(u->half_words[0]); ++i)
        u->half_words[i] = fnv(u->half_words[i], v->half_words[i]);
}
/// Calculates just 512bit dataset item
static void
calculate_dag_item(hash512* mix0, const epoch_context* context, int64_t index) 
{
    const hash512* const cache = context->light_cache;

    static const size_t num_half_words = sizeof(hash512) / sizeof(uint32_t);
    const int64_t num_cache_items = context->light_cache_num_items;

    uint32_t idx32 = (uint32_t)(index);

    memcpy(mix0, &cache[index % num_cache_items], 64);

    mix0->half_words[0] ^= fix_endianness(idx32);

    // Hash and convert to little-endian 32-bit words.
    keccak512_64(mix0->bytes);

    for (uint32_t j = 0; j < full_dataset_item_parents; ++j)
    {
        uint32_t t0 = fnv(idx32 ^ j, mix0->half_words[j % num_half_words]);
        int64_t parent_index0 = t0 % num_cache_items;
        fnv_512(mix0, &cache[parent_index0]);
    }

    // Covert 32-bit words back to bytes and hash.
    keccak512_64(mix0->bytes);
}


static hash2048* 
calculate_dataset_item_progpow(hash2048* r, const epoch_context* context,
 uint32_t index)
{

  hash512 n1,n2;
  calculate_dag_item( &n1, context, index*2);
  calculate_dag_item( &n2, context, index*2+1);
  memcpy(r->bytes, n1.bytes, 64);
  memcpy(r->bytes+64, n2.bytes, 64);
  return r;
}

/// Calculates a full l1 dataset item
///
/// This consist of one 32-bit items produced by calculate_dataset_item_partial().
static uint32_t calculate_L1dataset_item(const epoch_context* context, uint32_t index)
{
    uint32_t idx = index/2;
    hash2048 dag;
    calculate_dataset_item_progpow(&dag, context, (idx*2+101));
    uint64_t data = dag.words[0];
    uint32_t ret;
    ret = (uint32_t)((index%2)?(data>>32):(data));
    return ret;
}

void progPowInit(kiss99_t* prog_rnd, uint64_t prog_seed, uint32_t mix_seq[PROGPOW_REGS])
{
    //kiss99_t prog_rnd;
    uint32_t fnv_hash = 0x811c9dc5;
    prog_rnd->z = fnv1a(&fnv_hash, (uint32_t)prog_seed);
    prog_rnd->w = fnv1a(&fnv_hash, (uint32_t)(prog_seed >> 32));
    prog_rnd->jsr = fnv1a(&fnv_hash, (uint32_t)prog_seed);
    prog_rnd->jcong = fnv1a(&fnv_hash, (uint32_t)(prog_seed >> 32));
    // Create a random sequence of mix destinations for merge()
    // guaranteeing every location is touched once
    // Uses Fisher¨CYates shuffle
    for (uint32_t i = 0; i < PROGPOW_REGS; i++)
        mix_seq[i] = i;
    for (uint32_t i = PROGPOW_REGS - 1; i > 0; i--)
    {
        uint32_t j = kiss99(prog_rnd) % (i + 1);
        swap(&(mix_seq[i]), &(mix_seq[j]));
    }
}

typedef  hash2048* (*lookup_fn2)(hash2048 *, const epoch_context*, uint32_t);
typedef  uint32_t (*lookup_fn_l1)(const epoch_context*, uint32_t);

static void progPowLoop(
	const epoch_context* context,
    const uint64_t prog_seed,
    const uint32_t loop,
    uint32_t mix[PROGPOW_LANES][PROGPOW_REGS],
    lookup_fn2  g_lut,
    lookup_fn_l1 c_lut)
{
	// All lanes share a base address for the global load
    // Global offset uses mix[0] to guarantee it depends on the load result
    uint32_t offset_g = mix[loop%PROGPOW_LANES][0] % (uint32_t)context->full_dataset_num_items;
	
    hash2048 data256;
    fix_endianness32((hash2048*)g_lut(&data256, context, offset_g));

    // Lanes can execute in parallel and will be convergent
    for (uint32_t l = 0; l < PROGPOW_LANES; l++)
    {
        // global load to sequential locations
        uint64_t data64 = data256.words[l];

        // initialize the seed and mix destination sequence
        uint32_t mix_seq[PROGPOW_REGS];
        int mix_seq_cnt = 0;
        kiss99_t prog_rnd;
        progPowInit(&prog_rnd, prog_seed, mix_seq);

        uint32_t offset, data32;
        //int max_i = max(PROGPOW_CNT_CACHE, PROGPOW_CNT_MATH);
        uint32_t max_i;
        if (PROGPOW_CNT_CACHE > PROGPOW_CNT_MATH)
            max_i = PROGPOW_CNT_CACHE;
        else
            max_i = PROGPOW_CNT_MATH;
        for (uint32_t i = 0; i < max_i; i++)
        {
            if (i < PROGPOW_CNT_CACHE)
            {
                // Cached memory access
                // lanes access random location
                offset = mix[l][mix_src()] % (uint32_t)PROGPOW_CACHE_WORDS;
                data32 = fix_endianness(c_lut(context, offset));
                merge(&(mix[l][mix_dst()]), data32, rnd());
            }
            if (i < PROGPOW_CNT_MATH)
            {
                // Random Math
                data32 = math(mix[l][mix_src()], mix[l][mix_src()], rnd());
                merge(&(mix[l][mix_dst()]), data32, rnd());
            }
        }
        // Consume the global load data at the very end of the loop
        // Allows full latency hiding
        merge(&(mix[l][0]), (uint32_t)data64, rnd());
        merge(&(mix[l][mix_dst()]), (uint32_t)(data64 >> 32), rnd());
    }
}

static void
progpow_search(	ethash_return_value_t* ret,	
 const epoch_context* context, const uint64_t seed, lookup_fn2 g_lut, lookup_fn_l1 c_lut
    )
{
    uint32_t mix[PROGPOW_LANES][PROGPOW_REGS];
    hash256 result;
    for (int i = 0; i < 8; i++)
        result.hwords[i] = 0;

    // initialize mix for all lanes
    for (uint32_t l = 0; l < PROGPOW_LANES; l++)
        fill_mix(seed, l, mix[l]);

    // execute the randomly generated inner loop
    for (uint32_t i = 0; i < PROGPOW_CNT_MEM; i++)
    {
        progPowLoop(context, (uint64_t)context->epoch_number, i, mix, g_lut, c_lut);
    }

    // Reduce mix data to a single per-lane result
    uint32_t lane_hash[PROGPOW_LANES];
    for (int l = 0; l < PROGPOW_LANES; l++)
    {
        lane_hash[l] = 0x811c9dc5;
        for (int i = 0; i < PROGPOW_REGS; i++)
            fnv1a(&lane_hash[l], mix[l][i]);
    }
    // Reduce all lanes to a single 128-bit result
    for (int i = 0; i < 8; i++) {
        result.hwords[i] = 0x811c9dc5;
    }
    for (int l = 0; l < PROGPOW_LANES; l++) {
        fnv1a(&result.hwords[l % 8], lane_hash[l]);
    }

	memcpy(&ret->result, &result, sizeof(result));
}

bool progpow_hash(
       ethash_return_value_t* ret,
       const epoch_context *ctx,
       const ethash_hash256 *header_hash,
       uint64_t const nonce
)
{
    uint32_t result[4];
    for (int i = 0; i < 4; i++)
        result[i] = 0;
    uint64_t seed;
    seed = keccak_f800(header_hash, nonce, result);

    progpow_search(ret, ctx, seed, calculate_dataset_item_progpow, calculate_L1dataset_item);

    keccak_f800_arr((uint32_t*)&ret->result, header_hash, seed, (const uint32_t*)&ret->mix_hash);

    return 1;
}

static int is_prime(int number)
{
    int d;

    if (number <= 1)
        return 0;

    if (number % 2 == 0 && number > 2)
        return 0;

    /* Check factors up to sqrt(number).
       To avoid computing sqrt, compare d*d <= number with 64-bit precision. */
    for (d = 3; (int64_t)d * (int64_t)d <= (int64_t)number; d += 2)
    {
        if (number % d == 0)
            return 0;
    }

    return 1;
}

static
int ethash_find_largest_prime(int upper_bound)
{
    int n = upper_bound;

    if (n < 2)
        return 0;

    if (n == 2)
        return 2;

    /* If even number, skip it. */
    if (n % 2 == 0)
        --n;

    /* Test descending odd numbers. */
    while (!is_prime(n))
        n -= 2;

    return n;
}

/*
static
size_t get_light_cache_size(int num_items) 
{
    return (size_t)(num_items) * sizeof(hash512);
}
*/

static
int calculate_light_cache_num_items(int epoch_number) 
{
    int item_size = sizeof(hash512);
    int num_items_init = ETHASH_CACHE_BYTES_INIT / item_size;
    int num_items_growth = ETHASH_CACHE_BYTES_GROWTH / item_size;

    int num_items_upper_bound = num_items_init + epoch_number * num_items_growth;
    int num_items = ethash_find_largest_prime(num_items_upper_bound);
    return num_items;
}

static 
int calculate_full_dataset_num_items(int epoch_number) 
{
    int item_size = sizeof(hash2048);
    int num_items_init = ETHASH_DATASET_BYTES_INIT / item_size;
    int num_items_growth = ETHASH_DATASET_BYTES_GROWTH / item_size;

    int num_items_upper_bound = num_items_init + epoch_number * num_items_growth;
    int num_items = ethash_find_largest_prime(num_items_upper_bound);
    return num_items;
}


static void
set_epoch_context(int epoch_number, epoch_context* ctx, hash512* light_cache) 
{
    //size_t context_alloc_size = sizeof(hash512);

    int light_cache_num_items = calculate_light_cache_num_items(epoch_number);
    //size_t light_cache_size = get_light_cache_size(light_cache_num_items);
    //size_t alloc_size = context_alloc_size + light_cache_size;

    int full_dataset_num_items = calculate_full_dataset_num_items(epoch_number);
    
    ctx->epoch_number = epoch_number;
    ctx->light_cache_num_items = light_cache_num_items;
    ctx->light_cache = light_cache;
    ctx->full_dataset_num_items = full_dataset_num_items;
}

ethash_hash256* keccak256_arr(ethash_hash256* hash, const uint8_t* data, size_t size)
{
    keccak_256(hash->words, 32, data, size);
    return hash;
}

ethash_hash256* ethash_keccak256(ethash_hash256* hash, const ethash_hash256* header, const uint64_t seed, const uint32_t *result)
{
    keccak_f800_arr(hash->hwords, header, seed, result);
    return hash;
}

void verify_final_progpow_hash(ethash_hash256* final_hash,
                        const ethash_hash256* header_hash, 
                        const ethash_hash256* mix_hash, uint64_t nonce)
{
    uint32_t result[4]; 
    for (int i = 0; i < 4; i++)
        result[i] = 0;
    uint64_t seed = keccak_f800(header_hash, nonce, result);
    ethash_hash256 h;
    ethash_keccak256(&h, header_hash, seed, mix_hash->hwords);
    //XXX keccak_f800 using st[0] << 32 | st[1], st[0], st[1] are little endian,
    //here convert it back to big endian
    for(int i = 0; i < 8; i ++) 
        final_hash->hwords[i] = bswap32(h.hwords[i]);
}

/**************API********************************/
/**************************************************
 * header is 140 bytes with zerod nonce
 * mix is 32 bytes, nonce is 64 bytes
 * return with hash uint8_t array
 * hash is big endian, nonce is little endian.
***************************************************/
int 
get_block_progpow_hash_from_mix(uint8_t *header, uint8_t *mix,
 uint64_t nonce, uint8_t *out)
{
    memset(&header[108], 0, 32); 
    ethash_hash256 header_hash;
    keccak256_arr(&header_hash, header, 140);

    ethash_hash256 mix_hash;
    memcpy(mix_hash.bytes, mix, 32);

    ethash_hash256 final_hash;
    verify_final_progpow_hash(&final_hash, &header_hash, &mix_hash, nonce);   

    memcpy(out, final_hash.bytes, 32);
    return 0;
}

uint32_t g_total = 0;
hash512* g_light_cache = 0;
void create_light_cache(uint32_t index, uint8_t value[64]) 
{
    if ((index+1) > g_total) {
        if (g_total > 0) {
           free(g_light_cache); 
        }
        g_light_cache = malloc(64*(index+1));
        g_total = index+1;
        printf("alloc %d\n", g_total);
    }
    memcpy(g_light_cache+index, value, 64);
}

int32_t 
get_block_progpow_hash(uint32_t epoch, uint8_t header[64],
                       uint64_t nonce, uint8_t out[64])
{
    ethash_return_value_t r;
    epoch_context ctx;
    set_epoch_context(epoch, &ctx, (hash512*)g_light_cache);
    progpow_hash(&r, &ctx, (const ethash_hash256*)header, nonce);   

    memcpy(out, &r.result, 32);
    memcpy(out+32, &r.mix_hash, 32);
    return ctx.light_cache_num_items;
}


/****
[2018-06-30 09:59:54] GPU #0: start=31300181 end=315a9f6d range=002a9dec
[2018-06-30 09:59:54] GPU #0: Target 1881cffffff.
[2018-06-30 10:00:08] GPU #0: found count = 2,  buffer->count = 2
[2018-06-30 10:00:08] GPU #0: found result 0: nonces=313dfc18, mixes=5883f27cabc838b98e7cd660c5ee91e8b1882bd17f9e428b5aa6bc951d5a16f8
[2018-06-30 10:00:08] GPU #0: before verify, nonce = 313dfc18, header_hash =5d5378ed7576a89388fad85a628d1895483bf98bdb29b2fc9ad17db7263823f1, m_current_header=5d5378ed7576a89388fad85a628d1895483bf98bdb29b2fc9ad17db7263823f1, mix=5883f27cabc838b98e7cd660c5ee91e8b1882bd17f9e428b
[2018-06-30 10:00:08] GPU #0: calc_hash: 00000148b6715b3a32a7b36e5c820fcd4660acb72947ab9ebe4949134688066e

[2018-06-30 10:00:09] GPU #0: progpow hash results. final_hash 00000148b6715b3a32a7b36e5c820fcd4660acb72947ab9ebe4949134688066e, mix_hash 5883f27cabc838b98e7cd660c5ee91e8b1882bd17f9e428b5aa6bc951d5a16f8

[2018-06-30 10:00:09] GPU #0: verify_final_progpow passed!

[2018-06-30 10:00:10] GPU #0: verify passed!

yang@ubuntu:~/bitcoinnewyork_newfork/Bitcoinnyc/src$ ./btc2-cli -datadir=/data/bitcoin_data/ -debug=1 getblock 00000148b6715b3a32a7b36e5c820fcd4660acb72947ab9ebe4949134688066e 0
000000206812f2a87241851756cb79524ddb813a9f83bb4bbcdda51abe07daeba50000001280c5e80b3472eb0f63f14e0c2edebbbe0409fb30598ca0a5ee3674f9c7f875f3dd07000000000000000000000000000000000000000000000000000000000055b6375b1c88011e00000000000000000000000000000000000000000000000018fc3d3100000000fd40055883f27cabc838b98e7cd660c5ee91e8b1882bd17f9e428b5aa6bc951d5a16f80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
***/

/*
uint8_t inline parse_digit(uint8_t d) 
{
    return d <= '9' ? (d - '0') : (d - 'a' + 10);
}

inline void to_array (const std::string& hex, uint8_t *out)
{
    for (size_t i = 1; i < hex.size(); i += 2) {

        int h = parse_digit(hex[i-1]);
        int l = parse_digit(hex[i]);
        out[i/2] = uint8_t((h<<4) | l);
    }
}


main() 
{
    
    uint8_t header[140];
    to_array (
    "000000206812f2a87241851756cb79524ddb813a9f83bb4bbcdda51abe07daeba50000001280c5e80b3472eb0f63f14e0c2edebbbe0409fb30598ca0a5ee3674f9c7f875f3dd07000000000000000000000000000000000000000000000000000000000055b6375b1c88011e00000000000000000000000000000000000000000000000018fc3d3100000000", header);

    uint8_t mix[32]; 
    to_array (
    "5883f27cabc838b98e7cd660c5ee91e8b1882bd17f9e428b5aa6bc951d5a16f8",
    mix);

    uint64_t nonce = 0x313dfc18;

    uint8_t hash[32]; 
    get_block_progpow_hash(header, mix, nonce, hash);
    

    uint8_t expected[32];
    to_array (
    "00000148b6715b3a32a7b36e5c820fcd4660acb72947ab9ebe4949134688066e", 
    expected);

    if (memcmp(expected, hash, 32)) {
        std::cout << "hash calculation incorrect!!! "  << "\n";
    } else {
        std::cout << "hash calculation passed. "  << "\n";
    }

} 
*/


