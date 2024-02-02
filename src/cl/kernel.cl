
#define KECCAKF_ROUNDS 24
#define SHA3_256_MDLEN 32
#define ROTL64(x, y) rotate((x), (ulong)(y))

typedef struct {
  char d[64];
} word_ctx;

// Define the state context for SHA3
typedef struct {
  union {         // state:
    uchar b[200]; // 8-bit bytes
    ulong q[25];  // 64-bit words
  } st;
  int pt, rsiz; // these don't overflow
} sha3_ctx_t;

// Constants for Keccak
constant ulong keccakf_rndc[24] = {
    0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808AUL,
    0x8000000080008000UL, 0x000000000000808BUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL, 0x000000000000008AUL,
    0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000AUL,
    0x000000008000808BUL, 0x800000000000008BUL, 0x8000000000008089UL,
    0x8000000000008003UL, 0x8000000000008002UL, 0x8000000000000080UL,
    0x000000000000800AUL, 0x800000008000000AUL, 0x8000000080008081UL,
    0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL};

constant int keccakf_rotc[24] = {1,  3,  6,  10, 15, 21, 28, 36,
                                 45, 55, 2,  14, 27, 41, 56, 8,
                                 25, 43, 62, 18, 39, 61, 20, 44};

constant int keccakf_piln[24] = {10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
                                 15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1};

// The Keccak-f function
void sha3_keccakf(ulong *st) {
  int i, j, r;
  ulong t, bc[5];

  // actual iteration
  for (r = 0; r < KECCAKF_ROUNDS; r++) {

    // Theta
    for (i = 0; i < 5; i++)
      bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

    for (i = 0; i < 5; i++) {
      t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
      for (j = 0; j < 25; j += 5)
        st[j + i] ^= t;
    }

    // Rho Pi
    t = st[1];
    for (i = 0; i < 24; i++) {
      j = keccakf_piln[i];
      bc[0] = st[j];
      st[j] = ROTL64(t, keccakf_rotc[i]);
      t = bc[0];
    }

    //  Chi
    for (j = 0; j < 25; j += 5) {
      for (i = 0; i < 5; i++)
        bc[i] = st[j + i];
      for (i = 0; i < 5; i++)
        st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
    }

    //  Iota
    st[0] ^= keccakf_rndc[r];
  }
}

// SHA3-256 initialization
void sha3_init(sha3_ctx_t *c) {
  int i;

  for (i = 0; i < 25; i++)
    c->st.q[i] = 0;
  c->rsiz = 200 - 2 * SHA3_256_MDLEN;
  c->pt = 0;
}

// SHA3-256 update
void sha3_update(sha3_ctx_t *c, const uchar *data, uint len) {
  uchar i;
  int j;

  j = c->pt;
  for (i = 0; i < len; i++) {
    c->st.b[j++] ^= ((uchar *)data)[i];
    if (j >= c->rsiz) {
      sha3_keccakf(c->st.q);
      j = 0;
    }
  }
  c->pt = j;
}

// SHA3-256 finalization
void sha3_final(global uchar *md, sha3_ctx_t *c) {
  int i;

  c->st.b[c->pt] ^= 0x01; // 0x01 for keccak, 0x06 for sha3
  c->st.b[c->rsiz - 1] ^= 0x80;
  sha3_keccakf(c->st.q);

  for (i = 0; i < SHA3_256_MDLEN; i++) {
    ((global uchar *)md)[i] = c->st.b[i];
  }
}

void keccak_256(const uchar *in, uint inlen, global uchar *md) {
  sha3_ctx_t sha3;
  sha3_init(&sha3);
  sha3_update(&sha3, in, inlen);
  sha3_final(md, &sha3);
}

__kernel void keccak_bench(global const uchar *msgs, uint inlen,
                           global char *md) {
  const uint id = get_global_id(0);
  char msg[4];
  for (size_t i = 0; i < 4; i++) {
    msg[i] = msgs[id * 4 + i];
  }
  keccak_256(msg, 4, &md[id * 32]);
}
