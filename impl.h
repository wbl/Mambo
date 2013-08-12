extern int encrypt_block(unsigned char *out,
                  const unsigned char *in,
                  const unsigned char *k,
                  const unsigned char *t);
extern int decrypt_block(unsigned char *out,
                         const unsigned char *in,
                         const unsigned char *k,
                         const unsigned char *t);
