#include<stdio.h>
#include<stdlib.h>
#include"crypto_aed.h"
int main()
{
  unsigned char m[64];
  unsigned char c[64+128];
  unsigned char n[64];
  unsigned char k[32];
  unsigned long long mlen;
  unsigned long long clen;
  unsigned long long mlenback;
  unsigned char mback[64];
  int retval;
  mlen=62;
  for(int i=0; i<64; i++)
    {
      m[i]=0;
      n[i]=0;
    }
  for(int i=0; i<(64+128); i++)
    {
      c[i]=0;
    }
  for(int i=0; i<32; i++)
    {
      k[i]=0;
    }
  crypto_aed_encrypt(c, &clen, m, mlen, NULL, 0, NULL, n, k);
  printf("Encrypted length %lld\n", clen);
  retval=crypto_aed_decrypt(mback, &mlenback, NULL, c, clen, NULL, 0, n, k);
  printf("Asserted length of message %lld, actual length %lld, retval %d\n", mlenback, mlen, retval);
  exit(0);
}
