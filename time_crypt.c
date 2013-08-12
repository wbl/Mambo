#include "crypto_aed.h"
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv)
{
  unsigned char *m;
  unsigned long long mlen;
  unsigned char *c;
  unsigned long long clen;
  unsigned char k[32];
  unsigned char n[64];
  for (int i=0; i<64; i++)
    {
      n[i]=0;
    }
  for (int i=0; i<32; i++)
    {
      k[i]=0;
    }
  if(argc==2)
    {
      mlen=atoll(argv[1]);
    }
  else
    {
      mlen=256;
    }
  clen=mlen+128;
  m=calloc(mlen, 1);
  c=calloc(clen, 1);
  for(int i=0; i<1000000; i++)
    crypto_aed_encrypt(c, &clen, m, mlen, NULL, 0, NULL, n, k);
  exit(0);
}
