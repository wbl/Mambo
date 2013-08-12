#include "crypto_aed.h"
#include "impl.h"
#include <stdio.h>
typedef unsigned long long ull;
void xormov(unsigned char *x, const unsigned char *y, unsigned long long len)
{
  for(unsigned long long i=0; i<len; i++)
    {
      x[i]^=y[i];
    }
}

int crypto_aed_encrypt(
                       unsigned char *c, unsigned long long *clen,
                       const unsigned char *m, unsigned long long mlen,
                       const unsigned char *ad, unsigned long long adlen,
                       const unsigned char *nsec,
                       const unsigned char *npub,
                       const unsigned char *k
                       )
{
  unsigned char u[64];
  unsigned char tau[64];
  unsigned char tmp[64];
  unsigned char lastblock[64];
  unsigned long long remainder;
  unsigned long long blocks;
  for(ull i=0; i<64; i++)
    {
    u[i]=0;
    }
  /* First we process the header */
  for(ull i=0; i+64<adlen; i+=64)
    {
    encrypt_block(tmp, ad+i, k, u);
    xormov(u, tmp, 64);
    }
  /*We have to process the last block*/
  blocks=adlen/64;
  remainder=adlen-blocks*64;
  for(ull i=0; i<remainder; i++)
    {
      lastblock[i]=ad[i+blocks*64];
    }
  lastblock[remainder]=1;
  for(ull i=remainder+1; i<64; i++)
    {
      lastblock[i]=0;
    }
  encrypt_block(tmp, lastblock, k, u);
  xormov(u, tmp, 64);
  /*Now we process the public message number*/
  encrypt_block(tau, npub, k, u);
  xormov(u, tau, 64);
  /* At this point we have u
     and can now process the
     message*/
  blocks=mlen/64;
  remainder=mlen-blocks*64;
  for(ull i=0; i<blocks; i++)
    {
      encrypt_block(c+i*64, m+i*64, k, u);
      xormov(u, c+i*64, 64);
    }
  /*Once again we have the last block to process*/
  for(ull i=0; i<remainder; i++)
    {
      lastblock[i]=m[blocks*64+i];
    }
  lastblock[remainder]=1;
  for(int i=remainder+1; i<64; i++)
    {
      lastblock[i]=0;
    }
  encrypt_block(c+blocks*64, lastblock, k, u);
  xormov(u, c+blocks*64, 64);
  /*Finally the authenticator is computed*/
  encrypt_block(c+(blocks+1)*64, tau, k, u);
  *clen=blocks*64+64+64;
  return 0;
}

int crypto_aed_decrypt(
                       unsigned char *m, unsigned long long *mlen,
                       unsigned char *nsec,
                       const unsigned char *c, unsigned long long clen,
                       const unsigned char *ad, unsigned long long adlen,
                       const unsigned char *npub,
                       const unsigned char *k
                       )
{
  unsigned char tmp[64];
  unsigned char tau[64];
  unsigned char u[64];
  unsigned long long blocks;
  unsigned long long remainder;
  unsigned long long where;
  unsigned char comp;
  unsigned char lastblock[64];
  for(ull i=0; i<64; i++)
    {
      u[i]=0;
    }
  /* First we have to compute tau and u as above*/
  for(ull i=0; i+64<adlen; i+=64)
    {
      encrypt_block(tmp, ad+i, k, u);
      xormov(u, tmp, 64);
    }
  /*We have to process the last block*/
  blocks=adlen/64;
  remainder=adlen-blocks*64;
  for(ull i=0; i<remainder; i++)
    {
      lastblock[i]=ad[i+blocks*64];
    }
  lastblock[remainder]=1;
  for(ull i=remainder+1; i<64; i++)
    {
      lastblock[i]=0;
    }
  encrypt_block(tmp, lastblock, k, u);
  xormov(u, tmp, 64);
  /*Now we process the public message number*/
  encrypt_block(tau, npub, k, u);
  xormov(u, tau, 64);
  /*We now have to decrypt the message.
    The last block in the message is the tag.
    The block before the tag contains padding,
    and so it must be decrypted into a temporary
    buffer and then copied*/
  blocks=clen/64-2;
  for(ull i=0; i<blocks; i++)
    {
      decrypt_block(m+i*64, c+i*64, k, u);
      xormov(u, c+i*64, 64);
    }
  decrypt_block(tmp, c+clen-128, k, u);
  xormov(u, c+clen-128, 64);
  /*tmp contains the padded block. We've
    got to find out how much is padding to get
    the length right.*/
  for(where=63; !tmp[where]; where--);
  if(! where>64)
    for(ull i=0; i<remainder; i++)
      {
        m[blocks*64+i]=tmp[i];
      }
  *mlen=where+blocks*64;
  /*Lastly, decrypt the tag compare to tau*/
  decrypt_block(tmp, c+clen-64, k, u);
  comp=0;
  for(ull i=0; i<64; i++)
    {
      comp |=(tau[i]^tmp[i]);
    }
  return comp==0?0:-1;
}
  
