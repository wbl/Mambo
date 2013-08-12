#include<assert.h>
#include<stdint.h>
#include<stdio.h>
#include "impl.h"
typedef uint32_t uint32;

/*Some code and the ideas stolen from DJB's Salsa20.
  This is a tweaked block cipher  with a block and tweak
  of size 64 bytes, using 32 bit words and only bitwise operations
  and a 32 byte key.*/

/*Don't you love C?*/
#define rotate(u,c) (((u)<<c)|((u)>>(32-c)))

static uint32 load_littleendian(const unsigned char *x)
{
  return     (uint32) (x[0]) \
    | (((uint32) (x[1])) << 8) \
    | (((uint32) (x[2])) << 16) \
    | (((uint32) (x[3])) << 24)
    ;
}

static void store_littleendian(unsigned char *x,uint32 u)
{
  x[0] = u; u >>= 8;
  x[1] = u; u >>= 8;
  x[2] = u; u >>= 8;
  x[3] = u;
}
/* 64 byte block, 64 byte tweak,
   32 byte key */
int encrypt_block(unsigned char *out,
                  const unsigned char *in,
                  const unsigned char *k,
                  const unsigned char *t){
  uint32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
  uint32 k0, k1, k2, k3, k4, k5, k6, k7;
  uint32 t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15;
  uint32 temp;
  x0=load_littleendian(in+0*4);
  x1=load_littleendian(in+1*4);
  x2=load_littleendian(in+2*4);
  x3=load_littleendian(in+3*4);
  x4=load_littleendian(in+4*4);
  x5=load_littleendian(in+5*4);
  x6=load_littleendian(in+6*4);
  x7=load_littleendian(in+7*4);
  x8=load_littleendian(in+8*4);
  x9=load_littleendian(in+9*4);
  x10=load_littleendian(in+10*4);
  x11=load_littleendian(in+11*4);
  x12=load_littleendian(in+12*4);
  x13=load_littleendian(in+13*4);
  x14=load_littleendian(in+14*4);
  x15=load_littleendian(in+15*4);

  k0=load_littleendian(k+0*4);
  k1=load_littleendian(k+1*4);
  k2=load_littleendian(k+2*4);
  k3=load_littleendian(k+3*4);
  k4=load_littleendian(k+4*4);
  k5=load_littleendian(k+5*4);
  k6=load_littleendian(k+6*4);
  k7=load_littleendian(k+7*4);

  t0=load_littleendian(t+0*4);
  t1=load_littleendian(t+1*4);
  t2=load_littleendian(t+2*4);
  t3=load_littleendian(t+3*4);
  t4=load_littleendian(t+4*4);
  t5=load_littleendian(t+5*4);
  t6=load_littleendian(t+6*4);
  t7=load_littleendian(t+7*4);
  t8=load_littleendian(t+8*4);
  t9=load_littleendian(t+9*4);
  t10=load_littleendian(t+10*4);
  t11=load_littleendian(t+11*4);
  t12=load_littleendian(t+12*4);
  t13=load_littleendian(t+13*4);
  t14=load_littleendian(t+14*4);
  t15=load_littleendian(t+15*4);
  /*Now we are loaded. Plan is to do double rounds,
    followed by key mixing and adding of simple round constants.

    Key is added in checkerboard pattern for annoyance.
  */
  for(unsigned int i=0; i<12; i++){
    x1 ^= k0;
    x3 ^= k1;
    x4 ^= k2;
    x6 ^= k3;
    x9 ^= k4;
    x11 ^= k5;
    x12 ^= k6;
    x14 ^= k7;
    x0 ^= i;
    x5 ^= i;
    x10 ^= i;
    x15 ^= i;
    /* The following is the basic operation on
       four words. We repeat it on each row, than
       on each column.*/
    x1 ^= rotate(x2 & x0, 7);
    x2 ^= rotate(x0 | x3, 9);
    x3 ^= rotate(~(x1 & x0), 13);
    x0 ^= rotate(~(x2 | x1), 18);

    x5 ^= rotate(x6 & x4, 7);
    x6 ^= rotate(x4 | x7, 9);
    x7 ^= rotate(~(x5 & x4), 13);
    x4 ^= rotate(~(x6 | x5), 18);

    x9 ^= rotate(x10 & x8, 7);
    x10 ^= rotate(x8 | x11, 9);
    x11 ^= rotate(~(x9 & x8), 13);
    x8 ^= rotate(~(x10 | x9), 18);

    x13 ^= rotate(x14 & x12, 7);
    x14 ^= rotate(x12 | x15, 9);
    x15 ^= rotate(~(x13 & x12), 13);
    x12 ^= rotate(~(x14 | x13), 18);
    /*Now on the column */
    x4 ^= rotate(x8 & x0, 7);
    x8 ^= rotate(x0 | x12, 9);
    x12 ^= rotate(~(x4 & x0), 13);
    x0 ^= rotate(~(x8|x4), 18);

    x5 ^= rotate(x9 & x1, 7);
    x9 ^= rotate(x1 | x13, 9);
    x13 ^= rotate(~(x5 & x1), 13);
    x1 ^= rotate(~(x9|x5), 18);

    x6 ^= rotate(x10 & x2, 7);
    x10 ^= rotate(x2 | x14, 9);
    x14 ^= rotate(~(x6 & x2), 13);
    x2 ^= rotate(~(x10|x6), 18);
    
    x7 ^= rotate(x11 & x3, 7);
    x11 ^= rotate(x3 | x15, 9);
    x15 ^= rotate(~(x7 & x3), 13);
    x3 ^= rotate(~(x11 | x7), 18);
    if(i == 5){
      x0 ^= t0;
      x1 ^= t1;
      x2 ^= t2;
      x3 ^= t3;
      x4 ^= t4;
      x5 ^= t5;
      x6 ^= t6;
      x7 ^= t7;
      x8 ^= t8;
      x9 ^= t9;
      x10 ^= t10;
      x11 ^= t11;
      x12 ^= t12;
      x13 ^= t13;
      x14 ^= t14;
      x15 ^= t15;
    }
  }
  x1 ^= k0;
  x3 ^= k1;
  x4 ^= k2;
  x6 ^= k3;
  x9 ^= k4;
  x11 ^= k5;
  x12 ^= k6;
  x14 ^= k7;
  /*Now we have successfully mixed our x.
    Time to output it.*/
  store_littleendian(out+0*4,x0);
  store_littleendian(out+1*4,x1);
  store_littleendian(out+2*4,x2);
  store_littleendian(out+3*4,x3);
  store_littleendian(out+4*4,x4);
  store_littleendian(out+5*4,x5);
  store_littleendian(out+6*4,x6);
  store_littleendian(out+7*4,x7);
  store_littleendian(out+8*4,x8);
  store_littleendian(out+9*4,x9);
  store_littleendian(out+10*4,x10);
  store_littleendian(out+11*4,x11);
  store_littleendian(out+12*4,x12);
  store_littleendian(out+13*4,x13);
  store_littleendian(out+14*4,x14);
  store_littleendian(out+15*4,x15);
  return 0;
}

/* Now to decrypt. Note that all operations from above
   are invertable, so just reorder the operations.
   Great big swaths are wholesale copied.*/
int decrypt_block(unsigned char *out,
                  const unsigned char *in,
                  const unsigned char *k,
                  const unsigned char *t)
{
 uint32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
 uint32 k0, k1, k2, k3, k4, k5, k6, k7;
 uint32 t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15;
  x0=load_littleendian(in+0*4);
  x1=load_littleendian(in+1*4);
  x2=load_littleendian(in+2*4);
  x3=load_littleendian(in+3*4);
  x4=load_littleendian(in+4*4);
  x5=load_littleendian(in+5*4);
  x6=load_littleendian(in+6*4);
  x7=load_littleendian(in+7*4);
  x8=load_littleendian(in+8*4);
  x9=load_littleendian(in+9*4);
  x10=load_littleendian(in+10*4);
  x11=load_littleendian(in+11*4);
  x12=load_littleendian(in+12*4);
  x13=load_littleendian(in+13*4);
  x14=load_littleendian(in+14*4);
  x15=load_littleendian(in+15*4);

  k0=load_littleendian(k+0*4);
  k1=load_littleendian(k+1*4);
  k2=load_littleendian(k+2*4);
  k3=load_littleendian(k+3*4);
  k4=load_littleendian(k+4*4);
  k5=load_littleendian(k+5*4);
  k6=load_littleendian(k+6*4);
  k7=load_littleendian(k+7*4);

  t0=load_littleendian(t+0*4);
  t1=load_littleendian(t+1*4);
  t2=load_littleendian(t+2*4);
  t3=load_littleendian(t+3*4);
  t4=load_littleendian(t+4*4);
  t5=load_littleendian(t+5*4);
  t6=load_littleendian(t+6*4);
  t7=load_littleendian(t+7*4);
  t8=load_littleendian(t+8*4);
  t9=load_littleendian(t+9*4);
  t10=load_littleendian(t+10*4);
  t11=load_littleendian(t+11*4);
  t12=load_littleendian(t+12*4);
  t13=load_littleendian(t+13*4);
  t14=load_littleendian(t+14*4);
  t15=load_littleendian(t+15*4);

  /*Undo whitening*/
  x1 ^= k0;
  x3 ^= k1;
  x4 ^= k2;
  x6 ^= k3;
  x9 ^= k4;
  x11 ^= k5;
  x12 ^= k6;
  x14 ^= k7;

  for(int i=11; i>=0; i--){ /*Reverse order!*/
     if(i==5){
      x0 ^= t0;
      x1 ^= t1;
      x2 ^= t2;
      x3 ^= t3;
      x4 ^= t4;
      x5 ^= t5;
      x6 ^= t6;
      x7 ^= t7;
      x8 ^= t8;
      x9 ^= t9;
      x10 ^= t10;
      x11 ^= t11;
      x12 ^= t12;
      x13 ^= t13;
      x14 ^= t14;
      x15 ^= t15;
    }

    x3 ^= rotate(~(x11 | x7), 18);
    x15 ^= rotate(~(x7 & x3), 13);
    x11 ^= rotate(x3 | x15, 9);
    x7 ^= rotate(x11 & x3, 7);
    
    x2 ^= rotate(~(x10|x6), 18);
    x14 ^= rotate(~(x6 & x2), 13);
    x10 ^= rotate(x2 | x14, 9);
    x6 ^= rotate(x10 & x2, 7);

    x1 ^= rotate(~(x9|x5), 18);
    x13 ^= rotate(~(x5 & x1), 13);
    x9 ^= rotate(x1 | x13, 9);
    x5 ^= rotate(x9 & x1, 7);

    x0 ^= rotate(~(x8|x4), 18);
    x12 ^= rotate(~(x4 & x0), 13);
    x8 ^= rotate(x0 | x12, 9);
    x4 ^= rotate(x8 & x0, 7);
   
    x12 ^= rotate(~(x14 | x13), 18);
    x15 ^= rotate(~(x13 & x12), 13);
    x14 ^= rotate(x12 | x15, 9);
    x13 ^= rotate(x14 & x12, 7);

    x8 ^= rotate(~(x10 | x9), 18);
    x11 ^= rotate(~(x9 & x8), 13);
    x10 ^= rotate(x8 | x11, 9);
    x9 ^= rotate(x10 & x8, 7);

    x4 ^= rotate(~(x6 | x5), 18);
    x7 ^= rotate(~(x5 & x4), 13);
    x6 ^= rotate(x4 | x7, 9);
    x5 ^= rotate(x6 & x4, 7);

    x0 ^= rotate(~(x2 | x1), 18);
    x3 ^= rotate(~(x1 & x0), 13);
    x2 ^= rotate(x0 | x3, 9);
    x1 ^= rotate(x2 & x0, 7);
    /*Now we have undone the mixing, time to do the adding
      of various things again (recall ^ is its own inverse)*/
    x0 ^= i;
    x5 ^= i;
    x10 ^= i;
    x15 ^= i;
    x1 ^= k0;
    x3 ^= k1;
    x4 ^= k2;
    x6 ^= k3;
    x9 ^= k4;
    x11 ^= k5;
    x12 ^= k6;
    x14 ^= k7;
  }
  /* Decryption complete: time to output it*/
  store_littleendian(out+0*4,x0);
  store_littleendian(out+1*4,x1);
  store_littleendian(out+2*4,x2);
  store_littleendian(out+3*4,x3);
  store_littleendian(out+4*4,x4);
  store_littleendian(out+5*4,x5);
  store_littleendian(out+6*4,x6);
  store_littleendian(out+7*4,x7);
  store_littleendian(out+8*4,x8);
  store_littleendian(out+9*4,x9);
  store_littleendian(out+10*4,x10);
  store_littleendian(out+11*4,x11);
  store_littleendian(out+12*4,x12);
  store_littleendian(out+13*4,x13);
  store_littleendian(out+14*4,x14);
  store_littleendian(out+15*4,x15);

  return 0;
}
#undef rotate
