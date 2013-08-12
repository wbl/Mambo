#include<stdio.h>
#include<strings.h>
#include "impl.h"
int main(){
  unsigned char m[64];
  unsigned char t[64];
  unsigned char k[32];
  unsigned char c[64];
  unsigned char n[64];
  for(int i=0; i<64; i++){
    m[i]=0;
    t[i]=0;
    c[i]=0;
  }
  for(int i=0; i<32; i++){
    k[i]=0;
  }
  strcpy(m, "Test");
  strcpy(t, "Try");
  strcpy(k, "Me");
  for(int i=0; i<10000000; i++){
    encrypt_block(c, m, k, t);
  }
  printf("10 million encryptions finished with first output byte %.2x", c[0]);
  return 0;
}
