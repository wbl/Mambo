#include<stdio.h>
#include <string.h>
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
  encrypt_block(c, m, k,t);
  for(int i=0; i<64; i++){
    printf("%.2x", c[i]);
  }
  printf("\n");
  decrypt_block(n, c, k, t);
  if(memcmp(n, m, 64)){
    printf("Failure!\n");
  } else {
    printf("Success!\n");
  }
  return 0;
}
