#include "double_ratchet.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef struct {unsigned char h[40],n[12],t[16],c[256];size_t len;char from[8],to[8];} Packet;
static void must(int v,const char *why){if(!v){fprintf(stderr,"FAIL: %s\n",why);exit(1);}}
static Packet sendp(DRState *s,const char *from,const char *to,const char *msg){Packet p={0};
 strcpy(p.from,from);strcpy(p.to,to);p.len=strlen(msg);
 must(dr_encrypt(s,from,to,"2026-11-09T12:00:00Z",(const unsigned char*)msg,p.len,p.h,p.n,p.t,p.c),"encrypt");return p;}
static int recv(DRState *s,const Packet *p,const char *msg){unsigned char out[257]={0};
 int ok=dr_decrypt(s,p->from,p->to,"2026-11-09T12:00:00Z",p->h,p->n,p->t,p->c,p->len,out);
 if(ok && (strlen(msg)!=p->len || memcmp(out,msg,p->len)))return 0;
 return ok;}
int main(void){DRState a={0},b={0};unsigned char sk[32],pub[32];
 must(RAND_bytes(sk,32)==1,"random");EVP_PKEY *bob=dh_generate();must(bob!=NULL,"generate");
 must(dh_public(bob,pub),"pub");must(dr_init_responder(&b,sk,bob),"init bob");
 must(dr_init_initiator(&a,sk,pub),"init alice");EVP_PKEY_free(bob);
 Packet a0=sendp(&a,"alice","bob","A0"),a1=sendp(&a,"alice","bob","A1"),a2=sendp(&a,"alice","bob","A2");
 must(recv(&b,&a2,"A2"),"reordered a2");must(recv(&b,&a0,"A0"),"reordered a0");
 must(recv(&b,&a1,"A1"),"reordered a1");must(!recv(&b,&a0,"A0"),"replay");
 Packet b0=sendp(&b,"bob","alice","B0"),b1=sendp(&b,"bob","alice","B1");
 must(recv(&a,&b1,"B1"),"new DH epoch b1");must(recv(&a,&b0,"B0"),"old in epoch");
 Packet a3=sendp(&a,"alice","bob","A3"),a4=sendp(&a,"alice","bob","A4");
 Packet bad=a4;bad.t[0]^=1;
 must(!recv(&b,&bad,"A4"),"tamper rejection");must(recv(&b,&a4,"A4"),"rollback on tamper");
 must(recv(&b,&a3,"A3"),"skipped across DH epoch");
 Packet b2=sendp(&b,"bob","alice","B2");must(recv(&a,&b2,"B2"),"next DH epoch");
 dr_free(&a);dr_free(&b);OPENSSL_cleanse(sk,32);
 puts("PASS: DH transitions, reordered messages, skipped keys, replay rejection, tamper rollback");return 0;}
