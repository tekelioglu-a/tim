#ifndef IDENTITY_H
#define IDENTITY_H
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define NONCE_LEN 32
#define SIG_LEN 64
static inline void tohex(const unsigned char *src,size_t n,char *dst) {
 static const char h[]="0123456789abcdef";
 for(size_t i=0;i<n;i++){dst[2*i]=h[src[i]>>4];dst[2*i+1]=h[src[i]&15];}
 dst[2*n]=0;
}
static inline int hexval(char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}
static inline int fromhex(const char *src,unsigned char *dst,size_t n){
 if(strlen(src)!=2*n)return 0;
 for(size_t i=0;i<n;i++){int a=hexval(src[2*i]),b=hexval(src[2*i+1]);if(a<0||b<0)return 0;dst[i]=(unsigned char)((a<<4)|b);}
 return 1;
}
/* Domain-separated transcript: protocol label, username, and fresh server nonce. */
static inline int auth_message(const char *user,const unsigned char nonce[NONCE_LEN],unsigned char *buf,size_t cap,size_t *len){
 static const char label[]="messenger-auth-v1";
 size_t a=sizeof(label),b=strlen(user);
 if(a+b+NONCE_LEN>cap)return 0;
 memcpy(buf,label,a);memcpy(buf+a,user,b);memcpy(buf+a+b,nonce,NONCE_LEN);
 *len=a+b+NONCE_LEN;return 1;
}
static inline EVP_PKEY *load_key(const char *path,int priv){
 FILE *f=fopen(path,"r");if(!f)return NULL;
 EVP_PKEY *k=priv?PEM_read_PrivateKey(f,NULL,NULL,NULL):PEM_read_PUBKEY(f,NULL,NULL,NULL);
 fclose(f);
 if(k && EVP_PKEY_base_id(k)!=EVP_PKEY_ED25519){EVP_PKEY_free(k);return NULL;}
 return k;
}
static inline int ed_sign(EVP_PKEY *key,const unsigned char *msg,size_t len,unsigned char sig[SIG_LEN]){
 EVP_MD_CTX *ctx=EVP_MD_CTX_new();size_t n=SIG_LEN;
 int ok=ctx && EVP_DigestSignInit(ctx,NULL,NULL,NULL,key)==1 && EVP_DigestSign(ctx,sig,&n,msg,len)==1 && n==SIG_LEN;
 EVP_MD_CTX_free(ctx);return ok;
}
static inline int ed_verify(EVP_PKEY *key,const unsigned char *msg,size_t len,const unsigned char sig[SIG_LEN]){
 EVP_MD_CTX *ctx=EVP_MD_CTX_new();
 int ok=ctx && EVP_DigestVerifyInit(ctx,NULL,NULL,NULL,key)==1 && EVP_DigestVerify(ctx,sig,SIG_LEN,msg,len)==1;
 EVP_MD_CTX_free(ctx);return ok;
}
#endif
