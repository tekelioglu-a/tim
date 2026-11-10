#ifndef MESSAGE_CRYPTO_H
#define MESSAGE_CRYPTO_H
#include "keyexchange.h"
#include <openssl/evp.h>
#include <stdint.h>
#include <inttypes.h>
#define AEAD_NONCE 12
#define AEAD_TAG 16
/* Sequential-only demonstration ratchet. Not the Signal Double Ratchet. */
static inline int ratchet_kdf(const unsigned char key[32],const char *label,unsigned char out[32]) {
 EVP_PKEY_CTX *c=EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF,NULL);
 size_t n=32;
 int ok=c && EVP_PKEY_derive_init(c)==1 && EVP_PKEY_CTX_set_hkdf_md(c,EVP_sha256())==1 &&
 EVP_PKEY_CTX_set1_hkdf_salt(c,(const unsigned char*)"stage7-chain-v1",15)==1 &&
 EVP_PKEY_CTX_set1_hkdf_key(c,key,32)==1 &&
 EVP_PKEY_CTX_add1_hkdf_info(c,(const unsigned char*)label,(int)strlen(label))==1 &&
 EVP_PKEY_derive(c,out,&n)==1 && n==32;
 EVP_PKEY_CTX_free(c);if(!ok)OPENSSL_cleanse(out,32);return ok;
}
static inline int ratchet_init(const unsigned char session[32],const char *me,const char *peer,
 unsigned char send[32],unsigned char recv[32]) {
 unsigned char a[32],b[32];
 int ok=ratchet_kdf(session,"alice-to-bob",a) && ratchet_kdf(session,"bob-to-alice",b);
 if(ok){memcpy(send,!strcmp(me,"alice")?a:b,32);memcpy(recv,!strcmp(me,"alice")?b:a,32);}
 OPENSSL_cleanse(a,32);OPENSSL_cleanse(b,32);(void)peer;return ok;
}
/* Authentication binds sender, recipient, timestamp, counter and ciphertext. */
static inline int aead_crypt(int enc,const unsigned char key[32],const unsigned char nonce[12],
 const unsigned char *aad,size_t aadlen,const unsigned char *in,size_t len,
 unsigned char *out,unsigned char tag[16]) {
 if(len>INT_MAX || aadlen>INT_MAX)return 0;
 EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new();int n=0,m=0;
 int ok=c && EVP_CipherInit_ex(c,EVP_aes_256_gcm(),NULL,NULL,NULL,enc)==1 &&
 EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,12,NULL)==1 &&
 EVP_CipherInit_ex(c,NULL,NULL,key,nonce,enc)==1 &&
 EVP_CipherUpdate(c,NULL,&n,aad,(int)aadlen)==1 &&
 EVP_CipherUpdate(c,out,&n,in,(int)len)==1;
 if(ok && !enc)ok=EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_TAG,16,tag)==1;
 if(ok)ok=EVP_CipherFinal_ex(c,out+n,&m)==1;
 if(ok && enc)ok=EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,16,tag)==1;
 if(!ok && !enc && out)OPENSSL_cleanse(out,len);
 EVP_CIPHER_CTX_free(c);return ok;
}
static inline int message_aad(const char *from,const char *to,const char *stamp,
 const char *counter,unsigned char *out,size_t cap,size_t *n) {
 const char *f[]={"messenger-stage7-aead-v1",from,to,stamp,counter};size_t at=0;
 for(size_t i=0;i<5;i++){size_t z=strlen(f[i]);if(z>65535 || z+2>cap-at)return 0;
 out[at++]=(unsigned char)(z>>8);out[at++]=(unsigned char)z;memcpy(out+at,f[i],z);at+=z;}
 *n=at;return 1;
}
#endif
