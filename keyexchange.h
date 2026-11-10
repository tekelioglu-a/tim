/*
 * Authenticated-handshake building blocks.
 *
 * X25519 supplies shared-secret material; transcript construction binds
 * identities, session IDs, and ephemeral public keys to their roles.
 * Signature verification is performed by the protocol caller.
 */
#ifndef KEYEXCHANGE_H
#define KEYEXCHANGE_H
#include "identity.h"
#include <openssl/kdf.h>
#include <openssl/crypto.h>
#define DH_LEN 32
#define SID_LEN 16
/* X25519 building blocks reused by the Stage 8H handshake.
 *
 * X25519 alone does not authenticate who supplied a public key. The caller
 * must verify the Ed25519 signature over the full handshake transcript and
 * bind the derived secret to both identities and the session identifier.
 * The old Stage 6 note referred to the earlier standalone demonstration;
 * these primitives are now components of the authenticated E2EE handshake. */
static inline EVP_PKEY *dh_generate(void) {
 EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_X25519,NULL);
 EVP_PKEY *key=NULL;
 if(!ctx || EVP_PKEY_keygen_init(ctx)!=1 || EVP_PKEY_keygen(ctx,&key)!=1) {EVP_PKEY_free(key);key=NULL;}
 EVP_PKEY_CTX_free(ctx);return key;
}
static inline int dh_public(EVP_PKEY *key,unsigned char out[DH_LEN]) {
 size_t n=DH_LEN;return key && EVP_PKEY_get_raw_public_key(key,out,&n)==1 && n==DH_LEN;
}
static inline int dh_secret(EVP_PKEY *mine,const unsigned char pub[DH_LEN],unsigned char out[DH_LEN]) {
 EVP_PKEY *peer=EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519,NULL,pub,DH_LEN);
 EVP_PKEY_CTX *ctx=peer?EVP_PKEY_CTX_new(mine,NULL):NULL;
 size_t n=DH_LEN;
 int ok=ctx && EVP_PKEY_derive_init(ctx)==1 && EVP_PKEY_derive_set_peer(ctx,peer)==1 && EVP_PKEY_derive(ctx,out,&n)==1 && n==DH_LEN;
 EVP_PKEY_CTX_free(ctx);EVP_PKEY_free(peer);
 if(!ok) OPENSSL_cleanse(out,DH_LEN);
 return ok;
}
static inline int dh_transcript(const char *kind,const char *from,const char *to,
 const char *sid,const char *initpub,const char *resppub,
 unsigned char *out,size_t cap,size_t *len) {
 const char *fields[]={"messenger-stage6-x25519-v1",kind,from,to,sid,initpub,resppub};
 size_t at=0;
 for(size_t i=0;i<7;i++) {
  size_t n=strlen(fields[i]);if(n>65535 || n+2>cap-at)return 0;
  out[at++]=(unsigned char)(n>>8);out[at++]=(unsigned char)n;
  memcpy(out+at,fields[i],n);at+=n;
 }
 *len=at;return 1;
}
static inline int dh_derive_key(const unsigned char secret[DH_LEN],const char *initiator,
 const char *responder,const char *sid,const char *initpub,const char *resppub,
 unsigned char key[DH_LEN]) {
 unsigned char info[512];size_t len=0;
 if(!dh_transcript("session",initiator,responder,sid,initpub,resppub,info,sizeof(info),&len))return 0;
 EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF,NULL);
 int ok=ctx && EVP_PKEY_derive_init(ctx)==1 &&
 EVP_PKEY_CTX_set_hkdf_md(ctx,EVP_sha256())==1 &&
 EVP_PKEY_CTX_set1_hkdf_salt(ctx,(const unsigned char *)"stage6-hkdf-salt-v1",19)==1 &&
 EVP_PKEY_CTX_set1_hkdf_key(ctx,secret,DH_LEN)==1 &&
 EVP_PKEY_CTX_add1_hkdf_info(ctx,info,(int)len)==1;
 size_t outlen=DH_LEN;
 if(ok)ok=EVP_PKEY_derive(ctx,key,&outlen)==1 && outlen==DH_LEN;
 EVP_PKEY_CTX_free(ctx);OPENSSL_cleanse(info,sizeof(info));
 if(!ok)OPENSSL_cleanse(key,DH_LEN);
 return ok;
}
#endif
