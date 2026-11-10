/*
 * In-memory Double Ratchet state and primitives.
 *
 * The root KDF derives a new root/chain pair from X25519 output; the chain
 * KDF derives a one-time message key and the next chain key. The receiver
 * retains a bounded cache of skipped keys to tolerate out-of-order delivery.
 * Callers must not commit unauthenticated state changes. This implementation
 * is educational and has not undergone an independent security audit.
 */
#ifndef DOUBLE_RATCHET_H
#define DOUBLE_RATCHET_H
/* Educational Double Ratchet implementation: X25519, HKDF-SHA256, AES-256-GCM.
   NOT independently audited. In-memory state only; not crash-safe. */
#include "message_crypto.h"
#include <openssl/hmac.h>
#define DR_MAX_SKIP 64
#define DR_MAX_GAP 64

typedef struct { unsigned char pub[32], mk[32]; uint32_t n; int used; } DRSkipped;
typedef struct {
 EVP_PKEY *dhs;
 unsigned char dhr[32], rk[32], cks[32], ckr[32];
 uint32_t ns,nr,pn;
 int has_dhr,has_cks,has_ckr,ready;
 DRSkipped skipped[DR_MAX_SKIP];
} DRState;
/* Release the DH key and cleanse all ratchet and skipped-key state. */
static inline void dr_free(DRState *s) {
 EVP_PKEY_free(s->dhs); s->dhs=NULL;
 OPENSSL_cleanse(s,sizeof(*s));
}
/* Make a tentative snapshot for receive processing.
 *
 * Incoming packets are untrusted. They may force skipped-key derivation or a
 * DH ratchet before the authentication tag can be checked. Mutating the live
 * state first would let forged packets desynchronize a conversation. We copy
 * the state, increment the EVP_PKEY reference count for its owned DH key,
 * process against the copy, and commit only on successful AEAD verification.
 * Reference counting prevents the snapshot and original from double-freeing
 * the same OpenSSL key object. */
static inline int dr_clone(DRState *dst,const DRState *src) {
 memcpy(dst,src,sizeof(*dst));
 if(dst->dhs && EVP_PKEY_up_ref(dst->dhs)!=1){dst->dhs=NULL;OPENSSL_cleanse(dst,sizeof(*dst));return 0;}
 return 1;
}
/* Root-key evolution (HKDF-SHA256).
 *
 * Input: previous 32-byte root key as HKDF salt and a fresh 32-byte X25519
 * shared secret as key material. Domain-separated HKDF info identifies this
 * protocol operation. Output: 64 bytes, split into a new root key and a
 * chain key. The root key mixes fresh DH entropy into the session; the chain
 * key feeds per-message key derivation. Intermediate output is erased. */
static inline int dr_root(const unsigned char rk[32],const unsigned char dh[32],unsigned char newrk[32],unsigned char ck[32]) {
 unsigned char out[64];size_t n=64;
 static const unsigned char info[]="messenger-double-ratchet-root-v1";
 EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF,NULL);
 int ok=ctx && EVP_PKEY_derive_init(ctx)==1 && EVP_PKEY_CTX_set_hkdf_md(ctx,EVP_sha256())==1 &&
 EVP_PKEY_CTX_set1_hkdf_salt(ctx,rk,32)==1 && EVP_PKEY_CTX_set1_hkdf_key(ctx,dh,32)==1 &&
 EVP_PKEY_CTX_add1_hkdf_info(ctx,info,sizeof(info)-1)==1 && EVP_PKEY_derive(ctx,out,&n)==1 && n==64;
 if(ok){memcpy(newrk,out,32);memcpy(ck,out+32,32);} OPENSSL_cleanse(out,sizeof(out));EVP_PKEY_CTX_free(ctx);return ok;
}
/* Symmetric ratchet step.
 *
 * From one chain key derive two independent 32-byte outputs with HMAC-SHA256
 * and distinct one-byte labels: a per-message AEAD key and the successor chain
 * key. The old chain key must be retired after a successful step. The message
 * key is used once and erased; it is never transmitted to the relay or peer.
 * This mechanism is separate from the less frequent X25519 DH ratchet. */
static inline int dr_ck(const unsigned char ck[32],unsigned char next[32],unsigned char mk[32]) {
 unsigned int n=0;
 if(!HMAC(EVP_sha256(),ck,32,(const unsigned char*)"\1",1,mk,&n)||n!=32)return 0;
 if(!HMAC(EVP_sha256(),ck,32,(const unsigned char*)"\2",1,next,&n)||n!=32){OPENSSL_cleanse(mk,32);return 0;}
 return 1;
}
/* Responder begins with the shared root secret and DH key pair. */
static inline int dr_init_responder(DRState *s,const unsigned char sk[32],EVP_PKEY *bob_dh) {
 memset(s,0,sizeof(*s)); if(!bob_dh || EVP_PKEY_up_ref(bob_dh)!=1)return 0;
 s->dhs=bob_dh;memcpy(s->rk,sk,32);s->ready=1;return 1;
}
/* Initiator derives its initial sending chain from responder DH. */
static inline int dr_init_initiator(DRState *s,const unsigned char sk[32],const unsigned char bob_pub[32]) {
 memset(s,0,sizeof(*s));s->dhs=dh_generate();
 unsigned char dh[32],rk[32],ck[32];
 int ok=s->dhs && dh_secret(s->dhs,bob_pub,dh) && dr_root(sk,dh,rk,ck);
 if(ok){memcpy(s->rk,rk,32);memcpy(s->cks,ck,32);memcpy(s->dhr,bob_pub,32);s->has_dhr=s->has_cks=s->ready=1;}
 OPENSSL_cleanse(dh,32);OPENSSL_cleanse(rk,32);OPENSSL_cleanse(ck,32);
 if(!ok){dr_free(s);}return ok;
}
/* DH ratchet transition on a previously unseen peer DH public key.
 *
 * First combine our current DH private key with the new remote public key to
 * obtain the next receiving chain. Generate a fresh local DH key pair and
 * combine it with the same remote public key to obtain the next sending chain.
 * PN records the previous sending-chain length; Ns and Nr restart at zero.
 * The receive caller normally performs this on a cloned state, because a
 * malformed packet must not commit a speculative ratchet transition. */
static inline int dr_ratchet(DRState *s,const unsigned char remote[32]) {
 unsigned char dh[32],rk[32],ck[32];
 EVP_PKEY *newkey=NULL;
 int ok=s->dhs && dh_secret(s->dhs,remote,dh) && dr_root(s->rk,dh,rk,ck);
 if(ok){memcpy(s->rk,rk,32);memcpy(s->ckr,ck,32);s->has_ckr=1;
   newkey=dh_generate();ok=newkey && dh_secret(newkey,remote,dh) && dr_root(s->rk,dh,rk,ck);}
 if(ok){s->pn=s->ns;s->ns=0;s->nr=0;
   memcpy(s->dhr,remote,32);s->has_dhr=1;
   EVP_PKEY_free(s->dhs);s->dhs=newkey;newkey=NULL;
   memcpy(s->rk,rk,32);memcpy(s->cks,ck,32);s->has_cks=1;}
 EVP_PKEY_free(newkey);OPENSSL_cleanse(dh,32);OPENSSL_cleanse(rk,32);OPENSSL_cleanse(ck,32);return ok;
}
/* Cache message keys for gaps in the receiving sequence.
 *
 * If packet N arrives while Nr is smaller, derive keys for the intervening
 * messages and store them with the associated remote DH public key and index.
 * A later out-of-order packet can use exactly its cached key. DR_MAX_GAP and
 * DR_MAX_SKIP cap CPU work and retained secret material from attacker-supplied
 * counters. Cache entries must be erased after use. */
static inline int dr_cache(DRState *s,uint32_t until) {
 if(until<s->nr || until-s->nr>DR_MAX_GAP)return 0;
 if(!s->has_ckr)return until==0;
 size_t free_slots=0;for(int i=0;i<DR_MAX_SKIP;i++)if(!s->skipped[i].used)free_slots++;
 if(until-s->nr>free_slots)return 0;
 while(s->nr<until){unsigned char next[32],mk[32];int idx=-1;
  if(!dr_ck(s->ckr,next,mk))return 0;
  for(int i=0;i<DR_MAX_SKIP;i++)if(!s->skipped[i].used){idx=i;break;}
  if(idx<0)return 0;
  memcpy(s->skipped[idx].pub,s->dhr,32);s->skipped[idx].n=s->nr;
  memcpy(s->skipped[idx].mk,mk,32);s->skipped[idx].used=1;
  memcpy(s->ckr,next,32);s->nr++;
  OPENSSL_cleanse(next,32);OPENSSL_cleanse(mk,32);
 }return 1;
}
static inline int dr_aad(const char *from,const char *to,const char *stamp,const char *header,unsigned char *out,size_t cap,size_t *n){
 return message_aad(from,to,stamp,header,out,cap,n);
}
/* Header = public key (32 bytes), PN and N (4-byte big-endian each). */
static inline void dr_u32(unsigned char *p,uint32_t n){for(int i=3;i>=0;i--){p[i]=(unsigned char)n;n>>=8;}}
static inline uint32_t dr_read32(const unsigned char *p){return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];}
/* Encrypt one ratchet message.
 *
 * The 40-byte header is [X25519 public key:32][PN:4][N:4], with counters
 * in network (big-endian) order. Header, sender, recipient, and timestamp are
 * included in associated authenticated data (AAD). AES-256-GCM uses a random
 * 96-bit nonce and returns a 128-bit authentication tag. Only a successful
 * encryption advances the sending chain; temporary message keys are erased. */
static inline int dr_encrypt(DRState *s,const char *from,const char *to,const char *stamp,
 const unsigned char *plain,size_t len,unsigned char header[40],unsigned char nonce[12],unsigned char tag[16],unsigned char *cipher){
 if(!s->ready || !s->has_cks || s->ns==UINT32_MAX)return 0;
 unsigned char next[32],mk[32],aad[256];size_t alen=0;char hh[81];
 int ok=dr_ck(s->cks,next,mk) && dh_public(s->dhs,header);
 if(ok){dr_u32(header+32,s->pn);dr_u32(header+36,s->ns);tohex(header,40,hh);
  ok=dr_aad(from,to,stamp,hh,aad,sizeof(aad),&alen) && RAND_bytes(nonce,12)==1 &&
  aead_crypt(1,mk,nonce,aad,alen,plain,len,cipher,tag);}
 if(ok){memcpy(s->cks,next,32);s->ns++;}
 OPENSSL_cleanse(next,32);OPENSSL_cleanse(mk,32);OPENSSL_cleanse(aad,sizeof(aad));return ok;
}
/* Authenticate a received ratchet packet transactionally.
 *
 * 1. Build AAD from the claimed sender/recipient/timestamp/header.
 * 2. Clone state so forged packets cannot consume chain keys or DH state.
 * 3. Use a previously cached skipped key, or derive the appropriate receive
 *    chain, possibly crossing a new DH ratchet boundary.
 * 4. Verify AES-GCM tag before exposing plaintext or committing the clone.
 * 5. On success replace the original state; on failure discard the clone.
 *
 * A packet already consumed normally fails because its message key has been
 * retired. The client separately recognizes exact retransmitted ciphertext
 * for ACK replay without displaying duplicate plaintext. */
static inline int dr_decrypt(DRState *s,const char *from,const char *to,const char *stamp,
 const unsigned char header[40],const unsigned char nonce[12],const unsigned char tag[16],
 const unsigned char *cipher,size_t len,unsigned char *plain){
 if(!s->ready)return 0;
 uint32_t pn=dr_read32(header+32),n=dr_read32(header+36);
 char hh[81];unsigned char aad[256],mk[32]={0};size_t alen=0;
 tohex(header,40,hh);if(!dr_aad(from,to,stamp,hh,aad,sizeof(aad),&alen))return 0;
 DRState t; if(!dr_clone(&t,s))return 0;
 int ok=0,idx=-1;
 for(int i=0;i<DR_MAX_SKIP;i++)if(t.skipped[i].used && t.skipped[i].n==n && memcmp(t.skipped[i].pub,header,32)==0){idx=i;break;}
 if(idx>=0){memcpy(mk,t.skipped[idx].mk,32);OPENSSL_cleanse(t.skipped[idx].mk,32);t.skipped[idx].used=0;ok=1;}
 else {
  if(!t.has_dhr || memcmp(t.dhr,header,32)!=0){
   if(!dr_cache(&t,pn) || !dr_ratchet(&t,header))goto done;
  }
  if(n<t.nr || !dr_cache(&t,n) || !t.has_ckr)goto done;
  unsigned char next[32];ok=dr_ck(t.ckr,next,mk);
  if(ok){memcpy(t.ckr,next,32);t.nr++;}
  OPENSSL_cleanse(next,32);
 }
 if(ok){unsigned char tagcopy[16];memcpy(tagcopy,tag,16);
  ok=aead_crypt(0,mk,nonce,aad,alen,cipher,len,plain,tagcopy);
  OPENSSL_cleanse(tagcopy,16);}
 if(ok){dr_free(s);*s=t;OPENSSL_cleanse(&t,sizeof(t));}
 done:dr_free(&t);OPENSSL_cleanse(mk,32);OPENSSL_cleanse(aad,sizeof(aad));return ok;
}
#endif
