#define _POSIX_C_SOURCE 200809L
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "message_crypto.h"
#include <limits.h>

#define PORT "5555"
#define MAX_LINE 4096

static int send_line(SSL *ssl,const char *line) {
    size_t len=strlen(line),off=0;
    while (off<len) {
        size_t written=0;
        if (SSL_write_ex(ssl,line+off,len-off,&written)!=1) return -1;
        off+=written;
    }
    return 0;
}
static int connect_host(const char *host) {
    struct addrinfo hints={0},*res=NULL,*p;
    hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
    int e=getaddrinfo(host,PORT,&hints,&res);
    if (e) { fprintf(stderr,"getaddrinfo: %s\n",gai_strerror(e)); return -1; }
    int fd=-1;
    for (p=res;p;p=p->ai_next) {
        fd=socket(p->ai_family,p->ai_socktype,p->ai_protocol);
        if (fd<0) continue;
        if (connect(fd,p->ai_addr,p->ai_addrlen)==0) break;
        close(fd); fd=-1;
    }
    freeaddrinfo(res);
    return fd;
}
static int timestamp(char *buf,size_t size) {
    time_t t=time(NULL); struct tm tm;
    return gmtime_r(&t,&tm) && strftime(buf,size,"%Y-%m-%dT%H:%M:%SZ",&tm)>0 ? 0:-1;
}
typedef struct {
 EVP_PKEY *pending;
 char pending_peer[64],sid[SID_LEN*2+1],initpub[DH_LEN*2+1];
 unsigned char session_key[DH_LEN];
 char established_peer[64];
 unsigned char send_chain[32],recv_chain[32];
 uint64_t send_count,recv_count;
 int established;
} KeyState;
static int key_send(SSL *ssl,EVP_PKEY *identity,const char *from,const char *to,
 const char *kind,const char *sid,const char *initpub,const char *resppub) {
 unsigned char t[512],sig[SIG_LEN];size_t n=0;
 char hex[SIG_LEN*2+1],line[512];
 if(!dh_transcript(kind,from,to,sid,initpub,resppub,t,sizeof(t),&n) ||
    !ed_sign(identity,t,n,sig))return 0;
 tohex(sig,SIG_LEN,hex);
 int z=snprintf(line,sizeof(line),"KEY %s %s %s %s %s %s\n",to,kind,sid,initpub,resppub,hex);
 return z>0 && (size_t)z<sizeof(line) && send_line(ssl,line)==0;
}
static void key_receive(SSL *ssl,char *line,const char *user,EVP_PKEY *identity,
 EVP_PKEY *alice_pub,EVP_PKEY *bob_pub,KeyState *state) {
 char *parts[6],*save=NULL;
 for(int i=0;i<6;i++)parts[i]=strtok_r(i?NULL:line+8," ",&save);
 if(!parts[5] || strtok_r(NULL," ",&save)) {puts("[REJECTED malformed KEY]");return;}
 char *from=parts[0],*kind=parts[1],*sid=parts[2],*initpub=parts[3],*resppub=parts[4],*sighex=parts[5];
 EVP_PKEY *peer=!strcmp(from,"alice")?alice_pub:!strcmp(from,"bob")?bob_pub:NULL;
 unsigned char sig[SIG_LEN],sidbytes[SID_LEN],initbytes[DH_LEN],replybytes[DH_LEN],transcript[512];size_t n=0;
 if(!peer || !strcmp(from,user) || (strcmp(kind,"INIT") && strcmp(kind,"REPLY")) ||
    !fromhex(sid,sidbytes,SID_LEN) || !fromhex(initpub,initbytes,DH_LEN) ||
    (strcmp(kind,"INIT")? !fromhex(resppub,replybytes,DH_LEN):strcmp(resppub,"-")!=0) ||
    !fromhex(sighex,sig,SIG_LEN) ||
    !dh_transcript(kind,from,user,sid,initpub,resppub,transcript,sizeof(transcript),&n) ||
    !ed_verify(peer,transcript,n,sig)) {
    puts("[REJECTED unauthenticated KEY]");return;
 }
 if(!strcmp(kind,"INIT")) {
    EVP_PKEY *mine=dh_generate();unsigned char mypub[DH_LEN],secret[DH_LEN],key[DH_LEN];char myhex[DH_LEN*2+1];
    if(!mine || !dh_public(mine,mypub)) {puts("[KEY generation failed]");EVP_PKEY_free(mine);return;}
    tohex(mypub,DH_LEN,myhex);
    int ok=dh_secret(mine,initbytes,secret) &&
       dh_derive_key(secret,from,user,sid,initpub,myhex,key) &&
       key_send(ssl,identity,user,from,"REPLY",sid,initpub,myhex);
    OPENSSL_cleanse(secret,sizeof(secret));EVP_PKEY_free(mine);
    if(!ok){OPENSSL_cleanse(key,sizeof(key));puts("[KEY exchange failed]");return;}
    memcpy(state->session_key,key,DH_LEN);OPENSSL_cleanse(key,sizeof(key));
    snprintf(state->established_peer,sizeof(state->established_peer),"%s",from);
    if(!ratchet_init(state->session_key,user,from,state->send_chain,state->recv_chain)) {puts("[Ratchet init failed]");state->established=0;return;}
    state->send_count=state->recv_count=0;state->established=1;
    printf("[STAGE6] Authenticated X25519/HKDF session established with %s (responder)\n",from);
 } else {
    if(!state->pending || strcmp(state->pending_peer,from) || strcmp(state->sid,sid) ||
       strcmp(state->initpub,initpub)) {puts("[REJECTED unexpected KEY reply]");return;}
    unsigned char secret[DH_LEN],key[DH_LEN];
    int ok=dh_secret(state->pending,replybytes,secret) &&
           dh_derive_key(secret,user,from,sid,initpub,resppub,key);
    OPENSSL_cleanse(secret,sizeof(secret));EVP_PKEY_free(state->pending);state->pending=NULL;
    if(!ok){puts("[KEY derivation failed]");return;}
    memcpy(state->session_key,key,DH_LEN);OPENSSL_cleanse(key,sizeof(key));
    snprintf(state->established_peer,sizeof(state->established_peer),"%s",from);
    if(!ratchet_init(state->session_key,user,from,state->send_chain,state->recv_chain)) {puts("[Ratchet init failed]");state->established=0;return;}
    state->send_count=state->recv_count=0;state->established=1;
    printf("[STAGE6] Authenticated X25519/HKDF session established with %s (initiator)\n",from);
 }
 /* Stage 6 does NOT use this secret to encrypt messages yet. */
}
static int key_initiate(SSL *ssl,EVP_PKEY *identity,const char *user,const char *peer,KeyState *state) {
 if((strcmp(peer,"alice") && strcmp(peer,"bob")) || !strcmp(peer,user))return 0;
 EVP_PKEY *mine=dh_generate();unsigned char pub[DH_LEN],sid[SID_LEN];
 if(!mine || !dh_public(mine,pub) || RAND_bytes(sid,sizeof(sid))!=1){EVP_PKEY_free(mine);return 0;}
 char pubhex[DH_LEN*2+1],sidhex[SID_LEN*2+1];tohex(pub,DH_LEN,pubhex);tohex(sid,SID_LEN,sidhex);
 if(!key_send(ssl,identity,user,peer,"INIT",sidhex,pubhex,"-")){EVP_PKEY_free(mine);return 0;}
 EVP_PKEY_free(state->pending);state->pending=mine;
 strcpy(state->pending_peer,peer);
 strcpy(state->sid,sidhex);strcpy(state->initpub,pubhex);
 printf("[STAGE6] Sent signed ephemeral X25519 public key to %s\n",peer);
 return 1;
}
static void display_verified(char *line,const char *user,
                             EVP_PKEY *alice_pub,EVP_PKEY *bob_pub,KeyState *ks) {
 if(strncmp(line,"FROM ",5)!=0){printf("%s\n> ",line);return;}
 char *from=line+5,*stamp=strchr(from,' ');
 if(!stamp){puts("[REJECTED malformed message]");return;}*stamp++=0;
 char *sighex=strchr(stamp,' ');
 if(!sighex){puts("[REJECTED malformed message]");return;}*sighex++=0;
 char *body=strchr(sighex,' ');
 if(!body){puts("[REJECTED malformed message]");return;}*body++=0;
 EVP_PKEY *peer=!strcmp(from,"alice")?alice_pub:!strcmp(from,"bob")?bob_pub:NULL;
 unsigned char sig[SIG_LEN],transcript[MAX_LINE+128];size_t n=0;
 if(!peer || !fromhex(sighex,sig,SIG_LEN) ||
    !signed_message(from,user,stamp,body,transcript,sizeof(transcript),&n) ||
    !ed_verify(peer,transcript,n,sig)){
    printf("[REJECTED invalid signature from %s]\n> ",from);return;
 }
 if(strncmp(body,"E7:",3)!=0){puts("[REJECTED unencrypted message]\n> ");return;}
 if(!ks->established || strcmp(ks->established_peer,from)){
    puts("[REJECTED no active encrypted session]\n> ");return;
 }
 char *ctr=body+3,*noncehex=strchr(ctr,':');if(!noncehex){puts("[REJECTED malformed ciphertext]");return;}
 *noncehex++=0;char *taghex=strchr(noncehex,':');if(!taghex){puts("[REJECTED malformed ciphertext]");return;}
 *taghex++=0;char *cipherhex=strchr(taghex,':');if(!cipherhex){puts("[REJECTED malformed ciphertext]");return;}
 *cipherhex++=0;
 if(!*ctr || strlen(ctr)>20 || (strlen(ctr)>1 && *ctr=='0')){puts("[REJECTED counter]");return;}
 for(char *p=ctr;*p;p++)if(*p<'0'||*p>'9'){puts("[REJECTED counter]");return;}
 errno=0;char *last=NULL;uint64_t counter=strtoull(ctr,&last,10);
 if(errno || !last || *last || counter!=ks->recv_count){puts("[REJECTED replay/out-of-order message]");return;}
 size_t clen=strlen(cipherhex)/2;
 if(!clen || strlen(cipherhex)!=2*clen || clen>MAX_LINE/2){puts("[REJECTED ciphertext length]");return;}
 unsigned char nonce[12],tag[16],cipher[MAX_LINE/2],plain[MAX_LINE/2+1];
 if(!fromhex(noncehex,nonce,12)||!fromhex(taghex,tag,16)||!fromhex(cipherhex,cipher,clen)){
    puts("[REJECTED ciphertext encoding]");return;
 }
 unsigned char key[32],next[32],aad[256];size_t aadlen=0;
 int ok=ratchet_kdf(ks->recv_chain,"message",key) && ratchet_kdf(ks->recv_chain,"next",next) &&
    message_aad(from,user,stamp,ctr,aad,sizeof(aad),&aadlen) &&
    aead_crypt(0,key,nonce,aad,aadlen,cipher,clen,plain,tag);
 OPENSSL_cleanse(key,sizeof(key));
 if(!ok){OPENSSL_cleanse(next,sizeof(next));puts("[REJECTED authentication/tag failure]");return;}
 memcpy(ks->recv_chain,next,32);OPENSSL_cleanse(next,sizeof(next));ks->recv_count++;
 plain[clen]=0;
 if(memchr(plain,0,clen)){puts("[REJECTED binary text]");return;}
 printf("[E2EE VERIFIED %s] %s %s\n> ",from,stamp,plain);
 OPENSSL_cleanse(plain,sizeof(plain));
}
static int read_messages(SSL *ssl,char *line,size_t *used,int *overflow,int *state,
                         EVP_PKEY *key,const char *user,EVP_PKEY *alice_pub,EVP_PKEY *bob_pub,KeyState *ks) {
    char buf[1024];size_t n=0;
    int ok=SSL_read_ex(ssl,buf,sizeof(buf),&n);
    if (ok!=1) return -1;
    for (size_t i=0;i<n;i++) {
        if (buf[i]=='\n') {
            if (*overflow) { fprintf(stderr,"Server line too long\n"); return -1; }
            if (*used && line[*used-1]=='\r') --*used;
            line[*used]=0;
            if (*state==0) {
                unsigned char nonce[NONCE_LEN],msg[128],sig[SIG_LEN];
                size_t msglen=0;
                if (strncmp(line,"CHALLENGE ",10)!=0 ||
                    !fromhex(line+10,nonce,NONCE_LEN) ||
                    !auth_message(user,nonce,msg,sizeof(msg),&msglen) ||
                    !ed_sign(key,msg,msglen,sig)) {
                    fprintf(stderr,"Invalid authentication challenge: %s\n",line);
                    return -1;
                }
                char hex[SIG_LEN*2+1],out[160];
                tohex(sig,SIG_LEN,hex);
                snprintf(out,sizeof(out),"AUTH %s\n",hex);
                if (send_line(ssl,out)<0)return -1;
                *state=1;
            } else if (*state==1) {
                printf("%s\n",line);
                if (strncmp(line,"OK Logged in as ",16)!=0)return -1;
                *state=2;
                printf("Enter: recipient message (or QUIT)\n> ");
            } else {
                if(!strncmp(line,"KEYFROM ",8))key_receive(ssl,line,user,key,alice_pub,bob_pub,ks);
                else display_verified(line,user,alice_pub,bob_pub,ks);
            }
            fflush(stdout);
            *used=0; *overflow=0;
        } else if (!*overflow) {
            if (*used+1<MAX_LINE) line[(*used)++]=buf[i];
            else *overflow=1;
        }
    }
    return 0;
}
int main(int argc,char **argv) {
    if (argc!=7) {
        fprintf(stderr,"Usage: %s HOST USER identity.key ca.crt alice.pub bob.pub\n",argv[0]);return 1;
    }
    EVP_PKEY *identity=load_key(argv[3],1);
    if (!identity) {fprintf(stderr,"Invalid Ed25519 private identity key\n");return 1;}
    EVP_PKEY *alice_pub=load_key(argv[5],0),*bob_pub=load_key(argv[6],0);
    if (!alice_pub || !bob_pub) {fprintf(stderr,"Missing trusted peer public keys\n");return 1;}
    SSL_CTX *ctx=SSL_CTX_new(TLS_client_method());
    if (!ctx || SSL_CTX_set_min_proto_version(ctx,TLS1_3_VERSION)!=1 ||
        SSL_CTX_set_max_proto_version(ctx,TLS1_3_VERSION)!=1 ||
        SSL_CTX_load_verify_locations(ctx,argv[4],NULL)!=1) {
        ERR_print_errors_fp(stderr);return 1;
    }
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
    int fd=connect_host(argv[1]);
    if (fd<0) { perror("connect");return 1; }
    SSL *ssl=SSL_new(ctx);
    if (!ssl || SSL_set_fd(ssl,fd)!=1) { ERR_print_errors_fp(stderr);return 1; }
    /* IP literals require IP SAN; hostnames require DNS SAN. */
    unsigned char address[16];
    if (inet_pton(AF_INET,argv[1],address)==1 ||
        inet_pton(AF_INET6,argv[1],address)==1) {
        if (SSL_set1_host(ssl,NULL)!=1 ||
            X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl),argv[1])!=1) {
            fprintf(stderr,"IP verification setup failed\n");return 1;
        }
    } else if (SSL_set1_host(ssl,argv[1])!=1) {
        fprintf(stderr,"Hostname verification setup failed\n");return 1;
    }
    if (SSL_connect(ssl)!=1 || SSL_get_verify_result(ssl)!=X509_V_OK) {
        fprintf(stderr,"TLS handshake/certificate verification failed\n");
        ERR_print_errors_fp(stderr);return 1;
    }
    printf("TLS: %s; certificate verified for %s\n",SSL_get_version(ssl),argv[1]);
    char out[MAX_LINE+128];
    int n=snprintf(out,sizeof(out),"HELLO %s\n",argv[2]);
    if (n<0 || (size_t)n>=sizeof(out) || send_line(ssl,out)<0) {
        fprintf(stderr,"Login send failed\n");return 1;
    }
    char line[MAX_LINE];size_t used=0;int overflow=0,auth_state=0;
    KeyState ks={0};
    struct pollfd fds[2]={{.fd=STDIN_FILENO,.events=POLLIN},
                          {.fd=fd,.events=POLLIN}};
    int done=0;
    while (!done) {
        int ready=SSL_pending(ssl)>0 ? 1 : poll(fds,2,-1);
        if (ready<0) { if(errno==EINTR)continue;perror("poll");break; }
        if (SSL_pending(ssl)>0 || (fds[1].revents & POLLIN)) {
            if (read_messages(ssl,line,&used,&overflow,&auth_state,identity,argv[2],alice_pub,bob_pub,&ks)<0) {
                fprintf(stderr,"Server disconnected or TLS read failed\n");break;
            }
        }
        if (fds[1].revents & (POLLERR|POLLHUP|POLLNVAL)) break;
        if (auth_state==2 && (fds[0].revents & POLLIN)) {
            char input[MAX_LINE];
            if (!fgets(input,sizeof(input),stdin)) break;
            size_t len=strlen(input);
            if (len && input[len-1]!='\n' && !feof(stdin)) {
                int ch;while ((ch=getchar())!='\n' && ch!=EOF) {}
                fprintf(stderr,"Input too long\n> ");continue;
            }
            input[strcspn(input,"\r\n")]=0;
            if (!strcmp(input,"QUIT")) { send_line(ssl,"QUIT\n");break; }
            if (!strncmp(input,"/key ",5)) {
                if(!key_initiate(ssl,identity,argv[2],input+5,&ks))fprintf(stderr,"Key initiation failed\n");
                continue;
            }
            char *body=strchr(input,' ');
            if (!body) { fprintf(stderr,"Usage: recipient message\n> ");continue; }
            *body++=0;while (*body==' ') ++body;
            if (!*input || !*body) { fprintf(stderr,"Usage: recipient message\n> ");continue; }
            char stamp[32];
            if (timestamp(stamp,sizeof(stamp))<0) break;
            if(!ks.established || strcmp(ks.established_peer,input)){
                fprintf(stderr,"No established E2EE session with %s; use /key %s first\n> ",input,input);continue;
            }
            char ctr[32],noncehex[25],taghex[33],bodyhex[MAX_LINE],encrypted[MAX_LINE];
            snprintf(ctr,sizeof(ctr),"%" PRIu64,ks.send_count);
            unsigned char nonce[12],tag[16],keybytes[32],next[32],aad[256];size_t aadlen=0;
            size_t blen=strlen(body);unsigned char cipher[MAX_LINE];
            if(blen>1200 || RAND_bytes(nonce,sizeof(nonce))!=1 ||
               !ratchet_kdf(ks.send_chain,"message",keybytes) ||
               !ratchet_kdf(ks.send_chain,"next",next) ||
               !message_aad(argv[2],input,stamp,ctr,aad,sizeof(aad),&aadlen) ||
               !aead_crypt(1,keybytes,nonce,aad,aadlen,(unsigned char*)body,blen,cipher,tag)){
                OPENSSL_cleanse(keybytes,sizeof(keybytes));fprintf(stderr,"Encryption failed or message too long\n> ");continue;
            }
            OPENSSL_cleanse(keybytes,sizeof(keybytes));
            tohex(nonce,12,noncehex);tohex(tag,16,taghex);tohex(cipher,blen,bodyhex);
            int ez=snprintf(encrypted,sizeof(encrypted),"E7:%s:%s:%s:%s",ctr,noncehex,taghex,bodyhex);
            if(ez<0 || (size_t)ez>=sizeof(encrypted)){
                OPENSSL_cleanse(next,sizeof(next));fprintf(stderr,"Encrypted message too long\n> ");continue;
            }
            body=encrypted;
            unsigned char transcript[MAX_LINE+128],sig[SIG_LEN];size_t tlen=0;
            if (!signed_message(argv[2],input,stamp,body,transcript,sizeof(transcript),&tlen) ||
                !ed_sign(identity,transcript,tlen,sig)) {
                fprintf(stderr,"Message signing failed\n> ");continue;
            }
            char sighex[SIG_LEN*2+1];tohex(sig,SIG_LEN,sighex);
            n=snprintf(out,sizeof(out),"MSG %s %s %s %s\n",input,stamp,sighex,body);
            if (n<0 || n>=MAX_LINE) { fprintf(stderr,"Message too long\n> ");continue; }
            if (send_line(ssl,out)<0) { fprintf(stderr,"TLS write failed\n");break; }
            memcpy(ks.send_chain,next,32);OPENSSL_cleanse(next,sizeof(next));ks.send_count++;
        }
        if (fds[0].revents & (POLLERR|POLLHUP|POLLNVAL)) done=1;
    }
    EVP_PKEY_free(ks.pending);OPENSSL_cleanse(ks.session_key,sizeof(ks.session_key));
    OPENSSL_cleanse(ks.send_chain,sizeof(ks.send_chain));OPENSSL_cleanse(ks.recv_chain,sizeof(ks.recv_chain));
    SSL_shutdown(ssl);SSL_free(ssl);close(fd);SSL_CTX_free(ctx);EVP_PKEY_free(identity);EVP_PKEY_free(alice_pub);EVP_PKEY_free(bob_pub);
    return 0;
}
