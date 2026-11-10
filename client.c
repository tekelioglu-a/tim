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
#include "double_ratchet.h"
#include <limits.h>
#include <termios.h>
#include <signal.h>

#define PORT "5555"
#define MAX_LINE 4096
#define QUEUE_MAX 16
static int debug_mode=0;
#define DEBUG(...) do {if(debug_mode)fprintf(stderr,__VA_ARGS__);}while(0)

static struct termios saved_tty;
static int saved_tty_valid=0;
static void restore_tty(void){if(saved_tty_valid)tcsetattr(STDIN_FILENO,TCSANOW,&saved_tty);}
static void tty_signal(int sig){restore_tty();signal(sig,SIG_DFL);raise(sig);}

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
 char established_peer[64];
 DRState ratchet;
 int established;
 char queued[QUEUE_MAX][1201];
 int qcount;
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
static int send_encrypted(SSL *ssl,EVP_PKEY *identity,const char *from,const char *to,
 DRState *ratchet,const unsigned char *body,size_t blen) {
 if(blen>1200 || !ratchet->has_cks)return 0;
 char stamp[32],headerhex[81],noncehex[25],taghex[33],bodyhex[2401],encrypted[2700],out[3200];
 unsigned char header[40],nonce[12],tag[16],cipher[1200],sig[SIG_LEN],transcript[3200];size_t tlen=0;
 if(timestamp(stamp,sizeof(stamp))<0 || !dr_encrypt(ratchet,from,to,stamp,body,blen,header,nonce,tag,cipher))return 0;
 tohex(header,40,headerhex);tohex(nonce,12,noncehex);tohex(tag,16,taghex);tohex(cipher,blen,bodyhex);
 int z=snprintf(encrypted,sizeof(encrypted),"D8:%s:%s:%s:%s",headerhex,noncehex,taghex,bodyhex);
 if(z<0 || (size_t)z>=sizeof(encrypted) || !signed_message(from,to,stamp,encrypted,transcript,sizeof(transcript),&tlen) ||
 !ed_sign(identity,transcript,tlen,sig))return 0;
 char sighex[SIG_LEN*2+1];tohex(sig,SIG_LEN,sighex);
 z=snprintf(out,sizeof(out),"MSG %s %s %s %s\n",to,stamp,sighex,encrypted);
 return z>0 && (size_t)z<sizeof(out) && send_line(ssl,out)==0;
}
static void flush_queue(SSL *ssl,EVP_PKEY *identity,const char *user,KeyState *ks){
 if(!ks->established || !ks->ratchet.has_cks)return;
 int done=0;
 while(done<ks->qcount){
  const char *msg=ks->queued[done];
  if(!send_encrypted(ssl,identity,user,ks->established_peer,&ks->ratchet,(const unsigned char*)msg,strlen(msg))){
   fprintf(stderr,"[ERROR] Queued message could not be encrypted or sent\n");break;
  }
  DEBUG("[DEBUG] Queued encrypted message submitted to relay for %s\n",ks->established_peer);done++;
 }
 if(done){for(int i=done;i<ks->qcount;i++)memcpy(ks->queued[i-done],ks->queued[i],sizeof(ks->queued[0]));ks->qcount-=done;}
}
static int queue_message(KeyState *ks,const char *body){
 if(strlen(body)>1200 || ks->qcount>=QUEUE_MAX)return 0;
 strcpy(ks->queued[ks->qcount++],body);return 1;
}
static void key_receive(SSL *ssl,char *line,const char *user,EVP_PKEY *identity,
 EVP_PKEY *alice_pub,EVP_PKEY *bob_pub,KeyState *state) {
 char *parts[6],*save=NULL;
 for(int i=0;i<6;i++)parts[i]=strtok_r(i?NULL:line+8," ",&save);
 if(!parts[5] || strtok_r(NULL," ",&save)){puts("[REJECTED malformed KEY]");return;}
 char *from=parts[0],*kind=parts[1],*sid=parts[2],*initpub=parts[3],*resppub=parts[4],*sighex=parts[5];
 EVP_PKEY *peer=!strcmp(from,"alice")?alice_pub:!strcmp(from,"bob")?bob_pub:NULL;
 unsigned char sig[SIG_LEN],sidbytes[SID_LEN],initbytes[DH_LEN],replybytes[DH_LEN],transcript[512];size_t n=0;
 if(!peer || !strcmp(from,user) || (strcmp(kind,"INIT") && strcmp(kind,"REPLY")) ||
    !fromhex(sid,sidbytes,SID_LEN) || !fromhex(initpub,initbytes,DH_LEN) ||
    (!strcmp(kind,"REPLY")?!fromhex(resppub,replybytes,DH_LEN):strcmp(resppub,"-")!=0) ||
    !fromhex(sighex,sig,SIG_LEN) ||
    !dh_transcript(kind,from,user,sid,initpub,resppub,transcript,sizeof(transcript),&n) ||
    !ed_verify(peer,transcript,n,sig)) {puts("[REJECTED unauthenticated KEY]");return;}
 if(!strcmp(kind,"INIT")){
    if(state->established || state->pending){puts("[REJECTED active/pending session]");return;}
    EVP_PKEY *mine=dh_generate();unsigned char mypub[DH_LEN],secret[DH_LEN],key[DH_LEN];char myhex[DH_LEN*2+1];
    if(!mine || !dh_public(mine,mypub)){EVP_PKEY_free(mine);return;}
    tohex(mypub,DH_LEN,myhex);
    int ok=dh_secret(mine,initbytes,secret) && dh_derive_key(secret,from,user,sid,initpub,myhex,key);
    if(ok)ok=dr_init_responder(&state->ratchet,key,mine);
    if(ok)ok=key_send(ssl,identity,user,from,"REPLY",sid,initpub,myhex);
    OPENSSL_cleanse(secret,32);OPENSSL_cleanse(key,32);EVP_PKEY_free(mine);
    if(!ok){dr_free(&state->ratchet);puts("[KEY exchange failed]");return;}
    snprintf(state->established_peer,sizeof(state->established_peer),"%s",from);
    state->established=1;
    DEBUG("[DEBUG /key] Session established with %s (responder); awaiting automatic ratchet bootstrap\n",from);
 } else {
    if(!state->pending || strcmp(state->pending_peer,from) || strcmp(state->sid,sid) || strcmp(state->initpub,initpub)){
      puts("[REJECTED unexpected KEY reply]");return;}
    unsigned char secret[32],key[32];
    int ok=dh_secret(state->pending,replybytes,secret) && dh_derive_key(secret,user,from,sid,initpub,resppub,key);
    if(ok)ok=dr_init_initiator(&state->ratchet,key,replybytes);
    OPENSSL_cleanse(secret,32);OPENSSL_cleanse(key,32);
    EVP_PKEY_free(state->pending);state->pending=NULL;
    if(!ok){puts("[KEY derivation failed]");return;}
    snprintf(state->established_peer,sizeof(state->established_peer),"%s",from);
    state->established=1;
    DEBUG("[DEBUG /key] Session established with %s (initiator)\n",from);
    /* The first encrypted ratchet message is an internal control frame.
       It advances Bob's receive chain and creates his sending chain. */
    const unsigned char bootstrap[1]={1};
    if(!send_encrypted(ssl,identity,user,from,&state->ratchet,bootstrap,1)){
       fprintf(stderr,"[ERROR] Automatic ratchet bootstrap failed\n");return;
    }
    DEBUG("[DEBUG /rekey] Initial automatic DH ratchet bootstrap sent to %s\n",from);
    flush_queue(ssl,identity,user,state);
 }
}
static int key_initiate(SSL *ssl,EVP_PKEY *identity,const char *user,const char *peer,KeyState *state) {
 if((strcmp(peer,"alice") && strcmp(peer,"bob")) || !strcmp(peer,user) || state->pending || state->established)return 0;
 EVP_PKEY *mine=dh_generate();unsigned char pub[32],sid[16];
 if(!mine || !dh_public(mine,pub) || RAND_bytes(sid,16)!=1){EVP_PKEY_free(mine);return 0;}
 char pubhex[65],sidhex[33];tohex(pub,32,pubhex);tohex(sid,16,sidhex);
 if(!key_send(ssl,identity,user,peer,"INIT",sidhex,pubhex,"-")){EVP_PKEY_free(mine);return 0;}
 state->pending=mine;strcpy(state->pending_peer,peer);strcpy(state->sid,sidhex);strcpy(state->initpub,pubhex);
 DEBUG("[DEBUG /key] Sent authenticated X25519 initialization to %s\n",peer);return 1;
}
static void display_verified(SSL *ssl,EVP_PKEY *identity,char *line,const char *user,
                             EVP_PKEY *alice_pub,EVP_PKEY *bob_pub,KeyState *ks) {
 if(strncmp(line,"FROM ",5)!=0){if(!strcmp(line,"KEYSENT")){DEBUG("[DEBUG /key] Server acknowledged key-exchange frame\n");return;}if(!strcmp(line,"SENT")){DEBUG("[DEBUG] Relay accepted outgoing ciphertext (not a delivery receipt)\n");return;}printf("%s\n> ",line);return;}
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
 if(strncmp(body,"D8:",3)!=0){puts("[REJECTED unencrypted message]");return;}
 if(!ks->established || strcmp(ks->established_peer,from)){puts("[REJECTED no active session]");return;}
 char *pieces[4],*save=NULL;
 for(int i=0;i<4;i++)pieces[i]=strtok_r(i?NULL:body+3,":",&save);
 if(!pieces[3] || strtok_r(NULL,":",&save)){puts("[REJECTED malformed ciphertext]");return;}
 size_t clen=strlen(pieces[3])/2;
 if(clen==0 || clen>1200 || strlen(pieces[3])!=2*clen){puts("[REJECTED ciphertext length]");return;}
 unsigned char header[40],nonce[12],tag[16],cipher[1200],plain[1201];
 if(!fromhex(pieces[0],header,40) || !fromhex(pieces[1],nonce,12) ||
    !fromhex(pieces[2],tag,16) || !fromhex(pieces[3],cipher,clen)){
    puts("[REJECTED ciphertext encoding]");return;}
 unsigned char prior_pub[32];int had_prior=ks->ratchet.has_dhr;memcpy(prior_pub,ks->ratchet.dhr,32);
 int was_ready=ks->ratchet.has_cks;
 if(!dr_decrypt(&ks->ratchet,from,user,stamp,header,nonce,tag,cipher,clen,plain)){
    puts("[REJECTED ratchet/authentication/replay]");return;}
 if(had_prior && memcmp(prior_pub,header,32)!=0)DEBUG("[DEBUG /rekey] Automatic DH ratchet transition from %s\n",from);
 if(!was_ready && ks->ratchet.has_cks){
   DEBUG("[DEBUG /rekey] Automatic DH ratchet activated for %s\n",from);
   flush_queue(ssl,identity,user,ks);
 }
 if(clen==1 && plain[0]==1){OPENSSL_cleanse(plain,sizeof(plain));return;}
 plain[clen]=0;
 if(memchr(plain,0,clen)){OPENSSL_cleanse(plain,sizeof(plain));puts("[REJECTED binary text]");return;}
 /* Reject control characters in authenticated peer text: do not execute terminal escapes. */
 for(size_t j=0;j<clen;j++)if(plain[j]<32 || plain[j]==127){
   OPENSSL_cleanse(plain,sizeof(plain));puts("[REJECTED control character in message]");return;
 }
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
                else display_verified(ssl,key,line,user,alice_pub,bob_pub,ks);
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
    if (argc!=7 && argc!=8) {
        fprintf(stderr,"Usage: %s [-d] HOST USER identity.key ca.crt alice.pub bob.pub\n",argv[0]);return 1;
    }
    if(argc==8){
       if(!strcmp(argv[1],"-d")){debug_mode=1;argv++;argc--;}
       else if(!strcmp(argv[7],"-d")){debug_mode=1;argc--;}
       else {fprintf(stderr,"Unknown option: %s\n",argv[7]);return 1;}
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
    /* Read stdin with read(2), never mix poll(2) with buffered fgets(3).
       On terminals disable echo/canonical buffering and redraw the current line
       after asynchronous network output. */
    struct termios oldtty={0};
    int interactive=isatty(STDIN_FILENO), tty_changed=0;
    if(interactive && tcgetattr(STDIN_FILENO,&oldtty)==0){
        struct termios tty=oldtty;
        tty.c_lflag &= (tcflag_t)~(ICANON|ECHO);
        tty.c_cc[VMIN]=1;tty.c_cc[VTIME]=0;
        if(tcsetattr(STDIN_FILENO,TCSANOW,&tty)==0){
            tty_changed=1;saved_tty=oldtty;saved_tty_valid=1;
            atexit(restore_tty);
            signal(SIGINT,tty_signal);signal(SIGTERM,tty_signal);
        }
    }
    char input[MAX_LINE]={0};size_t input_len=0;
    struct pollfd fds[2]={{.fd=STDIN_FILENO,.events=POLLIN},
                          {.fd=fd,.events=POLLIN}};
    int done=0;
    while (!done) {
        fds[0].revents=fds[1].revents=0;
        int ready=SSL_pending(ssl)>0 ? 1 : poll(fds,2,-1);
        if (ready<0) { if(errno==EINTR)continue;perror("poll");break; }
        if (SSL_pending(ssl)>0 || (fds[1].revents & POLLIN)) {
            if(tty_changed && auth_state==2){fputs("\r\033[2K",stdout);fflush(stdout);}
            if (read_messages(ssl,line,&used,&overflow,&auth_state,identity,argv[2],alice_pub,bob_pub,&ks)<0) {
                fprintf(stderr,"Server disconnected or TLS read failed\n");break;
            }
            if(tty_changed && auth_state==2){
                /* Only the bytes actually typed are part of the live input. */
                printf("\r\033[2K> %.*s",(int)input_len,input);fflush(stdout);
            }
        }
        if (fds[1].revents & (POLLERR|POLLHUP|POLLNVAL)) break;
        if (auth_state==2 && (fds[0].revents & POLLIN)) {
            unsigned char ch;
            ssize_t nr=read(STDIN_FILENO,&ch,1);
            if(nr==0){done=1;continue;}
            if(nr<0){if(errno==EINTR)continue;done=1;continue;}
            if(ch==127 || ch==8){
                if(input_len){
                    /* Remove an entire UTF-8 codepoint, not just its final byte. */
                    do { --input_len; } while(input_len && ((unsigned char)input[input_len]&0xc0)==0x80);
                    input[input_len]=0;
                    if(tty_changed){fputs("\r\033[2K> ",stdout);fwrite(input,1,input_len,stdout);fflush(stdout);}
                }
                continue;
            }
            if(ch!='\n' && ch!='\r'){
                if(ch<32 || ch==127)continue; /* Never send terminal control characters. */
                if(input_len+1>=sizeof(input)){
                    fprintf(stderr,"\nInput too long; line cleared\n> ");input_len=0;input[0]=0;continue;
                }
                input[input_len++]=(char)ch;input[input_len]=0;
                if(tty_changed){fputc(ch,stdout);fflush(stdout);}
                continue;
            }
            if(tty_changed){fputc('\n',stdout);fflush(stdout);}
            input[input_len]=0;input_len=0;
            char command[MAX_LINE];
            memcpy(command,input,strlen(input)+1);
            input[0]=0; /* Never redraw the previous command. */
            if(!*command){if(tty_changed){fputs("> ",stdout);fflush(stdout);}continue;}
            if (!strcmp(command,"QUIT")) { send_line(ssl,"QUIT\n");break; }
            if(command[0]=='/') {
                fprintf(stderr,"Commands /key and /rekey are automatic. Type: recipient message\n> ");continue;
            }
            char *body=strchr(command,' ');
            if (!body) { fprintf(stderr,"Usage: recipient message\n> ");continue; }
            *body++=0;while (*body==' ') ++body;
            if (!*command || !*body) { fprintf(stderr,"Usage: recipient message\n> ");continue; }
            if((strcmp(command,"alice") && strcmp(command,"bob")) || !strcmp(command,argv[2])){
                fprintf(stderr,"Unknown recipient\n> ");continue;
            }
            if(ks.established && strcmp(ks.established_peer,command)){
                fprintf(stderr,"[ERROR] This prototype supports only one active peer\n> ");continue;
            }
            if(ks.pending && strcmp(ks.pending_peer,command)){
                fprintf(stderr,"[ERROR] Key exchange already in progress for another peer\n> ");continue;
            }
            if(ks.established && ks.ratchet.has_cks && ks.qcount==0){
                if(!send_encrypted(ssl,identity,argv[2],command,&ks.ratchet,(const unsigned char*)body,strlen(body))){
                    fprintf(stderr,"Encryption failed (maximum message length: 1200 bytes)\n> ");continue;
                }
                DEBUG("[DEBUG] Encrypted message submitted to relay for %s\n",command);
            }else{
                if(!queue_message(&ks,body)){
                    fprintf(stderr,"[ERROR] Message exceeds 1200 bytes or pending queue is full\n> ");continue;
                }
                if(!ks.established && !ks.pending && !key_initiate(ssl,identity,argv[2],command,&ks)){
                    fprintf(stderr,"[ERROR] Automatic key exchange failed\n> ");
                }else{
                    DEBUG("[DEBUG] Queued message for %s (pending=%d)\n",command,ks.qcount);
                }
                if(tty_changed){fputs("> ",stdout);fflush(stdout);}
            }

        }
        if (fds[0].revents & (POLLERR|POLLHUP|POLLNVAL)) done=1;
    }
    if(tty_changed)tcsetattr(STDIN_FILENO,TCSANOW,&oldtty);
    EVP_PKEY_free(ks.pending);dr_free(&ks.ratchet);
    SSL_shutdown(ssl);SSL_free(ssl);close(fd);SSL_CTX_free(ctx);EVP_PKEY_free(identity);EVP_PKEY_free(alice_pub);EVP_PKEY_free(bob_pub);
    return 0;
}
