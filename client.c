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
#include "identity.h"

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
static int read_messages(SSL *ssl,char *line,size_t *used,int *overflow,int *state, EVP_PKEY *key, const char *user) {
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
                printf("%s\n> ",line);
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
    if (argc!=5) {
        fprintf(stderr,"Usage: %s HOST USER identity.key ca.crt\n",argv[0]);return 1;
    }
    EVP_PKEY *identity=load_key(argv[3],1);
    if (!identity) {fprintf(stderr,"Invalid Ed25519 private identity key\n");return 1;}
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
    struct pollfd fds[2]={{.fd=STDIN_FILENO,.events=POLLIN},
                          {.fd=fd,.events=POLLIN}};
    int done=0;
    while (!done) {
        int ready=SSL_pending(ssl)>0 ? 1 : poll(fds,2,-1);
        if (ready<0) { if(errno==EINTR)continue;perror("poll");break; }
        if (SSL_pending(ssl)>0 || (fds[1].revents & POLLIN)) {
            if (read_messages(ssl,line,&used,&overflow,&auth_state,identity,argv[2])<0) {
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
            char *body=strchr(input,' ');
            if (!body) { fprintf(stderr,"Usage: recipient message\n> ");continue; }
            *body++=0;while (*body==' ') ++body;
            if (!*input || !*body) { fprintf(stderr,"Usage: recipient message\n> ");continue; }
            char stamp[32];
            if (timestamp(stamp,sizeof(stamp))<0) break;
            n=snprintf(out,sizeof(out),"MSG %s %s %s\n",input,stamp,body);
            if (n<0 || n>=MAX_LINE) { fprintf(stderr,"Message too long\n> ");continue; }
            if (send_line(ssl,out)<0) { fprintf(stderr,"TLS write failed\n");break; }
        }
        if (fds[0].revents & (POLLERR|POLLHUP|POLLNVAL)) done=1;
    }
    SSL_shutdown(ssl);SSL_free(ssl);close(fd);SSL_CTX_free(ctx);EVP_PKEY_free(identity);
    return 0;
}
