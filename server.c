/*
 * TIM TLS relay server.
 *
 * Authenticates connected users and forwards protocol frames. End-to-end
 * message decryption belongs to the clients, not this relay. Each connection
 * has one worker responsible for its SSL I/O; queued outgoing frames are
 * synchronized across workers.
 */
#define _POSIX_C_SOURCE 200809L
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ctype.h>
#include "keyexchange.h"

#define PORT "5555"
#define MAX_LINE 4096
#define MAX_USER 64
#define MAX_QUEUE_BYTES (1024 * 1024)

typedef struct Message {
    struct Message *next;
    size_t len, off;
    char data[];
} Message;
typedef struct Client {
    struct Client *next;
    SSL *ssl;
    int fd, wake[2], authenticated, challenged;
    unsigned char nonce[NONCE_LEN];
    char user[MAX_USER];
    pthread_mutex_t mu;
    Message *head, *tail;
    size_t queued_bytes;
} Client;
static Client *clients;
static pthread_mutex_t clients_mu = PTHREAD_MUTEX_INITIALIZER;
static SSL_CTX *tls_ctx;

static int nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL);
    return flags < 0 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
static void notify(Client *c) {
    char b = 'x';
    ssize_t n = write(c->wake[1], &b, 1);
    (void)n; /* EAGAIN means already readable */
}
/* Cross-thread delivery queue.
 *
 * The sender's worker can enqueue a frame for another connection, but only
 * the destination worker may perform SSL_write_ex on that connection's SSL.
 * Queue mutation is protected by c->mu; the wake pipe interrupts the worker's
 * poll so it can flush output promptly. MAX_QUEUE_BYTES bounds memory use if
 * a destination reads too slowly. Enqueueing means accepted for forwarding,
 * not cryptographically delivered to the destination application. */
static int enqueue(Client *c, const char *s) {
    size_t len = strlen(s);
    Message *m = malloc(sizeof(*m) + len);
    if (!m) return -1;
    m->next = NULL; m->len = len; m->off = 0;
    memcpy(m->data, s, len);
    pthread_mutex_lock(&c->mu);
    if (len > MAX_QUEUE_BYTES - c->queued_bytes) {
        pthread_mutex_unlock(&c->mu); free(m); return -1;
    }
    if (c->tail) c->tail->next = m; else c->head = m;
    c->tail = m; c->queued_bytes += len;
    pthread_mutex_unlock(&c->mu);
    notify(c);
    return 0;
}
static int has_output(Client *c) {
    pthread_mutex_lock(&c->mu);
    int yes = c->head != NULL;
    pthread_mutex_unlock(&c->mu);
    return yes;
}
/* Detach a disconnected client from the shared client registry. */
static void remove_client(Client *c) {
    pthread_mutex_lock(&clients_mu);
    Client **p = &clients;
    while (*p && *p != c) p = &(*p)->next;
    if (*p) *p = c->next;
    pthread_mutex_unlock(&clients_mu);
}
static int valid_time(const char *s) {
    if (strlen(s) != 20) return 0;
    for (int i = 0; i < 20; ++i) {
        char sep = i == 4 || i == 7 ? '-' : i == 10 ? 'T' :
                   i == 13 || i == 16 ? ':' : i == 19 ? 'Z' : 0;
        if (sep ? s[i] != sep : !isdigit((unsigned char)s[i])) return 0;
    }
    return 1;
}
static EVP_PKEY *alice_key, *bob_key;
static EVP_PKEY *identity_key(const char *user) {
    if (!strcmp(user,"alice")) return alice_key;
    if (!strcmp(user,"bob")) return bob_key;
    return NULL;
}
/* Relay opaque ciphertext without participating in end-to-end decryption.
 *
 * The sender identity comes from the authenticated TLS connection, not from
 * an untrusted field in the MSG command. The relay attaches that identity to
 * the forwarded frame; the recipient independently checks the sender's
 * Ed25519 signature and AES-GCM tag. The server neither derives ratchet keys
 * nor produces end-to-end delivery acknowledgements. */
static int forward(const char *from, const char *to,
                   const char *stamp, const char *body, const char *signature) {
    char out[MAX_LINE + MAX_USER + 64];
    int n = snprintf(out, sizeof(out), "FROM %s %s %s %s\n", from, stamp, signature, body);
    if (n < 0 || (size_t)n >= sizeof(out)) return 0;
    int count = 0;
    pthread_mutex_lock(&clients_mu);
    for (Client *c = clients; c; c = c->next)
        if (c->authenticated && !strcmp(c->user, to) && enqueue(c, out) == 0)
            ++count;
    pthread_mutex_unlock(&clients_mu);
    return count;
}
/* Relay protocol state machine.
 *
 * HELLO initiates a random challenge; AUTH proves possession of the user's
 * Ed25519 private key by signing the challenge-bound transcript. KEY forwards
 * peer handshake frames. MSG forwards a signed, opaque encrypted envelope.
 * QUIT ends the connection. Syntax checks and TLS transport authentication
 * are not substitutes for client-side end-to-end verification.
 *
 * This Stage 8H implementation deliberately supports two configured users,
 * alice and bob; it is not yet a general account or key-directory service. */
static int command(Client *c, char *line) {
    if (!strncmp(line,"HELLO ",6)) {
        const char *u=line+6;
        if (c->authenticated || c->challenged || strlen(u)>=MAX_USER || !identity_key(u)) {
            enqueue(c,"ERR Invalid identity request\n"); return 0;
        }
        if (RAND_bytes(c->nonce,NONCE_LEN)!=1) {
            enqueue(c,"ERR Random generator failure\n");return 1;
        }
        strcpy(c->user,u);c->challenged=1;
        char hex[NONCE_LEN*2+1],out[96];
        tohex(c->nonce,NONCE_LEN,hex);
        snprintf(out,sizeof(out),"CHALLENGE %s\n",hex);
        enqueue(c,out);
    } else if (!strncmp(line,"AUTH ",5)) {
        unsigned char sig[SIG_LEN],msg[128];size_t msglen=0;
        if (!c->challenged || c->authenticated ||
            !fromhex(line+5,sig,SIG_LEN) ||
            !auth_message(c->user,c->nonce,msg,sizeof(msg),&msglen) ||
            !ed_verify(identity_key(c->user),msg,msglen,sig)) {
            enqueue(c,"ERR Authentication failed\n");return 1;
        }
        c->challenged=0;
        memset(c->nonce,0,sizeof(c->nonce));
        pthread_mutex_lock(&clients_mu);
        c->authenticated=1;
        pthread_mutex_unlock(&clients_mu);
        char out[128];snprintf(out,sizeof(out),"OK Logged in as %s\n",c->user);
        enqueue(c,out);
        printf("Authenticated Ed25519 identity: %s (fd=%d)\n",c->user,c->fd);
    } else if (!strncmp(line,"KEY ",4)) {
        if (!c->authenticated) { enqueue(c,"ERR Please log in first\n");return 0; }
        /* KEY recipient INIT|REPLY sessionid initpub resppub signature */
        char *fields[6]={0};char *save=NULL;
        for (int i=0;i<6;i++) fields[i]=strtok_r(i?NULL:line+4," ",&save);
        if (!fields[5] || strtok_r(NULL," ",&save) || !identity_key(fields[0]) ||
            (strcmp(fields[1],"INIT") && strcmp(fields[1],"REPLY") && strcmp(fields[1],"RINIT") && strcmp(fields[1],"RREPLY") && strcmp(fields[1],"RESET")) ||
            strlen(fields[2])!=SID_LEN*2 || strlen(fields[3])!=DH_LEN*2 ||
            ((strcmp(fields[1],"INIT") && strcmp(fields[1],"RINIT") && strcmp(fields[1],"RESET")) ? strlen(fields[4])!=DH_LEN*2 : strcmp(fields[4],"-")) ||
            strlen(fields[5])!=SIG_LEN*2) {
            enqueue(c,"ERR Invalid key exchange\n");return 0;
        }
        unsigned char sid[SID_LEN],pub[DH_LEN],replypub[DH_LEN],sig[SIG_LEN];
        if(!fromhex(fields[2],sid,SID_LEN) || !fromhex(fields[3],pub,DH_LEN) ||
           (strcmp(fields[4],"-") && !fromhex(fields[4],replypub,DH_LEN)) ||
           !fromhex(fields[5],sig,SIG_LEN)) {
            enqueue(c,"ERR Invalid key encoding\n");return 0;
        }
        char out[MAX_LINE];int n=snprintf(out,sizeof(out),"KEYFROM %s %s %s %s %s %s\n",
            c->user,fields[1],fields[2],fields[3],fields[4],fields[5]);
        int count=0;
        if(n>0 && (size_t)n<sizeof(out)) {
            pthread_mutex_lock(&clients_mu);
            for(Client *other=clients;other;other=other->next)
                if(other->authenticated && !strcmp(other->user,fields[0]) && enqueue(other,out)==0)count++;
            pthread_mutex_unlock(&clients_mu);
        }
        enqueue(c,count?"KEYSENT\n":"ERR Peer not connected\n");
    } else if (!strcmp(line,"QUIT")) {
        enqueue(c,"OK Goodbye\n"); return 1;
    } else if (!strncmp(line,"MSG ",4)) {
        if (!c->authenticated) { enqueue(c,"ERR Please log in first\n"); return 0; }
        char *to = line+4, *stamp = strchr(to,' ');
        if (!stamp) { enqueue(c,"ERR Invalid message\n"); return 0; }
        *stamp++ = 0;
        char *signature = strchr(stamp,' ');
        if (!signature) { enqueue(c,"ERR Invalid message\n"); return 0; }
        *signature++ = 0;
        char *body = strchr(signature,' ');
        if (!body) { enqueue(c,"ERR Invalid message\n"); return 0; }
        *body++ = 0;
        while (*body == ' ') ++body;
        if (!*to || strlen(to)>=MAX_USER || !valid_time(stamp) || strlen(signature)!=SIG_LEN*2 || !*body) {
            enqueue(c,"ERR Invalid message\n"); return 0;
        }
        unsigned char decoded[SIG_LEN];
        if (!fromhex(signature,decoded,SIG_LEN)) { enqueue(c,"ERR Invalid signature encoding\n"); return 0; }
        enqueue(c,forward(c->user,to,stamp,body,signature) ? "SENT\n" : "ERR User not connected\n");
    } else enqueue(c,"ERR Unknown command\n");
    return 0;
}
/* Per-connection worker and OpenSSL I/O ownership.
 *
 * Only this thread calls SSL_read_ex/SSL_write_ex on c->ssl, avoiding
 * concurrent use of a single SSL object. Other workers append to its output
 * queue and wake it through a pipe. After the TLS handshake the socket is
 * nonblocking, so the poll loop must handle short reads/writes and OpenSSL's
 * WANT_READ/WANT_WRITE transitions without losing buffered frames. */
static void *worker(void *arg) {
    Client *c = arg;
    char input[MAX_LINE]; size_t used = 0;
    int overflow = 0, quitting = 0, failed = 0;
    int want_read_for_write = 0, want_write_for_read = 0;
    int read_blocked = 0;
    /* Handshake on a blocking socket, before entering the event loop. */
    if (SSL_accept(c->ssl) != 1) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    if (nonblock(c->fd) < 0) goto cleanup;
    printf("TLS 1.3 established (fd=%d)\n", c->fd);
    for (;;) {
        if (quitting && !has_output(c)) break;
        struct pollfd fds[2] = {{.fd=c->fd}, {.fd=c->wake[0],.events=POLLIN}};
        int output = has_output(c);
        if (!quitting && !want_write_for_read) fds[0].events |= POLLIN;
        if (!quitting && want_write_for_read) fds[0].events |= POLLOUT;
        if (output && !want_read_for_write) fds[0].events |= POLLOUT;
        if (output && want_read_for_write) fds[0].events |= POLLIN;
        /* SSL may have decrypted bytes buffered internally. */
        int buffered = !quitting && !read_blocked && SSL_pending(c->ssl)>0;
        int r = buffered ? 1 : poll(fds,2,-1);
        if (r < 0) { if (errno==EINTR) continue; break; }
        if (fds[1].revents & POLLIN) {
            char buf[128]; while (read(c->wake[0],buf,sizeof(buf))>0) {}
        }
        if (fds[0].revents & (POLLERR|POLLNVAL)) break;
        if (fds[0].revents & POLLHUP) break;
        if (!quitting && (buffered || (fds[0].revents &
              (want_write_for_read ? POLLOUT : POLLIN)))) {
            char buf[1024]; size_t n = 0;
            int ok = SSL_read_ex(c->ssl,buf,sizeof(buf),&n);
            if (ok == 1) {
                want_write_for_read=0; read_blocked=0;
                for (size_t i=0;i<n;i++) {
                    char ch=buf[i];
                    if (ch=='\n') {
                        if (overflow) enqueue(c,"ERR Line too long\n");
                        else {
                            if (used && input[used-1]=='\r') --used;
                            input[used]=0;
                            if (command(c,input)) { quitting=1; break; }
                        }
                        used=0; overflow=0;
                    } else if (!overflow) {
                        if (used+1<sizeof(input)) input[used++]=ch;
                        else overflow=1;
                    }
                }
            } else {
                int e=SSL_get_error(c->ssl,ok);
                if (e==SSL_ERROR_WANT_READ) { want_write_for_read=0; read_blocked=1; }
                else if (e==SSL_ERROR_WANT_WRITE) { want_write_for_read=1; read_blocked=1; }
                else { failed=1; break; }
            }
        }
        if (has_output(c) && (fds[0].revents &
            (want_read_for_write ? POLLIN : POLLOUT))) {
            pthread_mutex_lock(&c->mu);
            Message *m=c->head;
            /* Queue is stable under lock; only owner advances the head. */
            if (m) {
                size_t written=0;
                int ok=SSL_write_ex(c->ssl,m->data+m->off,m->len-m->off,&written);
                if (ok==1) {
                    want_read_for_write=0;
                    m->off+=written;
                    if (m->off==m->len) {
                        c->head=m->next;
                        if (!c->head) c->tail=NULL;
                        c->queued_bytes-=m->len;
                        free(m);
                    }
                } else {
                    int e=SSL_get_error(c->ssl,ok);
                    if (e==SSL_ERROR_WANT_READ) want_read_for_write=1;
                    else if (e==SSL_ERROR_WANT_WRITE) want_read_for_write=0;
                    else failed=1;
                }
            }
            pthread_mutex_unlock(&c->mu);
            if (failed) break;
        }
    }
cleanup:
    remove_client(c);
    if (!failed && quitting) SSL_shutdown(c->ssl);
    SSL_free(c->ssl);
    close(c->fd); close(c->wake[0]); close(c->wake[1]);
    Message *m=c->head;
    while (m) { Message *next=m->next; free(m); m=next; }
    pthread_mutex_destroy(&c->mu);
    free(c);
    return NULL;
}
int main(int argc,char **argv) {
    if (argc!=5) {
        fprintf(stderr,"Usage: %s server.crt server.key alice.pub bob.pub\n",argv[0]); return 1;
    }
    alice_key=load_key(argv[3],0);
    bob_key=load_key(argv[4],0);
    if (!alice_key || !bob_key) {
        fprintf(stderr,"Could not load Ed25519 public identity keys\n");return 1;
    }
    signal(SIGPIPE,SIG_IGN);
    tls_ctx=SSL_CTX_new(TLS_server_method());
    if (!tls_ctx || SSL_CTX_set_min_proto_version(tls_ctx,TLS1_3_VERSION)!=1 ||
        SSL_CTX_set_max_proto_version(tls_ctx,TLS1_3_VERSION)!=1 ||
        SSL_CTX_use_certificate_file(tls_ctx,argv[1],SSL_FILETYPE_PEM)!=1 ||
        SSL_CTX_use_PrivateKey_file(tls_ctx,argv[2],SSL_FILETYPE_PEM)!=1 ||
        SSL_CTX_check_private_key(tls_ctx)!=1) {
        ERR_print_errors_fp(stderr); return 1;
    }
    struct addrinfo hints={0},*res=NULL,*p;
    hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM; hints.ai_flags=AI_PASSIVE;
    int e=getaddrinfo(NULL,PORT,&hints,&res);
    if (e) { fprintf(stderr,"getaddrinfo: %s\n",gai_strerror(e)); return 1; }
    int listener=-1,yes=1;
    for (p=res;p;p=p->ai_next) {
        listener=socket(p->ai_family,p->ai_socktype,p->ai_protocol);
        if (listener<0) continue;
        setsockopt(listener,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
        if (bind(listener,p->ai_addr,p->ai_addrlen)==0) break;
        close(listener); listener=-1;
    }
    freeaddrinfo(res);
    if (listener<0 || listen(listener,32)<0) { perror("listen/bind"); return 1; }
    printf("TLS server listening on port %s\n",PORT);
    for (;;) {
        int fd=accept(listener,NULL,NULL);
        if (fd<0) { if (errno==EINTR) continue; perror("accept"); continue; }
        Client *c=calloc(1,sizeof(*c));
        if (!c) { close(fd); continue; }
        c->fd=fd;
        if (pthread_mutex_init(&c->mu,NULL)!=0) { close(fd); free(c); continue; }
        if (pipe(c->wake)<0) { pthread_mutex_destroy(&c->mu); close(fd); free(c); continue; }
        if (nonblock(c->wake[0])<0 || nonblock(c->wake[1])<0 ||
            !(c->ssl=SSL_new(tls_ctx)) || SSL_set_fd(c->ssl,fd)!=1) {
            if (c->ssl) SSL_free(c->ssl);
            close(c->wake[0]);close(c->wake[1]);close(fd);
            pthread_mutex_destroy(&c->mu);free(c);continue;
        }
        pthread_mutex_lock(&clients_mu); c->next=clients; clients=c;
        pthread_mutex_unlock(&clients_mu);
        pthread_t tid;
        int rc=pthread_create(&tid,NULL,worker,c);
        if (rc) {
            fprintf(stderr,"pthread_create: %s\n",strerror(rc));
            remove_client(c); SSL_free(c->ssl);close(fd);
            close(c->wake[0]);close(c->wake[1]);pthread_mutex_destroy(&c->mu);free(c);
        } else pthread_detach(tid);
    }
}
