
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT       5555
#define MAX_LINE   4096
#define MAX_USER   32
#define BACKLOG    20

typedef struct Client {
    int fd;
    int logged_in;
    char username[MAX_USER];
    struct Client *next;
} Client;

static Client *clients = NULL;
static pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Initial hard-coded accounts */
static const struct {
    const char *username;
    const char *password;
} accounts[] = {
    {"alice", "alice"},
    {"bob",   "bob"}
};

#define ACCOUNT_COUNT (sizeof(accounts) / sizeof(accounts[0]))

static int authenticate(const char *user, const char *pass)
{
    for (size_t i = 0; i < ACCOUNT_COUNT; i++) {
        if (strcmp(user, accounts[i].username) == 0 &&
            strcmp(pass, accounts[i].password) == 0)
            return 1;
    }
    return 0;
}

/* Send all bytes, handling partial writes */
static int send_all(int fd, const char *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = send(fd, buf, len, MSG_NOSIGNAL);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }

        if (n == 0)
            return -1;

        buf += n;
        len -= (size_t)n;
    }

    return 0;
}

static int send_line(int fd, const char *line)
{
    return send_all(fd, line, strlen(line));
}

/* Read one newline-terminated message */
static int recv_line(int fd, char *buf, size_t size)
{
    size_t pos = 0;

    while (pos < size - 1) {
        char c;
        ssize_t n = recv(fd, &c, 1, 0);

        if (n == 0)
            return -1;

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }

        if (c == '\n') {
            buf[pos] = '\0';

            if (pos > 0 && buf[pos - 1] == '\r')
                buf[pos - 1] = '\0';

            return 0;
        }

        if (c == '\0')
            return -1;

        buf[pos++] = c;
    }

    return -1; /* Line too long */
}

static void add_client(Client *c)
{
    pthread_mutex_lock(&clients_mutex);

    c->next = clients;
    clients = c;

    pthread_mutex_unlock(&clients_mutex);
}

static void remove_client(Client *c)
{
    pthread_mutex_lock(&clients_mutex);

    Client **p = &clients;

    while (*p && *p != c)
        p = &(*p)->next;

    if (*p == c)
        *p = c->next;

    pthread_mutex_unlock(&clients_mutex);
}

/* Forward a message to all connected sessions of recipient */
static int forward_message(const char *sender,
                           const char *recipient,
                           const char *timestamp,
                           const char *body)
{
    char output[MAX_LINE + MAX_USER + 16];

    int len = snprintf(output, sizeof(output),
                   "FROM %s %s %s\n",
                   sender, timestamp, body);

    if (len < 0 || (size_t)len >= sizeof(output))
        return -1;

    int delivered = 0;

    pthread_mutex_lock(&clients_mutex);

    for (Client *c = clients; c; c = c->next) {
        if (c->logged_in &&
            strcmp(c->username, recipient) == 0) {

            if (send_all(c->fd, output, (size_t)len) == 0)
                delivered++;
        }
    }

    pthread_mutex_unlock(&clients_mutex);

    return delivered;
}

static void *client_thread(void *arg)
{
    Client *c = arg;
    char line[MAX_LINE];
    char username[MAX_USER];
    char password[64];

    printf("Connection established: fd=%d\n", c->fd);

    /* First command must be LOGIN */
    if (recv_line(c->fd, line, sizeof(line)) < 0)
        goto cleanup;

    char extra;

    if (sscanf(line, "LOGIN %31s %63s %c",
               username, password, &extra) != 2 ||
        !authenticate(username, password)) {

        send_line(c->fd, "ERR Authentication failed\n");
        goto cleanup;
    }

    strncpy(c->username, username, sizeof(c->username) - 1);
    c->username[sizeof(c->username) - 1] = '\0';
    c->logged_in = 1;

    add_client(c);

    char response[128];

    snprintf(response, sizeof(response),
             "OK Logged in as %s\n", c->username);

    if (send_line(c->fd, response) < 0)
        goto cleanup;

    printf("User logged in: %s\n", c->username);

    /* Main message loop */
    while (recv_line(c->fd, line, sizeof(line)) == 0) {

        if (strcmp(line, "QUIT") == 0)
            break;

        if (strncmp(line, "MSG ", 4) != 0) {
            send_line(c->fd, "ERR Invalid command\n");
            continue;
        }

        char *recipient = line + 4;
		char *timestamp = strchr(recipient, ' ');

		if (!timestamp) {
			send_line(c->fd, "ERR Missing timestamp\n");
			continue;
		}

		*timestamp++ = '\0';

		char *body = strchr(timestamp, ' ');

		if (!body) {
			send_line(c->fd, "ERR Missing message body\n");
			continue;
		}

		*body++ = '\0';

		while (*body == ' ')
			body++;

		if (!*recipient || !*timestamp || !*body ||
			strlen(recipient) >= MAX_USER ||
			strlen(timestamp) != 20) {
			send_line(c->fd, "ERR Invalid message\n");
			continue;
		}

		int delivered = forward_message(
			c->username, recipient, timestamp, body);
			
		
        char *body = strchr(recipient, ' ');

        if (!body) {
            send_line(c->fd, "ERR Missing message body\n");
            continue;
        }

        *body++ = '\0';

        while (*body == ' ')
            body++;

        if (!*recipient || !*body ||
            strlen(recipient) >= MAX_USER) {
            send_line(c->fd, "ERR Invalid message\n");
            continue;
        }

        int delivered = forward_message(
            c->username, recipient, body);

        if (delivered > 0) {
            send_line(c->fd, "SENT\n");
        } else {
            send_line(c->fd, "ERR User not connected\n");
        }
    }

cleanup:
    if (c->logged_in) {
        printf("User disconnected: %s\n", c->username);
        remove_client(c);
    }

    close(c->fd);
    free(c);

    return NULL;
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (server_fd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    int opt = 1;

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR,
               &opt, sizeof(opt));

    struct sockaddr_in address = {0};

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address,
             sizeof(address)) < 0) {
        perror("bind");
        close(server_fd);
        return EXIT_FAILURE;
    }

    if (listen(server_fd, BACKLOG) < 0) {
        perror("listen");
        close(server_fd);
        return EXIT_FAILURE;
    }

    printf("Messaging server listening on port %d\n", PORT);

    for (;;) {
        int fd = accept(server_fd, NULL, NULL);

        if (fd < 0) {
            if (errno == EINTR)
                continue;

            perror("accept");
            continue;
        }

        Client *c = calloc(1, sizeof(*c));

        if (!c) {
            close(fd);
            continue;
        }

        c->fd = fd;

        pthread_t tid;

        if (pthread_create(&tid, NULL, client_thread, c) != 0) {
            close(fd);
            free(c);
            continue;
        }

        pthread_detach(tid);
    }

    close(server_fd);
    return EXIT_SUCCESS;
}

