
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define PORT       "5555"
#define MAX_LINE   4096
#define MAX_USER   64
#define MAX_OUTPUT (MAX_LINE + MAX_USER + 128)

typedef struct OutMessage {
    struct OutMessage *next;
    size_t length;
    size_t sent;
    char data[];
} OutMessage;

typedef struct Client {
    int fd;
    int wake_pipe[2];

    int authenticated;
    char username[MAX_USER];

    pthread_mutex_t queue_mutex;
    OutMessage *queue_head;
    OutMessage *queue_tail;

    struct Client *next;
} Client;

static Client *clients = NULL;
static pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

/* --------------------------------------------------------- */
/* Test authentication                                       */
/* --------------------------------------------------------- */

static int authenticate(const char *username, const char *password)
{
    if (strcmp(username, "alice") == 0 &&
        strcmp(password, "alice") == 0)
        return 1;

    if (strcmp(username, "bob") == 0 &&
        strcmp(password, "bob") == 0)
        return 1;

    return 0;
}

/* --------------------------------------------------------- */
/* Non-blocking file descriptors                             */
/* --------------------------------------------------------- */

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0)
        return -1;

    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* --------------------------------------------------------- */
/* Outgoing message queue                                    */
/* --------------------------------------------------------- */

static int queue_push(Client *client, const char *message)
{
    size_t length = strlen(message);

    OutMessage *item = malloc(sizeof(*item) + length);

    if (item == NULL)
        return -1;

    item->next = NULL;
    item->length = length;
    item->sent = 0;
    memcpy(item->data, message, length);

    pthread_mutex_lock(&client->queue_mutex);

    if (client->queue_tail != NULL)
        client->queue_tail->next = item;
    else
        client->queue_head = item;

    client->queue_tail = item;

    pthread_mutex_unlock(&client->queue_mutex);

    /*
     * Wake the connection-owning thread.
     * EAGAIN is harmless: a full pipe is already readable.
     */
    char byte = 'W';
    ssize_t n = write(client->wake_pipe[1], &byte, 1);

    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
        errno != EINTR) {
        /* The queued message remains available to the owner. */
    }

    return 0;
}

static OutMessage *queue_pop(Client *client)
{
    pthread_mutex_lock(&client->queue_mutex);

    OutMessage *item = client->queue_head;

    if (item != NULL) {
        client->queue_head = item->next;

        if (client->queue_head == NULL)
            client->queue_tail = NULL;
    }

    pthread_mutex_unlock(&client->queue_mutex);

    return item;
}

static int queue_is_empty(Client *client)
{
    pthread_mutex_lock(&client->queue_mutex);

    int empty = (client->queue_head == NULL);

    pthread_mutex_unlock(&client->queue_mutex);

    return empty;
}

static void drain_wakeup_pipe(int fd)
{
    char buffer[128];

    while (read(fd, buffer, sizeof(buffer)) > 0)
        ;
}

/* --------------------------------------------------------- */
/* Timestamp validation                                      */
/* --------------------------------------------------------- */

static int valid_timestamp(const char *s)
{
    if (strlen(s) != 20)
        return 0;

    if (s[4]  != '-' ||
        s[7]  != '-' ||
        s[10] != 'T' ||
        s[13] != ':' ||
        s[16] != ':' ||
        s[19] != 'Z')
        return 0;

    for (int i = 0; i < 20; i++) {
        if (i == 4 || i == 7 || i == 10 ||
            i == 13 || i == 16 || i == 19)
            continue;

        if (!isdigit((unsigned char)s[i]))
            return 0;
    }

    return 1;
}

/* --------------------------------------------------------- */
/* Client list                                               */
/* --------------------------------------------------------- */

static void remove_client(Client *client)
{
    pthread_mutex_lock(&clients_mutex);

    Client **current = &clients;

    while (*current != NULL) {
        if (*current == client) {
            *current = client->next;
            break;
        }

        current = &(*current)->next;
    }

    pthread_mutex_unlock(&clients_mutex);
}

/* --------------------------------------------------------- */
/* Message forwarding                                        */
/* --------------------------------------------------------- */

static int forward_message(const char *sender,
                           const char *recipient,
                           const char *timestamp,
                           const char *body)
{
    char output[MAX_OUTPUT];

    int n = snprintf(output, sizeof(output),
                     "FROM %s %s %s\n",
                     sender, timestamp, body);

    if (n < 0 || (size_t)n >= sizeof(output))
        return 0;

    int delivered = 0;

    pthread_mutex_lock(&clients_mutex);

    for (Client *c = clients; c != NULL; c = c->next) {
        if (c->authenticated &&
            strcmp(c->username, recipient) == 0) {

            if (queue_push(c, output) == 0)
                delivered++;
        }
    }

    pthread_mutex_unlock(&clients_mutex);

    return delivered;
}

/* --------------------------------------------------------- */
/* Process one complete client command                       */
/* --------------------------------------------------------- */

/* Returns 1 when the client requests QUIT. */
static int process_line(Client *client, char *line)
{
    if (strncmp(line, "LOGIN ", 6) == 0) {
        char username[MAX_USER];
        char password[MAX_USER];
        char extra;

        if (client->authenticated) {
            queue_push(client, "ERR Already logged in\n");
            return 0;
        }

        int fields = sscanf(line + 6, "%63s %63s %c",
                            username, password, &extra);

        if (fields != 2) {
            queue_push(client, "ERR Invalid login format\n");
            return 0;
        }

        if (!authenticate(username, password)) {
            queue_push(client, "ERR Authentication failed\n");
            return 0;
        }

        pthread_mutex_lock(&clients_mutex);

        client->authenticated = 1;
        snprintf(client->username, sizeof(client->username),
                 "%s", username);

        pthread_mutex_unlock(&clients_mutex);

        char response[MAX_USER + 64];

        snprintf(response, sizeof(response),
                 "OK Logged in as %s\n", username);

        queue_push(client, response);

        printf("User logged in: %s (fd=%d)\n",
               username, client->fd);

        return 0;
    }

    if (strcmp(line, "QUIT") == 0) {
        queue_push(client, "OK Goodbye\n");
        return 1;
    }

    if (strncmp(line, "MSG ", 4) == 0) {
        if (!client->authenticated) {
            queue_push(client, "ERR Please log in first\n");
            return 0;
        }

        char *recipient = line + 4;
        char *timestamp = strchr(recipient, ' ');

        if (timestamp == NULL) {
            queue_push(client, "ERR Missing timestamp\n");
            return 0;
        }

        *timestamp++ = '\0';

        char *body = strchr(timestamp, ' ');

        if (body == NULL) {
            queue_push(client, "ERR Missing message body\n");
            return 0;
        }

        *body++ = '\0';

        while (*body == ' ')
            body++;

        if (*recipient == '\0' ||
            strlen(recipient) >= MAX_USER ||
            !valid_timestamp(timestamp) ||
            *body == '\0') {
            queue_push(client, "ERR Invalid message\n");
            return 0;
        }

        int delivered = forward_message(
            client->username,
            recipient,
            timestamp,
            body
        );

        if (delivered > 0)
            queue_push(client, "SENT\n");
        else
            queue_push(client, "ERR User not connected\n");

        return 0;
    }

    queue_push(client, "ERR Unknown command\n");
    return 0;
}

/* --------------------------------------------------------- */
/* Connection-owning thread                                  */
/* --------------------------------------------------------- */

static void *client_thread(void *arg)
{
    Client *client = (Client *)arg;

    char input[MAX_LINE];
    size_t input_used = 0;
    int input_too_long = 0;

    OutMessage *current = NULL;

    int quit_requested = 0;
    int disconnected = 0;

    printf("Connection established: fd=%d\n", client->fd);

    for (;;) {
        if (current == NULL)
            current = queue_pop(client);

        if (quit_requested && current == NULL &&
            queue_is_empty(client))
            break;

        struct pollfd fds[2];

        fds[0].fd = client->fd;
        fds[0].events = quit_requested ? 0 : POLLIN;

        if (current != NULL || !queue_is_empty(client))
            fds[0].events |= POLLOUT;

        fds[0].revents = 0;

        fds[1].fd = client->wake_pipe[0];
        fds[1].events = POLLIN;
        fds[1].revents = 0;

        int result = poll(fds, 2, -1);

        if (result < 0) {
            if (errno == EINTR)
                continue;

            perror("poll");
            break;
        }

        if (fds[1].revents & POLLIN)
            drain_wakeup_pipe(client->wake_pipe[0]);

        /* Read incoming data. */
        if (!quit_requested &&
            (fds[0].revents & POLLIN)) {

            char buffer[1024];

            for (;;) {
                ssize_t n = recv(client->fd, buffer,
                                 sizeof(buffer), 0);

                if (n == 0) {
                    disconnected = 1;
                    break;
                }

                if (n < 0) {
                    if (errno == EINTR)
                        continue;

                    if (errno == EAGAIN ||
                        errno == EWOULDBLOCK)
                        break;

                    disconnected = 1;
                    break;
                }

                for (ssize_t i = 0; i < n; i++) {
                    char ch = buffer[i];

                    if (ch == '\n') {
                        if (!input_too_long) {
                            input[input_used] = '\0';

                            if (input_used > 0 &&
                                input[input_used - 1] == '\r')
                                input[--input_used] = '\0';

                            if (process_line(client, input)) {
                                quit_requested = 1;
                                break;
                            }
                        } else {
                            queue_push(client,
                                       "ERR Line too long\n");
                        }

                        input_used = 0;
                        input_too_long = 0;

                        if (quit_requested)
                            break;

                        continue;
                    }

                    if (!input_too_long) {
                        if (input_used + 1 < sizeof(input))
                            input[input_used++] = ch;
                        else
                            input_too_long = 1;
                    }
                }

                if (quit_requested || disconnected)
                    break;
            }
        }

        if (disconnected)
            break;

        /* Write outgoing data. Only this thread writes to this socket. */
        if (fds[0].revents & POLLOUT) {
            if (current == NULL)
                current = queue_pop(client);

            if (current != NULL) {
                ssize_t n = send(
                    client->fd,
                    current->data + current->sent,
                    current->length - current->sent,
                    MSG_NOSIGNAL
                );

                if (n > 0) {
                    current->sent += (size_t)n;

                    if (current->sent == current->length) {
                        free(current);
                        current = NULL;
                    }
                } else if (n < 0 &&
                           errno != EINTR &&
                           errno != EAGAIN &&
                           errno != EWOULDBLOCK) {
                    disconnected = 1;
                    break;
                } else if (n == 0) {
                    disconnected = 1;
                    break;
                }
            }
        }

        if (fds[0].revents & (POLLERR | POLLNVAL)) {
            disconnected = 1;
            break;
        }

        if ((fds[0].revents & POLLHUP) &&
            !(fds[0].revents & POLLIN)) {
            disconnected = 1;
            break;
        }
    }

    free(current);

    remove_client(client);

    close(client->fd);
    close(client->wake_pipe[0]);
    close(client->wake_pipe[1]);

    pthread_mutex_lock(&client->queue_mutex);

    OutMessage *item = client->queue_head;

    while (item != NULL) {
        OutMessage *next = item->next;
        free(item);
        item = next;
    }

    pthread_mutex_unlock(&client->queue_mutex);

    pthread_mutex_destroy(&client->queue_mutex);

    printf("Connection closed: fd=%d\n", client->fd);

    free(client);

    return NULL;
}

/* --------------------------------------------------------- */
/* Main server                                               */
/* --------------------------------------------------------- */

int main(void)
{
    struct addrinfo hints;
    struct addrinfo *results = NULL;
    struct addrinfo *rp;

    int server_fd = -1;
    int yes = 1;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int gai = getaddrinfo(NULL, PORT, &hints, &results);

    if (gai != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));
        return EXIT_FAILURE;
    }

    for (rp = results; rp != NULL; rp = rp->ai_next) {
        server_fd = socket(rp->ai_family,
                           rp->ai_socktype,
                           rp->ai_protocol);

        if (server_fd < 0)
            continue;

        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR,
                   &yes, sizeof(yes));

        if (bind(server_fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;

        close(server_fd);
        server_fd = -1;
    }

    freeaddrinfo(results);

    if (server_fd < 0) {
        perror("bind");
        return EXIT_FAILURE;
    }

    if (listen(server_fd, 32) < 0) {
        perror("listen");
        close(server_fd);
        return EXIT_FAILURE;
    }

    printf("Server listening on port %s\n", PORT);

    for (;;) {
        struct sockaddr_storage address;
        socklen_t address_length = sizeof(address);

        int client_fd = accept(server_fd,
                               (struct sockaddr *)&address,
                               &address_length);

        if (client_fd < 0) {
            if (errno == EINTR)
                continue;

            perror("accept");
            continue;
        }

        Client *client = calloc(1, sizeof(*client));

        if (client == NULL) {
            perror("calloc");
            close(client_fd);
            continue;
        }

        client->fd = client_fd;

        if (pthread_mutex_init(&client->queue_mutex, NULL) != 0) {
            fprintf(stderr, "Could not initialise client mutex\n");
            close(client_fd);
            free(client);
            continue;
        }

        if (pipe(client->wake_pipe) < 0) {
            perror("pipe");
            pthread_mutex_destroy(&client->queue_mutex);
            close(client_fd);
            free(client);
            continue;
        }

        if (set_nonblocking(client->wake_pipe[0]) < 0 ||
            set_nonblocking(client->wake_pipe[1]) < 0 ||
            set_nonblocking(client->fd) < 0) {
            perror("fcntl");
            close(client->wake_pipe[0]);
            close(client->wake_pipe[1]);
            pthread_mutex_destroy(&client->queue_mutex);
            close(client_fd);
            free(client);
            continue;
        }

        pthread_mutex_lock(&clients_mutex);

        client->next = clients;
        clients = client;

        pthread_mutex_unlock(&clients_mutex);

        pthread_t thread;

        int err = pthread_create(&thread, NULL,
                                 client_thread, client);

        if (err != 0) {
            fprintf(stderr, "pthread_create: %s\n", strerror(err));

            remove_client(client);
            close(client->fd);
            close(client->wake_pipe[0]);
            close(client->wake_pipe[1]);
            pthread_mutex_destroy(&client->queue_mutex);
            free(client);
            continue;
        }

        pthread_detach(thread);
    }

    close(server_fd);

    return EXIT_SUCCESS;
}

