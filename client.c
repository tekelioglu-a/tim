
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define PORT       "5555"
#define MAX_LINE   4096
#define MAX_OUTPUT (MAX_LINE + 128)

/* --------------------------------------------------------- */
/* Sending                                                   */
/* --------------------------------------------------------- */

static int send_all(int fd, const char *data, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        ssize_t n = send(fd, data + sent, length - sent, 0);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }

        if (n == 0)
            return -1;

        sent += (size_t)n;
    }

    return 0;
}

static int send_line(int fd, const char *line)
{
    return send_all(fd, line, strlen(line));
}

/* --------------------------------------------------------- */
/* Timestamp                                                 */
/* --------------------------------------------------------- */

static int get_timestamp(char *buffer, size_t size)
{
    time_t now = time(NULL);
    struct tm utc;

    if (gmtime_r(&now, &utc) == NULL)
        return -1;

    if (strftime(buffer, size,
                 "%Y-%m-%dT%H:%M:%SZ", &utc) == 0)
        return -1;

    return 0;
}

/* --------------------------------------------------------- */
/* Connection                                                */
/* --------------------------------------------------------- */

static int connect_to_server(const char *host)
{
    struct addrinfo hints;
    struct addrinfo *results = NULL;
    struct addrinfo *rp;
    int fd = -1;

    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int gai = getaddrinfo(host, PORT, &hints, &results);

    if (gai != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));
        return -1;
    }

    for (rp = results; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family,
                    rp->ai_socktype,
                    rp->ai_protocol);

        if (fd < 0)
            continue;

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;

        close(fd);
        fd = -1;
    }

    freeaddrinfo(results);

    return fd;
}

/* --------------------------------------------------------- */
/* Incoming server data                                      */
/* --------------------------------------------------------- */

static void process_server_data(const char *data, size_t length,
                                char *line, size_t *used,
                                int *too_long)
{
    for (size_t i = 0; i < length; i++) {
        char ch = data[i];

        if (ch == '\n') {
            if (*too_long) {
                printf("\n[Server message too long]\n");
            } else {
                line[*used] = '\0';

                if (*used > 0 && line[*used - 1] == '\r')
                    line[--(*used)] = '\0';

                printf("\n%s\n", line);
            }

            *used = 0;
            *too_long = 0;
            printf("> ");
            fflush(stdout);

            continue;
        }

        if (!*too_long) {
            if (*used + 1 < MAX_LINE)
                line[(*used)++] = ch;
            else
                *too_long = 1;
        }
    }
}

/* --------------------------------------------------------- */
/* Main                                                      */
/* --------------------------------------------------------- */

int main(int argc, char *argv[])
{
    if (argc != 4) {
        fprintf(stderr,
                "Usage: %s SERVER_IP USERNAME PASSWORD\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    const char *server = argv[1];
    const char *username = argv[2];
    const char *password = argv[3];

    int fd = connect_to_server(server);

    if (fd < 0) {
        perror("connect");
        return EXIT_FAILURE;
    }

    printf("Connected to %s:%s\n", server, PORT);

    /* Automatic login. */
    char login[MAX_OUTPUT];

    int n = snprintf(login, sizeof(login),
                     "LOGIN %s %s\n", username, password);

    if (n < 0 || (size_t)n >= sizeof(login)) {
        fprintf(stderr, "Login command too long\n");
        close(fd);
        return EXIT_FAILURE;
    }

    if (send_line(fd, login) < 0) {
        perror("send login");
        close(fd);
        return EXIT_FAILURE;
    }

    /*
     * Receive login response. Use a buffered read because
     * TCP does not preserve message boundaries.
     */
    char server_line[MAX_LINE];
    size_t server_used = 0;
    int server_too_long = 0;
    int logged_in = 0;

    while (!logged_in) {
        char buffer[1024];

        ssize_t received = recv(fd, buffer, sizeof(buffer), 0);

        if (received < 0) {
            if (errno == EINTR)
                continue;

            perror("recv");
            close(fd);
            return EXIT_FAILURE;
        }

        if (received == 0) {
            fprintf(stderr, "Server closed connection during login\n");
            close(fd);
            return EXIT_FAILURE;
        }

        for (ssize_t i = 0; i < received; i++) {
            char ch = buffer[i];

            if (ch == '\n') {
                if (server_too_long) {
                    fprintf(stderr, "Invalid server response\n");
                    close(fd);
                    return EXIT_FAILURE;
                }

                server_line[server_used] = '\0';

                if (server_used > 0 &&
                    server_line[server_used - 1] == '\r')
                    server_line[--server_used] = '\0';

                printf("%s\n", server_line);

                if (strncmp(server_line, "OK ", 3) != 0) {
                    close(fd);
                    return EXIT_FAILURE;
                }

                logged_in = 1;
                break;
            }

            if (!server_too_long) {
                if (server_used + 1 < sizeof(server_line))
                    server_line[server_used++] = ch;
                else
                    server_too_long = 1;
            }
        }
    }

    printf("\nEnter messages as: recipient message\n");
    printf("Enter QUIT to disconnect.\n\n");
    printf("> ");
    fflush(stdout);

    struct pollfd fds[2];

    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;

    fds[1].fd = fd;
    fds[1].events = POLLIN;

    char input[MAX_LINE];

    server_used = 0;
    server_too_long = 0;

    for (;;) {
        int ready = poll(fds, 2, -1);

        if (ready < 0) {
            if (errno == EINTR)
                continue;

            perror("poll");
            break;
        }

        /* Incoming server data. */
        if (fds[1].revents & POLLIN) {
            char buffer[1024];

            ssize_t received = recv(fd, buffer, sizeof(buffer), 0);

            if (received == 0) {
                printf("\nServer disconnected.\n");
                break;
            }

            if (received < 0) {
                if (errno == EINTR)
                    continue;

                perror("recv");
                break;
            }

            process_server_data(buffer, (size_t)received,
                                server_line, &server_used,
                                &server_too_long);
        }

        if (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            printf("\nServer connection closed.\n");
            break;
        }

        /* Keyboard input. */
        if (fds[0].revents & POLLIN) {
            if (fgets(input, sizeof(input), stdin) == NULL)
                break;

            input[strcspn(input, "\r\n")] = '\0';

            if (strcmp(input, "QUIT") == 0) {
                send_line(fd, "QUIT\n");
                break;
            }

            if (*input == '\0') {
                printf("> ");
                fflush(stdout);
                continue;
            }

            /* Separate recipient and message body. */
            char *body = strchr(input, ' ');

            if (body == NULL) {
                printf("Usage: recipient message\n> ");
                fflush(stdout);
                continue;
            }

            *body++ = '\0';

            while (*body == ' ')
                body++;

            if (*input == '\0' || *body == '\0') {
                printf("Usage: recipient message\n> ");
                fflush(stdout);
                continue;
            }

            char timestamp[32];

            if (get_timestamp(timestamp, sizeof(timestamp)) < 0) {
                fprintf(stderr, "Could not generate timestamp\n");
                continue;
            }

            char output[MAX_OUTPUT];

            n = snprintf(output, sizeof(output),
                         "MSG %s %s %s\n",
                         input, timestamp, body);

            if (n < 0 || (size_t)n >= sizeof(output)) {
                printf("Message too long\n> ");
                fflush(stdout);
                continue;
            }

            if (send_all(fd, output, (size_t)n) < 0) {
                perror("send");
                break;
            }
        }

        if (fds[0].revents & (POLLHUP | POLLERR | POLLNVAL))
            break;
    }

    close(fd);

    printf("Disconnected.\n");

    return EXIT_SUCCESS;
}

