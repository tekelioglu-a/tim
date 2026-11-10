
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define PORT      5555
#define MAX_LINE  4096

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

    return -1;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr,
                "Usage: %s SERVER_IP USERNAME PASSWORD\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    const char *server_ip = argv[1];
    const char *username = argv[2];
    const char *password = argv[3];

    if (strlen(username) > 31 || strlen(password) > 63) {
        fprintf(stderr, "Username or password too long\n");
        return EXIT_FAILURE;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    struct sockaddr_in server = {0};

    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);

    if (inet_pton(AF_INET, server_ip,
                  &server.sin_addr) != 1) {
        fprintf(stderr, "Invalid IPv4 address\n");
        close(fd);
        return EXIT_FAILURE;
    }

    if (connect(fd, (struct sockaddr *)&server,
                sizeof(server)) < 0) {
        perror("connect");
        close(fd);
        return EXIT_FAILURE;
    }

    printf("Connected to %s:%d\n", server_ip, PORT);

    char line[MAX_LINE];

    snprintf(line, sizeof(line),
             "LOGIN %s %s\n", username, password);

    if (send_line(fd, line) < 0 ||
        recv_line(fd, line, sizeof(line)) < 0) {
        fprintf(stderr, "Connection lost during login\n");
        close(fd);
        return EXIT_FAILURE;
    }

    printf("Server: %s\n", line);

    if (strncmp(line, "OK ", 3) != 0) {
        close(fd);
        return EXIT_FAILURE;
    }

    printf("\nEnter messages as: recipient message\n");
    printf("Type QUIT to disconnect.\n\n");

    struct pollfd fds[2];

    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLLIN;

    fds[1].fd = fd;
    fds[1].events = POLLIN;

    for (;;) {
        int ret = poll(fds, 2, -1);

        if (ret < 0) {
            if (errno == EINTR)
                continue;

            perror("poll");
            break;
        }

        /* Incoming server messages */
        if (fds[1].revents & (POLLIN | POLLHUP | POLLERR)) {

            if (fds[1].revents & POLLIN) {
                if (recv_line(fd, line, sizeof(line)) < 0) {
                    printf("Server disconnected\n");
                    break;
                }

                printf("\n%s\n", line);
                fflush(stdout);
            } else {
                printf("Server connection closed\n");
                break;
            }
        }

        /* Keyboard input */
        if (fds[0].revents & POLLIN) {

            if (!fgets(line, sizeof(line), stdin)) {
                send_line(fd, "QUIT\n");
                break;
            }

            line[strcspn(line, "\r\n")] = '\0';

            if (strcmp(line, "QUIT") == 0) {
                send_line(fd, "QUIT\n");
                break;
            }

            if (!*line)
                continue;

            if (strlen(line) >= MAX_LINE - 1) {
                printf("Message too long\n");
                continue;
            }

            char output[MAX_LINE + 8];

            snprintf(output, sizeof(output),
                     "MSG %s\n", line);

            if (send_line(fd, output) < 0) {
                printf("Send failed\n");
                break;
            }
        }

        if (fds[0].revents & (POLLHUP | POLLERR | POLLNVAL))
            break;
    }

    shutdown(fd, SHUT_RDWR);
    close(fd);

    return EXIT_SUCCESS;
}

