#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define BUFFERLENGTH 10000


/* displays error messages from system calls */
void error(char *msg) {
    perror(msg);
    exit(1);
}

int writeResult(int sockfd, char *buffer, size_t bufsize) {
    int n;
    n = write(sockfd, &bufsize, sizeof(size_t));
    if (n < 0) {
        fprintf(stderr, "ERROR writing to result\n");
        return -1;
    }
    
    n = write(sockfd, buffer, bufsize);
    if (n != bufsize) {
        fprintf(stderr, "Couldn't write %ld bytes, wrote %d bytes\n", bufsize, n);
        return -1;
    }
    return 0;
}

char *readRes(int sockfd) {
    size_t bufsize;
    int res;
    char *buffer;

    res = read(sockfd, &bufsize, sizeof(size_t));
    if (res != sizeof(size_t)) {
        error("Reading number of bytes from socket");
        exit(1);
    }

    buffer = malloc(bufsize + 1);
    buffer[bufsize] = '\0';
    res = read(sockfd, buffer, bufsize);
    if (res != bufsize) {
        error("Reading reply from socket");
        exit(1);
    }

    return buffer;
}

int main(int argc, char *argv[]) {
    int sockfd, n;
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int res;
    char buffer[BUFFERLENGTH];

    if (argc < 4) {
        fprintf(stderr, "usage %s hostname port command\n", argv[0]);
        exit(1);
    }

    /* Obtain address(es) matching host/port */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
    hints.ai_flags = 0;
    hints.ai_protocol = 0;          /* Any protocol */

    res = getaddrinfo(argv[1], argv[2], &hints, &result);
    if (res != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(res));
        exit(EXIT_FAILURE);
    }

    /* Try each address until we successfully connect */
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1) {
            continue;
        }

        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1) {
            break; /* Success */
        }

        close(sockfd);
    }

    if (rp == NULL) { /* No address succeeded */
        fprintf(stderr, "Could not connect\n");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(result); /* No longer needed */

    /* Concatenate command arguments into one string */
    bzero(buffer, BUFFERLENGTH);
    for (int i = 3; i < argc; i++) {
        strcat(buffer, argv[i]);
        if (i < argc - 1) {
            strcat(buffer, " "); // Add space between arguments
        }
    }

    /* Send message */
    n = writeResult(sockfd, buffer, strlen(buffer));
    if (n < 0) {
        error("ERROR writing to socket");
    }

    /* Wait for reply */
    char *response = readRes(sockfd);
    printf("%s", response);
    free(response);

    /* Cleanup */
    close(sockfd);
    return 0;
}