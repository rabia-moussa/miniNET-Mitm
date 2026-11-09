#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

int main(){
    int fileD = socket(AF_INET, SOCK_STREAM, 0);
    if (fileD < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in server = {0};
    server.sin_family = AF_INET;
    server.sin_port = htons(8080);
    if (inet_pton(AF_INET, "127.0.0.1", &server.sin_addr) != 1) {
        fprintf(stderr, "Invalid server IPv4 address\n");
        close(fileD);
        return 1;
    }

    if (connect(fileD, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("connect");
        close(fileD);
        return 1;
    }

    const char request[] = "Hello from client\n";
    size_t sent = 0;
    while (sent < sizeof(request) - 1) {
        ssize_t result = send(fileD, request + sent, sizeof(request) - 1 - sent, 0);
        if (result < 0) {
            perror("send");
            close(fileD);
            return 1;
        }
        if (result == 0) {
            fprintf(stderr, "send made no progress\n");
            close(fileD);
            return 1;
        }
        sent += (size_t)result;
    }

    printf("Request sent to 127.0.0.1:8080\n");
    close(fileD);
    return 0;
}