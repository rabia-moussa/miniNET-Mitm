#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

int createTCPIPsocket(){
    return socket(AF_INET, SOCK_STREAM, 0);
}

struct sockaddr_in* createipv4addr(char *ip, int port){
    struct sockaddr_in *addr = malloc(sizeof(struct sockaddr_in));
    addr->sin_port = htons(port);
    addr->sin_family = AF_INET;
    if (ip == NULL)
        addr->sin_addr.s_addr = INADDR_ANY; // listen on all interfaces
    else
        inet_pton(AF_INET, ip, &addr->sin_addr.s_addr);
    return addr;
}

int main(){
    int serverFd = createTCPIPsocket();
    if (serverFd < 0){
        printf("socket error\n");
        return -1;
    }

    int opt = 1;
    setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)); // allows reusing the port quickly after restart

    struct sockaddr_in *server = createipv4addr(NULL, 8080);

    if (bind(serverFd, (struct sockaddr *)server, sizeof(*server)) < 0){
        printf("bind error\n");
        return -1;
    }

    if (listen(serverFd, 5) < 0){ // 5 = max queued connections
        printf("listen error\n");
        return -1;
    }

    printf("listening on port 8080...\n");

    while (1){
        struct sockaddr_in client;
        socklen_t clientLen = sizeof(client);
        int clientFd = accept(serverFd, (struct sockaddr *)&client, &clientLen);
        if (clientFd < 0){
            printf("accept error\n");
            continue;
        }

        printf("client connected: %s\n", inet_ntoa(client.sin_addr));

        char buffer[1024] = {0};
        int bytes = recv(clientFd, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0){
            printf("received: %s\n", buffer);
        }

        close(clientFd);
    }

    close(serverFd);
    return 0;
}