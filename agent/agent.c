/*
 * ShadowLink C2 Agent - Implementation
 * Phase 1: TCP Client
 */

#include "agent.h"


#define BUFFER_SIZE 1024




int main() {
    printf("[*] ShadowLink Agent - Phase 1\n");

    WSADATA wsaData; 

    int result = WSAStartup(MAKEWORD(2,2), &wsaData);

    if (result != 0) {
        printf("WSAStartup failed: %d\n", result);
        return 1;
    }
    
    printf("[+] Winsock initialized \n");
    

    


    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sock == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    printf("[+] Socket created\n");
    

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));

    // Address configuration
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    
    if (server_addr.sin_addr.s_addr == INADDR_NONE) {
        printf("Invalid IP address\n");
        closesocket(sock);
        return 1;
    }


    // Connect to server
    result = connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (result == SOCKET_ERROR) {
        printf("connect() failed: %d\n", WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    
    printf("[+] Connected to server at %s:%d\n", SERVER_IP, SERVER_PORT);
    
     char recvBuffer[1024];
    int bytesReceived = recv(sock, recvBuffer, sizeof(recvBuffer) - 1, 0);
    
    if (bytesReceived > 0) {
        recvBuffer[bytesReceived] = '\0';
        printf("[+] Received: %s", recvBuffer);
    } else if (bytesReceived == 0) {
        printf("[*] Connection closed by server\n");
    } else {
        printf("recv() failed: %d\n", WSAGetLastError());
    }
    
    const char *response = "Agent connected successfully!";
    int bytesSent = send(sock, response, strlen(response), 0);
    
    if (bytesSent == SOCKET_ERROR) {
        printf("send() failed: %d\n", WSAGetLastError());
    } else {
        printf("[+] Sent %d bytes\n", bytesSent);
    }
    
    closesocket(sock); 
    WSACleanup();
    printf("[*] Cleanup complete\n");

    return 0;
}
