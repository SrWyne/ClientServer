#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <openssl/evp.h>
#include <arpa/inet.h>
#include <termios.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>
#include <netinet/tcp.h>

#define BUFFER 1024
#define PORT 3000

unsigned char key [16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
unsigned char iv[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

int Encrypt(unsigned char in_plain[], int len_plain, unsigned char out_cipher[]){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int total, len;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, out_cipher, &len, in_plain, len_plain);
    total = len;

    EVP_EncryptFinal_ex(ctx, out_cipher + len, &len);
    total+=len;

    EVP_CIPHER_free(ctx);

    return total;

}

int Decrypt(unsigned char in_cipher[], int len_cipher, unsigned char out_plain[]){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int total, len;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, out_plain, &len, in_cipher, len_cipher);
    total = len;

    EVP_EncryptFinal_ex(ctx, out_plain + total, &len);
    total+=len;

    EVP_CIPHER_free(ctx);

    return total;
}

int recv_full(int sock, unsigned char buff[], int len){
    int total = 0;

    while(total<len){
        int r = recv(sock, buff+total, len-total, 0);
        total+=r;
    }

    return total;
}

int recv_packet(int sock, unsigned char buf[]){
    int size_to_network;
    int size_to_host;

    recv_full(sock, &size_to_network, 4);

    size_to_host = ntohl(size_to_network);

    recv_full(sock, buf, size_to_host);

    return size_to_host;
}

int send_packet(int sock, unsigned char buff[], int len){
    int size_to_netowrk = htonl(len);

    send(sock, &size_to_netowrk, 4, 0);

    int total = 0;

    while(total<len){
        int s = send(sock, buff+total, len-total, 0);
        total+=s;
    }

    return 0;
}

struct termios old;

void restore_terminal(){
    tcsetattr(0, TCSANOW, &old);
}

void sig_terminal(int sig){
    restore_terminal();
    printf("Saindo...");
    exit(0);

}

void setup_terminal(){
    struct termios newt;

    tcgetattr(0, &old);
    atexit(sig_terminal);
    signal(SIGINT, restore_terminal);

    newt = old;
    newt.c_cflag &= ~(ICANON | ECHO);

    tcsetattr(0, TCSANOW, &newt);
}

int main(){
    int server, client;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    server = socket(AF_INET, SOCK_STREAM, 0);

    int opt = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(server, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    addr.sin_port = htons(PORT);
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    bind(server, (struct sockaddr*)&addr, sizeof(addr));

    listen(server, 1);

    client = accept(server, NULL, NULL);
    setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    setup_terminal();

    while (1)
    {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(0, &fds);
        FD_SET(client, &fds);

        int maxfds = client;

        int r = select(maxfds+1, &fds, NULL, NULL, NULL);
        if(r < 0){
            return -1;
        }

        if(FD_ISSET(0, &fds)){
            unsigned char buff[BUFFER];
            unsigned char encrypted[BUFFER];

            int bytes = read(0, buff, strlen(buff));

            int enc_len = Encrypt(buff, bytes, encrypted);
            send_packet(client, encrypted, enc_len);
        }

        if(FD_ISSET(client, &fds)){
            unsigned char buff[BUFFER];
            unsigned char decrypted[BUFFER];

            int r = recv_packet(client, buff);

            int dec_len = Decrypt(buff, sizeof(buff), decrypted);
            write(1, decrypted, dec_len);
        }

    }

    close(client);
    close(server);

    return 0;
}



