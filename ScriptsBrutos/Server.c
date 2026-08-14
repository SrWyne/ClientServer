//Simple ==Client/Server==

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <termios.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>
#include <netinet/tcp.h>

#define BUFFER 4096
#define PORT 3000

#define TAG_SIZE 16
#define NONCE_SIZE 12
#define KEY_SIZE 32


int Encrypt_gcm(
    const unsigned char in[],
    int in_len,
    unsigned char out[],
    const unsigned char key[],
    unsigned char nonce[],
    unsigned char tag[]){

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int len = 0;
        int total = 0;

        if (ctx == NULL){
            return -1;
        }

        if(RAND_bytes(nonce, NONCE_SIZE) != 1){
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }

        if(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)!=1){
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }

        if(EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce)!=1){
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }

        if(EVP_EncryptUpdate(ctx, out, &len, in, in_len)!=1){
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }

        total=len;

        if(EVP_EncryptFinal_ex(ctx, out + total, &len)!=1){
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }

        total+=len;

        if(EVP_CIPHER_CTX_ctrl(
            ctx, 
            EVP_CTRL_GCM_GET_TAG, 
            TAG_SIZE, 
            tag)!=1){
                EVP_CIPHER_CTX_free(ctx);
                return -1;
            }

        EVP_CIPHER_CTX_free(ctx);

        return total;

}

int Decrypt_gcm(const unsigned char in[],
    int in_len,
    unsigned char out[],
    const unsigned char key[],
    unsigned char tag[],
    unsigned char nonce[]){

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int total = 0;
        int len = 0;
        int ret;

        if(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)!=1){
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }

        if(EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce)!=1){
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }

        if(EVP_DecryptUpdate(ctx, out, &len, in, in_len)!=1){
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        total=len;

        if(EVP_CIPHER_CTX_ctrl(
            ctx, 
            EVP_CTRL_GCM_SET_TAG, TAG_SIZE, 
            (void*)tag)!=1)
            {
                EVP_CIPHER_CTX_free(ctx);
                return -1;
            }

        ret = EVP_DecryptFinal_ex(ctx, out+total, &len);

        if(ret<=0){
            EVP_CIPHER_CTX_free(ctx);
            return -2;
        }

        total+=len;

        EVP_CIPHER_CTX_free(ctx);

        return total;

}

int recv_full(int sock, unsigned char buff[], int len){
    int total = 0;

    while(total<len){
        int r = recv(sock, buff+total, len-total, 0);
        if(r <= 0) return -1;
        total+=r;
    }

    return total;
}

int recv_packet(int sock, unsigned char buf[]){
    int size_to_network;
    int size_to_host;

    if(recv_full(sock, (unsigned char*)&size_to_network, 4) != 4){
        return -1;
    }

    size_to_host = ntohl(size_to_network);

    if(recv_full(sock, buf, size_to_host) <= 0){
        return -1;
    }

    return size_to_host;
}

int send_packet(int sock, unsigned char buff[], int len){
    int size_to_network = htonl(len);

    int totalsize = 0;
    int total = 0;

    while(totalsize<4){
        int sen = send(sock, (unsigned char *)&size_to_network + totalsize, 4 - totalsize, 0);
        if(sen<=0) return -1;
        totalsize+=sen;
    }

    while(total<len){
        int s = send(sock, buff+total, len-total, 0);
        if(s <= 0) return -1;
        total+=s;
    }

    return 0;
}

struct termios old;

void restore_terminal(){
    tcsetattr(0, TCSANOW, &old);
}

void setup_terminal(){
    struct termios newt;

    tcgetattr(0, &old);
    atexit(restore_terminal);

    newt = old;
    newt.c_lflag &= ~(ICANON | ECHO);

    tcsetattr(0, TCSANOW, &newt);
}

int main(){
    signal(SIGTSTP, SIG_IGN);
    int server, client;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    server = socket(AF_INET, SOCK_STREAM, 0);

    int opt = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(server, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    addr.sin_port = htons(PORT);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;

    if(bind(server, (struct sockaddr*)&addr, sizeof(addr)) != 0){
        printf("Err in Bind!\n");
        return -1;
    }

    listen(server, 2);
    printf("Ouvindo na porta %d...\n", PORT);

    while (1)
    {
        client = accept(server, NULL, NULL);
        setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
        printf("[+] Conectado!\n");

        setup_terminal();
        unsigned char buff[BUFFER];
        unsigned char encrypted[BUFFER];
        unsigned char decrypted[BUFFER];

        unsigned char nonce[NONCE_SIZE];
        unsigned char tag[TAG_SIZE];
        unsigned char key_send[KEY_SIZE];
        unsigned char key_recv[KEY_SIZE];

        RAND_bytes(key_send, KEY_SIZE);

        while(1){

            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(0, &fds);
            FD_SET(client, &fds);

            int maxfds = client;

            int r = select(maxfds+1, &fds, NULL, NULL, NULL);
            if(r < 0){
                break;
            }

            if(FD_ISSET(0, &fds)){

                int bytes = read(0, buff, sizeof(buff));

                if(bytes <= 0) break;

                int enc_len = Encrypt_gcm(buff, bytes, encrypted, (const unsigned char*)key_send, nonce, tag);
                if(enc_len<=0) break;

                if(send_packet(client, key_send, KEY_SIZE) != 0) break;
                if(send_packet(client, nonce, NONCE_SIZE) != 0) break;
                if(send_packet(client, encrypted, enc_len) != 0) break;
                if(send_packet(client, tag, TAG_SIZE) != 0) break;
            }

            if(FD_ISSET(client, &fds)){

                int k = recv_packet(client, key_recv);
                int nc = recv_packet(client, nonce);
                int r = recv_packet(client, buff);
                int tags = recv_packet(client, tag);

                if(r<=0) break;

                int dec_len = Decrypt_gcm(buff, r, decrypted, (const unsigned char*)key_recv, tag, nonce);
                if(dec_len <= 0) break;

                write(1, decrypted, dec_len);
            }

        }

        restore_terminal();
        close(client);
        break;
    }

    close(server);
    printf("Conexão encerrada!\n");

    return 0;
}
