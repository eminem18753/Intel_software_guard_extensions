#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

const char * HOST = "seclab-enclave-2.cs.illinois.edu";
const char * PORT = "10001";
const int BUFFER_SIZE = 4096;

char * readCSV(const char * filename, char ** ret, int * retLength) {
    FILE * file = fopen(filename, "r");
    char * line = NULL;
    ssize_t length = -1, size = 0;
    int readHeader = 0;

    float * vals = NULL;
    int * lbls = NULL;
    size_t linesRead = 0;

    while ((length = getline(&line, &size, file)) >= 0) {
        vals = realloc(vals, 4*sizeof(float)*(linesRead + 1));
        lbls = realloc(lbls, sizeof(int)*(linesRead + 1));
        if (!readHeader) {
            readHeader = 1;
            continue;
        }
        float SepalLength, SepalWidth, PetalLength, PetalWidth;
        int IsVirginica;
        sscanf(line, "%f,%f,%f,%f,%d", &SepalLength, &SepalWidth, &PetalLength, &PetalWidth, &IsVirginica);
        const size_t offset = 4*linesRead;
        vals[offset] = SepalLength;
        vals[offset + 1] = SepalWidth;
        vals[offset + 2] = PetalLength;
        vals[offset + 3] = PetalWidth;
        lbls[linesRead] = IsVirginica;
        linesRead++;
    }

    const size_t floatsSize = 4*sizeof(float)*linesRead;
    const size_t intsSize = sizeof(int)*linesRead;
    const size_t resultSize = floatsSize + intsSize;
    char * result = malloc(resultSize);
    memcpy(result, vals, floatsSize);
    memcpy(result + floatsSize, lbls, intsSize);

    *ret = result;
    *retLength = (int)linesRead;

    free(vals);
    free(lbls);
    free(line);
    fclose(file);
}


int openConnection() {
    struct addrinfo info;
    struct addrinfo * result, * iter;
    memset(&info, 0, sizeof(info));
    info.ai_flags = 0;
    info.ai_family = AF_INET;
    info.ai_socktype = SOCK_STREAM;
    info.ai_protocol = 0;

    int ret = getaddrinfo(HOST, PORT, &info, &result);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo failed %s\n", gai_strerror(ret));
        exit(1);
    }

    int fd;

    for (iter = result; iter != NULL; iter = iter->ai_next) {
        if ((fd = socket(iter->ai_family, iter->ai_socktype, iter->ai_protocol)) < 0) {
            perror("Failed to connect");
            continue;
        }

        if (connect(fd, iter->ai_addr, iter->ai_addrlen) >= 0) {
            break;
        }

        close(fd);
    }

    if (!iter) {
        fprintf(stderr, "Failed to open connection\n");
        exit(1);
    }

    freeaddrinfo(result);
    return fd;
}

// Based off example from getaddrinfo man pages.
void getKey(unsigned char * key, int * length) {
    int fd = openConnection();
    int len = (int)read(fd, key, BUFFER_SIZE); 
    if (len < 0) {
        perror("Read failed");
        printf("%x\n", (unsigned int)(size_t)key);
    } else {
        printf("Read %d bytes\n", len);
        for (int i = 0; i < len; ++i) {
            printf("0x%x ", key[i]);
        }
    }
    printf("\n");
    close(fd);
}

int main(int argc, const char ** argv) {
    unsigned char buffer[BUFFER_SIZE];
    int len;
    
    getKey(buffer, &len);

    EVP_PKEY * key = NULL;
    EVP_PKEY * ret = d2i_PublicKey(EVP_PKEY_RSA, &key, (const unsigned char **)&buffer, len);
    if (ret == NULL) {
        char ERROR_BUFFER[256];
        ERR_error_string(ERR_get_error(), ERROR_BUFFER);
        fprintf(stderr, "%s\n", ERROR_BUFFER);
    }

    return 0;
}
