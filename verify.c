#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

void handlerErr(char *msg){
    printf("ERROR: %s\n", msg);
    exit(1);
}

char* Read_File(const char *filename, int *length) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return NULL;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char *buffer = (char*)malloc(file_size + 1);
    if (!buffer) {
        fclose(file);
        return NULL;
    }
    
    size_t read_size = fread(buffer, 1, file_size, file);
    buffer[read_size] = '\0';
    
    // Remove trailing whitespace
    while (read_size > 0 && (buffer[read_size-1] == '\n' || 
                              buffer[read_size-1] == '\r' || 
                              buffer[read_size-1] == ' ')) {
        buffer[--read_size] = '\0';
    }
    
    *length = read_size;
    fclose(file);
    return buffer;
}

int Read_Int_From_File(const char *filename) {
    int length;
    char *str = Read_File(filename, &length);
    if (!str) return -1;
    
    int value = atoi(str);
    free(str);
    return value;
}

int Compute_SHA256(const unsigned char *inputBytes, int inputLen, unsigned char *hash) {

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, inputBytes, inputLen);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);

    return 0;
}

int Hex_to_Bytes(const char *hex, unsigned char *bytes, int hex_len) {
    if (hex_len % 2 != 0) {
        fprintf(stderr, "Error: Hex string length must be even\n");
        return -1;
    }
    
    int byte_len = hex_len / 2;
    for (int i = 0; i < byte_len; i++) {
        unsigned int byte;
        if (sscanf(hex + (i * 2), "%2x", &byte) != 1) {
            fprintf(stderr, "Error: Invalid hex character at position %d\n", i * 2);
            return -1;
        }
        bytes[i] = (unsigned char)byte;
    }
    
    return byte_len;
}

int Write_File(const char *filename, const char *data) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s for writing\n", filename);
        return -1;
    }
    
    fprintf(file, "%s", data);
    fclose(file);
    return 0;
}

int valid(int d, char *h) {
    int bytes = d / 8;
    int bits = d % 8;

    for (int i = 0; i < bytes; i++) {
        if (h[i] != 0) {
            // fail
            return 0;
        }
    }

    if (bits > 0) {
        unsigned char mask = (0xFF << (8 - bits));
        if ((h[bytes] & mask) != 0) {
            // fail
            return 0;
        }
    }

    // success
    return 1;
}

int main(int argc, char *argv[]) {
    
    // check args
    if (argc != 4) {
        handlerErr("Incorrect args");
    }

    char *challengeFilename = argv[1];
    char *difficultyFilename = argv[2];
    char *nonceFilename = argv[3];

    // read challenge
    int challengeLen;
    char *challenge = Read_File(challengeFilename, &challengeLen);

    // read difficulty
    int difficulty = Read_Int_From_File(difficultyFilename);
    
    // read solution nonce
    int nonceLen;
    char *nonce = Read_File(nonceFilename, &nonceLen);

    // concat challenge hex + nonce hex
    int concatLen = challengeLen + strlen(nonce);
    char *data = malloc(concatLen);
    strcpy(data, challenge);
    strcat(data, nonce);

    // convert concat hex to bytes
    int byteLen = concatLen/2;
    char *bytes = malloc(byteLen);

    Hex_to_Bytes(data, bytes, strlen(data));

    // compute SHA
    unsigned char hash[SHA256_DIGEST_LENGTH];

    int ok = Compute_SHA256(bytes, byteLen, hash);
    if (ok != 0) {
        handlerErr("SHA256 failed");
    }

    if (valid(difficulty, hash)) {
        Write_File("verification_result.txt", "ACCEPT\n");
        exit(0);
    } else {
        Write_File("verification_result.txt", "REJECT\n");
        exit(1);
    }
}