#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

void handlerErr(char *msg){
    printf("ERROR: %s\n", msg);
    exit(1);
}

// Write string to file
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

// Read File
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

int main(int argc, char *argv[]) {

    // check args
    if (argc != 3) {
        handlerErr("Incorrect args");
    }

    char *challengeFilename = argv[1];
    char *difficultyFilename = argv[2];

    // read challenge and diffculty

    int *challengeLen = malloc(sizeof(int));
    char *challenge = Read_File(challengeFilename, challengeLen);

    int *difficultyLen = malloc(sizeof(int));
    char *difficulty = Read_File(difficultyFilename, difficultyLen);

    // write challenge and difficulty

    Write_File("puzzle_challenge.txt", challenge);
    Write_File("puzzle_k.txt", difficulty);

    return 0;
}