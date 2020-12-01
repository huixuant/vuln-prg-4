#include <stdlib.h>
#include <Windows.h>
#include <io.h>
#include <fcntl.h>
#include <sys\stat.h>
#include <share.h>
#include "crc32.h"

#define MIN_REQ_SIZE 8

void this_is_a_vulnerable_function(size_t size) {
    char buf[10] = { 0 };
    buf[size] = "A";
}

int compare_crc(uint32_t a, uint32_t b) {
    if (a == b)
        return 1;
    else
        return 0;
}

__declspec(dllexport) int fuzz_target(char* filename);

int fuzz_target(char* filename) {
    //int fd;
    //__int64 file_size;
    int bytes_read;
    unsigned char* req_contents;
    unsigned char req_crc[8];

    /*
    _sopen_s(&fd, filename, _O_RDONLY, _SH_DENYRW, _S_IREAD);
    if (fd == -1) {
        fputs("Error opening file.", stderr);
        return 0;
    }

    file_size = _filelengthi64(fd);
    if (file_size == -1) {
        fputs("Error getting file size.", stderr);
        return 0;
    }
    */
    // open file 
    FILE* fp;
    errno_t err;
    err = fopen_s(&fp, filename, "rb");
    if (err != 0) {
        printf("Error reading file.");
        return 0;
    }

    // determine no of bytes 
    fseek(fp, 0, SEEK_END);
    int bytes_count = ftell(fp);
    rewind(fp);

    // verify size of request
    if (bytes_count == -1 || bytes_count < MIN_REQ_SIZE) {
        printf("Invalid input.");
        return 0;
    }

    // dynamically allocate memory for file data
    req_contents = malloc(sizeof(unsigned char) * (bytes_count - 7));
    if (req_contents == NULL) {
        printf("Memory error occured.");
        return 0;
    }

    memset(req_contents, 0, sizeof(unsigned char) * (bytes_count - 7));
    fread(req_contents, sizeof(unsigned char), bytes_count - 8, fp);
    fread(&req_crc, sizeof(req_crc), 1, fp);
    
    // dynamically allocate memory for file data
    /*
    unsigned char* buf = malloc(sizeof(unsigned char) * (bytes_count + 1));
    if (buf == NULL) {
        fputs("Memory error occured.", stderr);
        return 0;
    }

    memset(buf, 0, sizeof(unsigned char) * (bytes_count + 1));
    if ((bytes_read = fread(buf, 1, bytes_count, fp)) <= 0) {
        fputs("Problem reading file.", stderr);
        return 0;
    }
    */
    fclose(fp);

    // check crc given is valid
    uint32_t crc_int = (uint32_t)strtol(req_crc, NULL, 16);
    if (crc_int == 0 || errno == ERANGE) {
        printf("Invalid CRC32 value given.");
        return 0;
    }

    uint32_t computed_crc = rc_crc32(0, req_contents, bytes_count-8);

    if (compare_crc(computed_crc, crc_int)) {
        printf("CRC32 check passed.");
        this_is_a_vulnerable_function(0xFFFF);
    }
    else
        printf("CRC32 check failed.");

    free(req_contents);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input file>\n", argv[0]);
        return 0;
    }
    return fuzz_target(argv[1]);
}