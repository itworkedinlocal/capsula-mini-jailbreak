/* Preserve times of existing overlay directories touched by our file additions. */
#define _GNU_SOURCE
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 4 || (strcmp(argv[1], "save") && strcmp(argv[1], "restore"))) return 2;
    int dir = open(argv[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) { perror("directory"); return 1; }
    int save = !strcmp(argv[1], "save");
    int fd = open(argv[3], save ? O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW : O_RDONLY | O_NOFOLLOW, 0600);
    if (fd < 0) { perror("time record"); close(dir); return 1; }
    int64_t record[4];
    if (save) {
        struct stat st;
        if (fstat(dir, &st)) return 1;
        record[0] = st.st_atim.tv_sec; record[1] = st.st_atim.tv_nsec;
        record[2] = st.st_mtim.tv_sec; record[3] = st.st_mtim.tv_nsec;
        if (write(fd, record, sizeof record) != sizeof record || fsync(fd)) return 1;
    } else {
        struct stat st;
        if (fstat(fd, &st) || st.st_size != sizeof record || read(fd, record, sizeof record) != sizeof record) return 1;
        if (record[1] < 0 || record[1] >= 1000000000 || record[3] < 0 || record[3] >= 1000000000) return 1;
        struct timespec times[2] = {{record[0], record[1]}, {record[2], record[3]}};
        if (futimens(dir, times) || fsync(dir)) { perror("restore times"); return 1; }
    }
    close(fd); close(dir);
    return 0;
}
