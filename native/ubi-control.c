/* Attach/detach only data and the selected read-only stock slot. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

struct attach_req {
    int32_t ubi_num, mtd_num, vid_hdr_offset;
    int16_t max_beb_per1024;
    int8_t disable_fm, need_resv_pool, padding[8];
};
_Static_assert(sizeof(struct attach_req) == 24, "UBI ioctl ABI");

static long number(const char *path) {
    char text[128], *end;
    FILE *f = fopen(path, "r");
    if (!f || !fgets(text, sizeof text, f)) { perror(path); exit(1); }
    fclose(f); errno = 0;
    long n = strtol(text, &end, 0);
    if (errno || end == text || (*end && *end != '\n')) exit(1);
    return n;
}

static void require(int mtd, const char *key, long expected) {
    char path[128]; snprintf(path, sizeof path, "/sys/class/mtd/mtd%d/%s", mtd, key);
    if (number(path) != expected) { fprintf(stderr, "MTD profile mismatch: %s\n", path); exit(1); }
}

int main(int argc, char **argv) {
    if (argc != 3 || getuid()) return 2;
    int data = !strcmp(argv[2], "data"), stock = !strcmp(argv[2], "stock");
    if (!data && !stock) return 2;
    int data_index=8, stock_index=7, count=9;
    int writable=1;
    long data_size=81264640, stock_size=67633152;
    char stock_name[32]="system_b", line[128], key[64], value[64];
    FILE *configuration=fopen("/capsula-device.conf", "r");
    if(configuration) {
        while(fgets(line,sizeof line,configuration)) {
            if(sscanf(line,"%63[^=]=%63s",key,value)!=2) return 1;
            char *end; errno=0; long n=strtol(value,&end,10);
            if(!strcmp(key,"STOCK_NAME")) {
                if(strcmp(value,"system_a")&&strcmp(value,"system_b")) return 1;
                snprintf(stock_name,sizeof stock_name,"%s",value);
            } else if(!strcmp(key,"DATA_INDEX")) {if(errno||*end||n<0||n>31)return 1;data_index=(int)n;}
            else if(!strcmp(key,"STOCK_INDEX")) {if(errno||*end||n<0||n>31)return 1;stock_index=(int)n;}
            else if(!strcmp(key,"MTD_COUNT")) {if(errno||*end||n<1||n>32)return 1;count=(int)n;}
            else if(!strcmp(key,"DATA_SIZE")) {if(errno||*end||n<=0)return 1;data_size=n;}
            else if(!strcmp(key,"STOCK_SIZE")) {if(errno||*end||n<=0)return 1;stock_size=n;}
            else if(!strcmp(key,"DATA_WRITABLE")) {if(errno||*end||(n!=0&&n!=1))return 1;writable=(int)n;}
        }
        fclose(configuration);
    }
    if(data_index==stock_index||data_index>=count||stock_index>=count) return 1;
    int mtd = data ? data_index : stock_index, ubi = data ? 0 : 1;
    /* RO inspection is permitted; enforced MTD flags prevent UBI writes. */
    for (int i = 0; i < count; i++) require(i, "flags", i == data_index && writable ? 0x400 : 0);
    require(mtd, "size", data ? data_size : stock_size);
    require(mtd, "erasesize", 131072); require(mtd, "writesize", 2048);
    char path[128], text[64];
    snprintf(path, sizeof path, "/sys/class/mtd/mtd%d/name", mtd);
    FILE *f = fopen(path, "r");
    if (!f || !fgets(text, sizeof text, f)) return 1;
    fclose(f);
    text[strcspn(text,"\n")]=0;
    if (strcmp(text, data ? "data" : stock_name)) return 1;
    int fd = open("/dev/ubi_ctrl", O_RDWR | O_CLOEXEC);
    if (fd < 0) { perror("UBI control"); return 1; }
    int rc;
    if (!strcmp(argv[1], "attach")) {
        struct attach_req req = {.ubi_num = ubi, .mtd_num = mtd, .vid_hdr_offset = 2048, .disable_fm = 1};
        rc = ioctl(fd, _IOW('o', 64, struct attach_req), &req);
        if (!rc && req.ubi_num != ubi) rc = -1;
    } else if (!strcmp(argv[1], "detach")) {
        snprintf(path, sizeof path, "/sys/class/ubi/ubi%d/mtd_num", ubi);
        if (number(path) != mtd) return 1;
        int32_t n = ubi;
        rc = ioctl(fd, _IOW('o', 65, int32_t), &n);
    } else { close(fd); return 2; }
    if (rc) perror("UBI operation");
    close(fd); return rc ? 1 : 0;
}
