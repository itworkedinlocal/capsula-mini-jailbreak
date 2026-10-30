#define _GNU_SOURCE
/* Temporary RAM only. No block/MTD opens, environment writes or boot flags. */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

static int clean_mounts(FILE *f) {
    char source[1024], target[1024], type[128], rest[4096];
    if (!f) return 0;
    unsigned rows=0;
    for (;;) {
        int fields=fscanf(f,"%1023s %1023s %127s",source,target,type);
        if(fields==EOF) return rows>0 && feof(f) && !ferror(f);
        if(fields!=3 || !fgets(rest,sizeof rest,f)) return 0;
        if (strcmp(type,"rootfs") && strcmp(type,"ramfs") && strcmp(type,"tmpfs") &&
            strcmp(type,"proc") && strcmp(type,"sysfs") && strcmp(type,"devtmpfs") &&
            strcmp(type,"devpts") && strcmp(type,"configfs")) return 0;
        rows++;
    }
}
static int clean_ubi(DIR *d) {
    struct dirent *entry;
    if (!d) return errno == ENOENT;
    errno = 0;
    while ((entry=readdir(d))) {
        if (!strncmp(entry->d_name,"ubi",3) && isdigit((unsigned char)entry->d_name[3])) return 0;
    }
    return errno == 0;
}
static int has_bytes(const char *path, const char *needle) {
    char buf[8192];
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0) return 0;
    ssize_t n=read(fd,buf,sizeof buf-1);close(fd);
    if(n<=0 || n==(ssize_t)sizeof buf-1) return 0;
    size_t len=strlen(needle);
    for(ssize_t i=0;i+(ssize_t)len<=n;i++) if(!memcmp(buf+i,needle,len)) return 1;
    return 0;
}
static int safe_environment(void) {
    struct utsname u;
    if(geteuid()!=0 || uname(&u) || strcmp(u.machine,"aarch64")) return 0;
    if(!has_bytes("/proc/cmdline","rdinit=/capsula-agent-init") ||
       !has_bytes("/proc/cmdline","reboot=cold") ||
       !has_bytes("/sys/firmware/devicetree/base/compatible","amlogic,meson-axg") ||
       !has_bytes("/sys/firmware/devicetree/base/psci/method","smc")) return 0;
    struct stat st;
    if(lstat("/capsula-run-id",&st) || !S_ISREG(st.st_mode) || st.st_size!=65) return 0;
    FILE *mounts=fopen("/proc/mounts","r");
    int okay=clean_mounts(mounts);if(mounts)fclose(mounts);
    if(!okay)return 0;
    DIR *ubi=opendir("/sys/class/ubi");
    okay=clean_ubi(ubi);if(ubi)closedir(ubi);
    return okay;
}
int main(int argc,char **argv) {
    if(argc!=2 || (strcmp(argv[1],"check") && strcmp(argv[1],"schedule"))) return 2;
    if(!safe_environment()) { fputs("REFUSED: restart requires clean detached A113X RAM environment\n",stderr); return 1; }
    if(!strcmp(argv[1],"check")) {puts("RESTART_READY");return 0;}
    int fd=open("/run/capsula-restart.armed",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0) {perror("REFUSED: restart already armed or unsafe marker");return 1;}
    close(fd);
    sync();
    pid_t child=fork();
    if(child<0) {unlink("/run/capsula-restart.armed");return 1;}
    if(child==0) {
        if(setsid()<0)_exit(1);
        int nullfd=open("/dev/null",O_RDWR);
        if(nullfd<0)_exit(1);
        for(int i=0;i<3;i++)if(dup2(nullfd,i)<0)_exit(1);
        if(nullfd>2)close(nullfd);
        sleep(2); /* Let host receive the nonce-framed acknowledgement. */
        if(!safe_environment())_exit(1);
        sync();
        reboot(RB_AUTOBOOT); /* PSCI SYSTEM_RESET(0), not RESTART2/update/recovery. */
        _exit(1);
    }
    puts("RESTART_ARMED");
    return 0;
}
