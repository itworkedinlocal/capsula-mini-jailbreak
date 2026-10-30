/* Read-only A113X NAND scanner. No erase, write or BBT-update ioctl exists here. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

struct mtd_info_user { uint8_t type; uint32_t flags,size,erasesize,writesize,oobsize; uint64_t padding; };
struct ecc_stats { uint32_t corrected,failed,badblocks,bbtblocks; };
#define GETINFO _IOR('M',1,struct mtd_info_user)
#define GETBAD _IOW('M',11,int64_t)
#define GETECC _IOR('M',18,struct ecc_stats)
typedef struct { uint32_t s[8]; uint64_t bytes; uint8_t buf[64]; size_t used; } Sha;
static const uint32_t k[64]={
 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
static uint32_t rr(uint32_t x,unsigned n){return (x>>n)|(x<<(32-n));}
static void compress(Sha *c,const uint8_t *p){
 uint32_t w[64];for(unsigned i=0;i<16;i++)w[i]=((uint32_t)p[4*i]<<24)|((uint32_t)p[4*i+1]<<16)|((uint32_t)p[4*i+2]<<8)|p[4*i+3];
 for(unsigned i=16;i<64;i++){uint32_t x=w[i-15],y=w[i-2];w[i]=w[i-16]+(rr(x,7)^rr(x,18)^(x>>3))+w[i-7]+(rr(y,17)^rr(y,19)^(y>>10));}
 uint32_t a=c->s[0],b=c->s[1],d=c->s[3],e=c->s[4],f=c->s[5],g=c->s[6],h=c->s[7],v=c->s[2];
 for(unsigned i=0;i<64;i++){uint32_t t=h+(rr(e,6)^rr(e,11)^rr(e,25))+((e&f)^(~e&g))+k[i]+w[i];uint32_t u=(rr(a,2)^rr(a,13)^rr(a,22))+((a&b)^(a&v)^(b&v));h=g;g=f;f=e;e=d+t;d=v;v=b;b=a;a=t+u;}
 c->s[0]+=a;c->s[1]+=b;c->s[2]+=v;c->s[3]+=d;c->s[4]+=e;c->s[5]+=f;c->s[6]+=g;c->s[7]+=h;
}
static void init(Sha*c){*c=(Sha){.s={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}};}
static void update(Sha*c,const void*data,size_t n){const uint8_t*p=data;c->bytes+=n;while(n){size_t z=64-c->used;if(z>n)z=n;memcpy(c->buf+c->used,p,z);c->used+=z;p+=z;n-=z;if(c->used==64){compress(c,c->buf);c->used=0;}}}
static void finish(Sha*c,char out[65]){uint64_t bits=c->bytes*8;uint8_t one=128,zero=0;update(c,&one,1);while(c->used!=56)update(c,&zero,1);uint8_t end[8];for(unsigned i=0;i<8;i++)end[7-i]=(uint8_t)(bits>>(8*i));update(c,end,8);for(unsigned i=0;i<8;i++)snprintf(out+8*i,9,"%08"PRIx32,c->s[i]);}
static void die(const char*s){perror(s);exit(1);}
static unsigned number(const char*s){char*e;errno=0;unsigned long n=strtoul(s,&e,10);if(errno||!*s||*e||n>UINT32_MAX)exit(2);return (unsigned)n;}
static void require_name(unsigned n,const char*expected){char path[128],line[128];snprintf(path,sizeof path,"/sys/class/mtd/mtd%u/name",n);FILE*f=fopen(path,"r");if(!f||!fgets(line,sizeof line,f))die("MTD name");fclose(f);line[strcspn(line,"\n")]=0;if(strcmp(line,expected)){fputs("Unexpected MTD name\n",stderr);exit(1);}}
static int open_mtd(unsigned n,struct mtd_info_user *m){char p[64];snprintf(p,sizeof p,"/dev/mtd%u",n);int fd=open(p,O_RDONLY|O_CLOEXEC);if(fd<0||ioctl(fd,GETINFO,m))die("MTD info");if(m->type!=4||m->erasesize!=131072||m->writesize!=2048||m->oobsize!=64){fputs("Unsupported NAND/ECC geometry\n",stderr);exit(1);}return fd;}
static int read_block(int fd,uint8_t*buf,uint32_t erase,int64_t offset){size_t n=0;while(n<erase){ssize_t r=pread(fd,buf+n,erase-n,offset+(int64_t)n);if(r<0&&errno==EINTR)continue;if(r<=0)return -1;n+=(size_t)r;}return 0;}
static int metadata_parts(int full){
 FILE*f=fopen("/capsula-device.conf","r");if(!f)die("device configuration");char line[128];unsigned count=0,data=99,writable=1;
 while(fgets(line,sizeof line,f)){unsigned n;if(sscanf(line,"MTD_COUNT=%u",&n)==1)count=n;if(sscanf(line,"DATA_INDEX=%u",&n)==1)data=n;if(sscanf(line,"DATA_WRITABLE=%u",&n)==1)writable=n;}fclose(f);
 if(!count||count>32||data>=count||writable>1||(full&&writable))return 1;
 struct mtd_info_user infos[32];uint64_t size=0;
 for(unsigned i=0;i<count;i++){int fd=open_mtd(i,&infos[i]);close(fd);if(!!(infos[i].flags&0x400)!=(i==data&&writable))return 1;size+=infos[i].size;}
 if(size>UINT32_MAX||size%131072)return 1;
 printf("{\"kind\":\"geometry\",\"size\":%"PRIu64",\"erasesize\":131072,\"writesize\":2048,\"oobsize\":64}\n",size);
 unsigned block=0;
 uint8_t *buf=full?malloc(131072):NULL;if(full&&!buf)die("malloc");
 for(unsigned i=0;i<count;i++){int fd=open_mtd(i,&infos[i]);for(int64_t off=0;off<infos[i].size;off+=131072){int64_t q=off;int bad=ioctl(fd,GETBAD,&q);if(bad<0)die("bad-block marker");printf("{\"kind\":\"block\",\"block\":%u,\"bad\":%s",block,bad?"true":"false");
 if(full&&!bad&&block>=64){struct ecc_stats a={0},z={0};if(ioctl(fd,GETECC,&a))die("ECC stats");int rc=read_block(fd,buf,131072,off);if(ioctl(fd,GETECC,&z))die("ECC stats");unsigned failed=z.failed-a.failed;if(rc)failed=failed?failed:1;printf(",\"corrected\":%u,\"failed\":%u",z.corrected-a.corrected,failed);if(!failed){Sha c;char hash[65];init(&c);update(&c,buf,131072);finish(&c,hash);printf(",\"sha256\":\"%s\"",hash);}}
 puts("}");block++;}close(fd);}
 free(buf);printf("{\"kind\":\"end\",\"mode\":\"%s\",\"blocks\":%u}\n",full?"scan":"metadata",block);return 0;
}
int main(int argc,char**argv){
 if(argc==3&&!strcmp(argv[1],"hash")){FILE*f=fopen(argv[2],"rb");if(!f)die("input");Sha c;init(&c);uint8_t buf[4096];size_t n;while((n=fread(buf,1,sizeof buf,f)))update(&c,buf,n);if(ferror(f))die("read");fclose(f);char out[65];finish(&c,out);puts(out);return 0;}
 if(argc==5&&!strcmp(argv[1],"read")){
  unsigned n=number(argv[2]),size=number(argv[3]),writable=number(argv[4]);if(writable>1)return 2;require_name(n,"data");struct mtd_info_user m={0};int fd=open_mtd(n,&m);if(m.size!=size||!!(m.flags&0x400)!=writable)return 1;
  struct ecc_stats before={0},after={0};if(ioctl(fd,GETECC,&before))die("ECC statistics");int out=open("/run/capsula-data.bin",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);if(out<0)die("RAM output");uint8_t*buf=malloc(m.erasesize);if(!buf)die("malloc");unsigned good=0,bad=0;
  for(int64_t off=0;off<m.size;off+=m.erasesize){int64_t q=off;int b=ioctl(fd,GETBAD,&q);if(b<0)die("bad-block marker");if(b){bad++;continue;}if(read_block(fd,buf,m.erasesize,off))die("ECC read");size_t put=0;while(put<m.erasesize){ssize_t z=write(out,buf+put,m.erasesize-put);if(z<0&&errno==EINTR)continue;if(z<=0)die("RAM write");put+=(size_t)z;}good++;}
  if(ioctl(fd,GETECC,&after))die("ECC statistics");free(buf);close(out);close(fd);printf("good_blocks=%u bad_blocks=%u bytes=%u corrected_delta=%u failed_delta=%u\n",good,bad,good*m.erasesize,after.corrected-before.corrected,after.failed-before.failed);if(after.failed!=before.failed){unlink("/run/capsula-data.bin");return 1;}return 0;
 }
 if(argc!=2||(strcmp(argv[1],"scan")&&strcmp(argv[1],"metadata")))return 2;
 int full=!strcmp(argv[1],"scan");if(access("/capsula-device.conf",R_OK)==0)return metadata_parts(full);require_name(0,"capsula-scan");struct mtd_info_user m={0};int fd=open_mtd(0,&m);if(m.flags&0x400){fputs("Writable scan device refused\n",stderr);return 1;}
 uint8_t*buf=malloc(m.erasesize);if(!buf)die("malloc");unsigned count=m.size/m.erasesize;
 printf("{\"kind\":\"geometry\",\"size\":%u,\"erasesize\":%u,\"writesize\":%u,\"oobsize\":%u}\n",m.size,m.erasesize,m.writesize,m.oobsize);
 for(unsigned b=0;b<count;b++){
  int64_t off=(int64_t)b*m.erasesize,q=off;int bad=ioctl(fd,GETBAD,&q);if(bad<0)die("bad-block marker");
  printf("{\"kind\":\"block\",\"block\":%u,\"bad\":%s",b,bad?"true":"false");
  /* ROM/reserved data use vendor ECC and must not be reclassified by BCH8. */
  if(full&&!bad&&off>=0x800000){struct ecc_stats a={0},z={0};if(ioctl(fd,GETECC,&a))die("ECC stats");int rc=read_block(fd,buf,m.erasesize,off);if(ioctl(fd,GETECC,&z))die("ECC stats");unsigned failed=z.failed-a.failed;if(rc)failed=failed?failed:1;printf(",\"corrected\":%u,\"failed\":%u",z.corrected-a.corrected,failed);if(!failed){Sha c;char hash[65];init(&c);update(&c,buf,m.erasesize);finish(&c,hash);printf(",\"sha256\":\"%s\"",hash);}}
  puts("}");fflush(stdout);
 }
 printf("{\"kind\":\"end\",\"mode\":\"%s\",\"blocks\":%u}\n",argv[1],count);free(buf);close(fd);return 0;
}
