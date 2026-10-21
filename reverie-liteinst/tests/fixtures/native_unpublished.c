#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/prctl.h>
#include <ucontext.h>
#include <dlfcn.h>

extern long raw_call(long,long,long,long,long,long,long);
extern long split_call(long,long,long,long,long,long,long);
extern long contrast_call(long,long,long,long,long,long,long);
extern long contrast_tail_call(void);
extern long tail_call(long,long,long,long,long,long,long,long);
extern unsigned char tail_site[],tail_end[];
extern long cache_call(long,long,long,long,long,long,long);
extern long boundary_call(long,long,long,long,long,long,long);
extern unsigned char cache_page[],cache_page_end[],cache_site[],cache_end[];
extern unsigned char boundary_page[],boundary_page_end[],boundary_site[],boundary_end[];
extern const unsigned char __GNU_EH_FRAME_HDR[];
extern unsigned char split_site[],split_end[],contrast_site[],contrast_entry[],contrast_end[];
extern void guest_restorer(void);
/* Address-taken entry is real data as well as an executable symbol/branch. */
void *volatile contrast_anchor=contrast_entry;
static const unsigned char ORIGINAL[8]={0x0f,0x05,0x31,0xc9,0x31,0xd2,0x90,0x90};
static unsigned char split_before[64],contrast_before[64];
static size_t split_len,contrast_len;
static int errors;
static unsigned char bulk[65536],scratch[4096];
static volatile sig_atomic_t handler_calls;
static volatile long handler_result;
static int handler_mutates_tail,handler_mutates_pkru;
static unsigned requested_frame_pkru,frame_pkru_before,frame_pkru_after,frame_pkru_offset;
static volatile sig_atomic_t frame_valid;
struct ka { uint64_t handler,flags,restorer,mask; };
#define SA_RESTORER_RAW 0x04000000UL
static long r(long n,long a,long b,long c,long d,long e,long f){return raw_call(n,a,b,c,d,e,f);}
static long rw(long n,int fd,void *p,size_t z){return split_call(n,fd,(long)p,(long)z,0,0,0);}
static size_t slen(const char*s){size_t n=0;while(s[n])++n;return n;}
static int same(const char*a,const char*b){size_t i=0;while(a[i]&&a[i]==b[i])++i;return a[i]==b[i];}
static void text(const char*s){size_t n=slen(s);if(r(SYS_write,1,(long)s,n,0,0,0)!=(long)n)r(SYS_exit_group,90,0,0,0,0,0);}
static void number(long v){char b[32];size_t n=0;unsigned long u=v<0?0UL-(unsigned long)v:(unsigned long)v;if(v<0)text("-");do{b[n++]=(char)('0'+u%10);u/=10;}while(u);while(n){char c=b[--n];if(r(SYS_write,1,(long)&c,1,0,0,0)!=1)r(SYS_exit_group,90,0,0,0,0,0);}}
static void hex(const unsigned char*p,size_t n){static const char d[]="0123456789abcdef";char b[128];if(n>64)r(SYS_exit_group,91,0,0,0,0,0);for(size_t i=0;i<n;i++){b[2*i]=d[p[i]>>4];b[2*i+1]=d[p[i]&15];}if(r(SYS_write,1,(long)b,n*2,0,0,0)!=(long)(n*2))r(SYS_exit_group,90,0,0,0,0,0);}
static void address(const void*p){uintptr_t v=(uintptr_t)p;unsigned char b[8];for(unsigned i=0;i<8;i++)b[7-i]=(unsigned char)(v>>(i*8));hex(b,8);}
static void obs(const char*name,long got,long expected){text("OBS name=");text(name);text(" result=");number(got);text(" expected=");number(expected);text("\n");if(got!=expected)errors++;}
static void policy_obs(const char*name,long got){text("POLICY name=");text(name);text(" result=");number(got);text("\n");}
static void need(int ok,const char*name){if(!ok){text("ERROR ");text(name);text("\n");r(SYS_exit_group,20,0,0,0,0,0);}}
static void closefd(int fd){need(r(SYS_close,fd,0,0,0,0,0)==0,"close");}
static void pipefds(int fd[2],int flags){need(r(SYS_pipe2,(long)fd,flags,0,0,0,0)==0,"pipe2");}
static void seed(int fd,const void*p,size_t n){need(r(SYS_write,fd,(long)p,n,0,0,0)==(long)n,"seed-write");}
static void ready(long nr,void *buffer,size_t count,const void *site){uint64_t message[6]={0x554e505542525731ULL,(uint64_t)nr,3,(uintptr_t)buffer,count,(uintptr_t)site};need(r(SYS_write,4,(long)message,sizeof message,0,0,0)==(long)sizeof message,"ready-fd4");}
static void bytes(const char*name,const unsigned char*p,size_t n){text("BYTES name=");text(name);text(" value=");hex(p,n);text("\n");}
static void signal_handler(int sig,siginfo_t*info,void*context){
 (void)sig;(void)info;handler_calls++;
 if(handler_mutates_tail)tail_site[3]=0x22;
 if(handler_mutates_pkru){
  ucontext_t *u=context;unsigned char *fp=(void*)u->uc_mcontext.fpregs;
  if(fp){uint32_t magic,size;uint64_t features,state,comp;
   __builtin_memcpy(&magic,fp+464,4);__builtin_memcpy(&features,fp+472,8);__builtin_memcpy(&size,fp+480,4);
   __builtin_memcpy(&state,fp+512,8);__builtin_memcpy(&comp,fp+520,8);
   if(magic==0x46505853U&&(features&(1ULL<<9))&&(state&(1ULL<<9))&&!(comp>>63)&&size>=frame_pkru_offset+4){
    __builtin_memcpy(&frame_pkru_before,fp+frame_pkru_offset,4);
    __builtin_memcpy(fp+frame_pkru_offset,&requested_frame_pkru,4);
    __builtin_memcpy(&frame_pkru_after,fp+frame_pkru_offset,4);frame_valid=1;
   }
  }
 }
 handler_result=rw(SYS_write,5,(void*)"H",1);
}
static void install_handler(int restart){struct ka a={(uintptr_t)signal_handler,SA_SIGINFO|SA_RESTORER_RAW|(restart?SA_RESTART:0),(uintptr_t)guest_restorer,0};need(r(SYS_rt_sigaction,SIGUSR1,(long)&a,0,8,0,0)==0,"rt_sigaction");}
/* Only this diagnostic fixture changes its original SIGTRAP action before ctor. */
static void unknown_trap(int sig,siginfo_t*info,void*context){(void)sig;(void)info;(void)context;}
static void before_ctors(int argc,char**argv,char**env){(void)env;if(argc==2&&(same(argv[1],"trap-ignore")||same(argv[1],"prior-ignore")||same(argv[1],"prior-unknown"))){int unknown=same(argv[1],"prior-unknown");struct ka a={unknown?(uintptr_t)unknown_trap:1,unknown?(SA_SIGINFO|SA_RESTORER_RAW):0,unknown?(uintptr_t)guest_restorer:0,0};if(r(SYS_rt_sigaction,SIGTRAP,(long)&a,0,8,0,0)!=0)r(SYS_exit_group,21,0,0,0,0,0);}}
__attribute__((used,section(".preinit_array"))) static void(*const preinit)(int,char**,char**)=before_ctors;
static void windows_before(void){
 split_len=(size_t)((uintptr_t)split_end-(uintptr_t)split_site);contrast_len=(size_t)((uintptr_t)contrast_end-(uintptr_t)contrast_site);
 need(split_len<=64&&contrast_len<=64&&split_len>=8&&contrast_len>=8,"window-size");
 need(((uintptr_t)split_site&63)==60&&((uintptr_t)contrast_site&63)==60,"window-offset");
 need((uintptr_t)contrast_entry==(uintptr_t)contrast_site+2&&contrast_anchor==contrast_entry,"contrast-entry");
 need(contrast_tail_call()==23,"contrast-live-entry");
 for(size_t i=0;i<8;i++)need(split_site[i]==ORIGINAL[i]&&contrast_site[i]==ORIGINAL[i],"literal-original");
 for(size_t i=0;i<split_len;i++)split_before[i]=split_site[i];
 for(size_t i=0;i<contrast_len;i++)contrast_before[i]=contrast_site[i];
 text("SITE split=0x");address(split_site);text(" contrast=0x");address(contrast_site);text(" entry=0x");address(contrast_entry);text("\n");
 bytes("split-before",split_before,split_len);bytes("contrast-before",contrast_before,contrast_len);
}
static void windows_after(void){int equal=1;for(size_t i=0;i<split_len;i++)if(split_site[i]!=split_before[i])equal=0;for(size_t i=0;i<contrast_len;i++)if(contrast_site[i]!=contrast_before[i])equal=0;bytes("split-after",split_site,split_len);bytes("contrast-after",contrast_site,contrast_len);obs("source-unchanged",equal,1);}
static void data_case(int partial){int f[2];unsigned char b[8]={0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc};pipefds(f,0);seed(f[1],partial?"abc":"abcdef",partial?3:6);closefd(f[1]);obs("read",rw(SYS_read,f[0],b,sizeof b),partial?3:6);bytes("read",b,sizeof b);for(size_t i=0;i<(partial?3UL:6UL);i++)if(b[i]!=(unsigned char)("abcdef"[i]))errors++;obs("eof-1",rw(SYS_read,f[0],b,sizeof b),0);obs("eof-2",rw(SYS_read,f[0],b,sizeof b),0);closefd(f[0]);}
static void eof_case(void){int f[2];unsigned char b=0xcc;pipefds(f,0);closefd(f[1]);obs("eof",rw(SYS_read,f[0],&b,1),0);obs("untouched",b,0xcc);closefd(f[0]);}
static void zero_case(void){int f[2];unsigned char b=0xcc;pipefds(f,0);seed(f[1],"Z",1);obs("zero-read",rw(SYS_read,f[0],&b,0),0);obs("zero-write",rw(SYS_write,f[1],&b,0),0);obs("zero-untouched",b,0xcc);closefd(f[1]);obs("remaining",r(SYS_read,f[0],(long)&b,1,0,0,0),1);obs("literal",b,'Z');closefd(f[0]);}
static long capacity(int fd){long cap=r(SYS_fcntl,fd,F_GETPIPE_SZ,0,0,0,0);need(cap>=4096&&cap<=65536&&cap%4096==0,"bounded-pipe-capacity");return cap;}
static void fill(int fd,long count,unsigned char byte){for(size_t i=0;i<sizeof bulk;i++)bulk[i]=byte;need(count>=0&&count<=65536,"fill-count");if(count)seed(fd,bulk,(size_t)count);}
static void partial_write_case(void){int f[2];pipefds(f,O_NONBLOCK);long cap=capacity(f[1]);fill(f[1],cap-4096,'A');for(size_t i=0;i<8192;i++)bulk[i]='B';long got=rw(SYS_write,f[1],bulk,8192);obs("partial-write",got,4096);closefd(f[1]);long total=0,wrong=0;for(int n=0;n<17;n++){long k=r(SYS_read,f[0],(long)scratch,sizeof scratch,0,0,0);need(k>=0,"drain");if(!k)break;for(long i=0;i<k;i++){unsigned char expected=(total+i<cap-4096)?'A':'B';if(scratch[i]!=expected)wrong++;}total+=k;}obs("drained",total,cap);obs("literal-errors",wrong,0);closefd(f[0]);}
static void again_case(int write_case){int f[2];unsigned char b=0xcc;pipefds(f,O_NONBLOCK);if(write_case)fill(f[1],capacity(f[1]),'F');obs(write_case?"eagain-write":"eagain-read",rw(write_case?SYS_write:SYS_read,write_case?f[1]:f[0],&b,1),-EAGAIN);closefd(f[0]);closefd(f[1]);}
static void badfd_case(void){unsigned char b=0;obs("ebadf-read",rw(SYS_read,-1,&b,1),-EBADF);obs("ebadf-write",rw(SYS_write,-1,&b,1),-EBADF);}
static void fault_case(void){int f[2];unsigned char b=0;pipefds(f,O_NONBLOCK);seed(f[1],"Q",1);obs("efault-read",rw(SYS_read,f[0],(void*)1,1),-EFAULT);obs("efault-write",rw(SYS_write,f[1],(void*)1,1),-EFAULT);obs("remaining",r(SYS_read,f[0],(long)&b,1,0,0,0),1);obs("literal",b,'Q');obs("nothing-written",r(SYS_read,f[0],(long)&b,1,0,0,0),-EAGAIN);closefd(f[0]);closefd(f[1]);}
static unsigned pkru(void){unsigned a,d;__asm__ volatile("rdpkru":"=a"(a),"=d"(d):"c"(0));(void)d;return a;}
static void setpkru(unsigned value){__asm__ volatile("wrpkru; lfence"::"a"(value),"c"(0),"d"(0):"memory");}
static void pkey_case(void){
 unsigned a,b,c,d;__asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(7),"c"(0));(void)a;(void)b;(void)d;need((c&(1U<<4))!=0,"OSPKE-required");
 unsigned entry_rights=pkru();long key=r(SYS_pkey_alloc,0,0,0,0,0,0);unsigned allocated_rights=pkru();need(key>0&&key<16,"pkey_alloc");
 long mapped=r(SYS_mmap,0,8192,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(mapped>0,"mmap");unsigned char*p=(void*)mapped;p[0]='K';p[4096]='N';need(r(SYS_pkey_mprotect,mapped,4096,PROT_READ|PROT_WRITE,key,0,0)==0,"pkey_mprotect");
 int f[2];pipefds(f,O_NONBLOCK);seed(f[1],"Q",1);unsigned original=pkru(),denied=original|(3U<<(2*(unsigned)key));setpkru(denied);
 long rr=rw(SYS_read,f[0],p,1);unsigned p1=pkru();long wr=rw(SYS_write,f[1],p,1);unsigned p2=pkru();long nr=rw(SYS_read,f[0],p+4096,1);unsigned p3=pkru();long nw=rw(SYS_write,f[1],p+4096,1);unsigned p4=pkru();setpkru(original);
 text("PKRU key=");number(key);text(" entry=");number(entry_rights);text(" after-alloc=");number(allocated_rights);text(" original=");number(original);text(" denied=");number(denied);text(" after-restore=");number(pkru());text("\n");
 obs("pkey-read",rr,-EFAULT);obs("pkey-write",wr,-EFAULT);obs("neighbor-read",nr,1);obs("neighbor-write",nw,1);obs("rights-1",p1,denied);obs("rights-2",p2,denied);obs("rights-3",p3,denied);obs("rights-4",p4,denied);obs("neighbor-literal",p[4096],'Q');obs("denied-unchanged",p[0],'K');unsigned char q=0;obs("neighbor-remaining",r(SYS_read,f[0],(long)&q,1,0,0,0),1);obs("neighbor-literal-remaining",q,'Q');closefd(f[0]);closefd(f[1]);need(r(SYS_munmap,mapped,8192,0,0,0,0)==0,"munmap");need(r(SYS_pkey_free,key,0,0,0,0,0)==0,"pkey_free");
}
static void contrast_case(void){int f[2];unsigned char q=0xcc;pipefds(f,O_NONBLOCK);seed(f[1],"C",1);long got=contrast_call(SYS_read,f[0],(long)&q,1,0,0,0);policy_obs("contrast-read",got);bytes("contrast-data",&q,1);if(got==1){if(q!='C')errors++;obs("contrast-residual",r(SYS_read,f[0],(long)&q,1,0,0,0),-EAGAIN);}else if(got==-EOPNOTSUPP){if(q!=0xcc)errors++;obs("contrast-residual",r(SYS_read,f[0],(long)&q,1,0,0,0),1);obs("contrast-residual-literal",q,'C');}else errors++;closefd(f[0]);closefd(f[1]);}
static void other_case(void){int f[2];unsigned char q=0;pipefds(f,0);seed(f[1],"O",1);obs("qualifying-read",rw(SYS_read,f[0],&q,1),1);obs("literal",q,'O');long got=split_call(SYS_getpid,0,0,0,0,0,0);policy_obs("same-site-getpid",got);long actual=r(SYS_getpid,0,0,0,0,0,0);if(got!=-EOPNOTSUPP&&got!=actual)errors++;closefd(f[0]);closefd(f[1]);}
/* Explicit guest-owned rights case, separate from the legacy pkey_alloc loss. */
static void pkey_permission_case(void) {
 unsigned a,b,c,d;
 __asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(7),"c"(0));
 (void)a;(void)b;(void)d;need((c&(1U<<4))!=0,"OSPKE-required");
 unsigned entry=pkru();
 long key=r(SYS_pkey_alloc,0,0,0,0,0,0);need(key>0&&key<16,"pkey_alloc");
 unsigned allocated=pkru(),bits=3U<<(2*(unsigned)key),allowed=allocated&~bits;
 /* Initialize this guest-owned key deliberately, regardless of the separately
  * recorded allocation-side-effect defect. No claim that pkey_alloc passed. */
 setpkru(allowed);
 long mapped=r(SYS_mmap,0,8192,PROT_READ|PROT_WRITE,
               MAP_PRIVATE|MAP_ANONYMOUS,-1,0);need(mapped>0,"mmap");
 unsigned char*p=(void*)mapped;
 need(r(SYS_pkey_mprotect,mapped,4096,PROT_READ|PROT_WRITE,key,0,0)==0,"pkey_mprotect");
 p[0]='K';p[4096]='N';
 int f[2];pipefds(f,O_NONBLOCK);seed(f[1],"Q",1);
 unsigned denied=allowed|bits;setpkru(denied);
 long rr=rw(SYS_read,f[0],p,1);unsigned p1=pkru();
 long wr=rw(SYS_write,f[1],p,1);unsigned p2=pkru();
 long nr=rw(SYS_read,f[0],p+4096,1);unsigned p3=pkru();
 long nw=rw(SYS_write,f[1],p+4096,1);unsigned p4=pkru();
 setpkru(allowed);
 text("PKRU_SETUP key=");number(key);text(" entry=");number(entry);
 text(" after-alloc=");number(allocated);text(" explicit-allowed=");number(allowed);
 text(" denied=");number(denied);text("\n");
 obs("explicit-pkey-read",rr,-EFAULT);obs("explicit-pkey-write",wr,-EFAULT);
 obs("explicit-neighbor-read",nr,1);obs("explicit-neighbor-write",nw,1);
 obs("explicit-rights-1",p1,denied);obs("explicit-rights-2",p2,denied);
 obs("explicit-rights-3",p3,denied);obs("explicit-rights-4",p4,denied);
 obs("explicit-neighbor-literal",p[4096],'Q');obs("explicit-denied-unchanged",p[0],'K');
 unsigned char q=0;obs("explicit-remaining",r(SYS_read,f[0],(long)&q,1,0,0,0),1);
 obs("explicit-remaining-literal",q,'Q');
 closefd(f[0]);closefd(f[1]);
 /* Remove every mapping before freeing its key; restore entry rights only
  * afterwards, when no remaining guest byte depends on the key. */
 need(r(SYS_munmap,mapped,8192,0,0,0,0)==0,"munmap");
 need(r(SYS_pkey_free,key,0,0,0,0,0)==0,"pkey_free");
 setpkru(entry);obs("explicit-entry-rights-restored",pkru(),entry);
}

static void async_case(const char*name){unsigned char q=0xcc;int partial=same(name,"handler-partial");int restarting=same(name,"handler-restart");int caught=partial||restarting||same(name,"handler-eintr");if(caught)install_handler(restarting);if(partial){need(capacity(3)==4096,"parent-pipe-capacity4096");for(size_t i=0;i<8192;i++)bulk[i]='W';}ready(partial?SYS_write:SYS_read,partial?(void*)bulk:(void*)&q,partial?8192:1,split_site);long got=rw(partial?SYS_write:SYS_read,3,partial?(void*)bulk:(void*)&q,partial?8192:1);obs("async-io",got,partial?4096:(same(name,"handler-eintr")?-EINTR:1));if(!partial&&!same(name,"handler-eintr"))obs("async-literal",q,'R');if(caught){obs("handler-calls",handler_calls,1);obs("handler-write",handler_result,1);}else obs("handler-calls",handler_calls,0);}

static void profile_case(void){int f[2];unsigned char q=0xcc;pipefds(f,O_NONBLOCK);seed(f[1],"P",1);long got=rw(SYS_read,f[0],&q,1);policy_obs("prior-profile-read",got);if(got==1){obs("profile-literal",q,'P');obs("profile-residual",r(SYS_read,f[0],(long)&q,1,0,0,0),-EAGAIN);}else if(got==-EOPNOTSUPP){obs("profile-untouched",q,0xcc);obs("profile-residual",r(SYS_read,f[0],(long)&q,1,0,0,0),1);obs("profile-residual-literal",q,'P');}else errors++;closefd(f[0]);closefd(f[1]);}
static void sigpipe_ignore_case(void){struct ka a={1,0,0,0};need(r(SYS_rt_sigaction,SIGPIPE,(long)&a,0,8,0,0)==0,"sigpipe-ignore");int f[2];pipefds(f,0);closefd(f[0]);obs("sigpipe-write",rw(SYS_write,f[1],(void*)"W",1),-EPIPE);closefd(f[1]);}
static void sigpipe_default_case(void){struct ka a={0,0,0,0};need(r(SYS_rt_sigaction,SIGPIPE,(long)&a,0,8,0,0)==0,"sigpipe-default");for(size_t i=0;i<sizeof bulk;i++)bulk[i]='W';ready(SYS_write,bulk,1,split_site);obs("sigpipe-write",rw(SYS_write,3,bulk,1),-EPIPE);}
static void live_tail_case(void){
 unsigned char before[64];size_t len=(uintptr_t)tail_end-(uintptr_t)tail_site;need(len<=64&&len>=8,"tail-size");
 static const unsigned char literal[8]={0x0f,0x05,0xba,0x11,0,0,0,0x90};
 for(size_t i=0;i<8;i++)need(tail_site[i]==literal[i],"tail-literal");
 for(size_t i=0;i<len;i++)before[i]=tail_site[i];
 need(((uintptr_t)tail_site&63)==60,"tail-offset");bytes("tail-before",before,len);
 uintptr_t page=(uintptr_t)tail_site&~(uintptr_t)4095;
 need(r(SYS_mprotect,page,4096,PROT_READ|PROT_WRITE|PROT_EXEC,0,0,0)==0,"tail-write-enable");
 handler_mutates_tail=1;install_handler(1);unsigned char q=0xcc;unsigned marker=0;
 ready(SYS_read,&q,1,tail_site);long got=tail_call(SYS_read,3,(long)&q,1,0,0,0,(long)&marker);
 obs("live-tail-read",got,1);obs("live-tail-literal",q,'R');obs("live-tail-marker",marker,0x22);
 obs("live-tail-handler",handler_calls,1);obs("live-tail-handler-write",handler_result,1);
 bytes("tail-after",tail_site,len);for(size_t i=0;i<len;i++)if(tail_site[i]!=(i==3?0x22:before[i]))errors++;
}
static void frame_pkru_case(void){
 unsigned a,b,c,d;__asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(7),"c"(0));(void)a;(void)b;(void)d;need((c&(1U<<4))!=0,"OSPKE-required");
 __asm__ volatile("cpuid":"=a"(a),"=b"(b),"=c"(c),"=d"(d):"a"(13),"c"(9));need(a>=4&&b>=576&&b<=16380,"PKRU-standard-frame-offset");frame_pkru_offset=b;
 unsigned entry=pkru();long key=r(SYS_pkey_alloc,0,0,0,0,0,0);need(key>0&&key<16,"pkey_alloc");unsigned bits=3U<<(2*(unsigned)key),allowed=pkru()&~bits;setpkru(allowed);
 requested_frame_pkru=allowed|bits;handler_mutates_pkru=1;install_handler(1);unsigned char q=0xcc;
 ready(SYS_read,&q,1,split_site);long got=rw(SYS_read,3,&q,1);unsigned returned=pkru();setpkru(allowed);
 obs("frame-read",got,1);obs("frame-literal",q,'R');obs("frame-valid",frame_valid,1);
 obs("frame-before",frame_pkru_before,allowed);obs("frame-after",frame_pkru_after,requested_frame_pkru);obs("frame-returned",returned,requested_frame_pkru);
 obs("frame-handler",handler_calls,1);obs("frame-handler-write",handler_result,1);
 need(r(SYS_pkey_free,key,0,0,0,0,0)==0,"pkey_free");setpkru(entry);obs("frame-entry-restored",pkru(),entry);
}

static long cache_read(int boundary,int fd,unsigned char*q){
 return (boundary?boundary_call:cache_call)(SYS_read,fd,(long)q,1,0,0,0);
}
static void replace_page(uintptr_t page,unsigned char*site,int change_tail,int executable){
 unsigned char copy[4096];for(size_t i=0;i<sizeof copy;i++)copy[i]=((unsigned char*)page)[i];
 if(change_tail){uintptr_t offset=(uintptr_t)site+3-page;need(offset<4096,"changed-tail-in-page");copy[offset]=0xd2;}
 long fd=r(SYS_memfd_create,(long)"native-unpublished-map",1,0,0,0,0);need(fd>=0,"memfd_create");
 seed((int)fd,copy,sizeof copy);
 long mapped=r(SYS_mmap,page,4096,PROT_READ|(executable?PROT_EXEC:0),MAP_PRIVATE|MAP_FIXED,fd,0);
 need(mapped==(long)page,"fixed-page-replacement");long wrong=0;for(size_t i=0;i<sizeof copy;i++)if(((unsigned char*)page)[i]!=copy[i])wrong++;obs("replacement-full-page",wrong,0);closefd((int)fd);
}
static void exact_cache_window(const unsigned char*site,const unsigned char*before,int changed){
 int equal=1;for(size_t i=0;i<25;i++)if(site[i]!=(changed&&i==3?0xd2:before[i]))equal=0;
 obs("cache-exact-window",equal,1);bytes("cache-after",site,25);
}
static void cached_refusal_case(const char*name){
 int boundary=same(name,"boundary-replace"),changed=same(name,"cache-mutate")||same(name,"mapping-replace")||boundary;
 int metadata=same(name,"metadata-replace")||same(name,"metadata-read-restored");
 unsigned char*site=boundary?boundary_site:cache_site;unsigned char*end=boundary?boundary_end:cache_end;
 unsigned char before[25];need((uintptr_t)end-(uintptr_t)site==25,"cache-window25");for(size_t i=0;i<25;i++)before[i]=site[i];
 for(size_t i=0;i<8;i++)need(before[i]==ORIGINAL[i],"cache-literal");
 need(((uintptr_t)site&63)==(boundary?62:60),"cache-offset");
 need(((uintptr_t)cache_page&4095)==0&&(uintptr_t)cache_page_end-(uintptr_t)cache_page==4096,"dedicated-cache-page");
 need(((uintptr_t)boundary_page&4095)==0&&(uintptr_t)boundary_page_end-(uintptr_t)boundary_page==8192,"dedicated-boundary-pages");
 text("CACHE site=0x");address(site);text(" metadata=0x");address(__GNU_EH_FRAME_HDR);text("\n");bytes("cache-before",before,25);
 if(same(name,"cache-mutate"))need(r(SYS_mprotect,(uintptr_t)cache_page,4096,PROT_READ|PROT_WRITE|PROT_EXEC,0,0,0)==0,"cache-write-enable");
 int f[2];unsigned char q=0xcc;pipefds(f,O_NONBLOCK);seed(f[1],"F",1);
 obs("cache-initial-read",cache_read(boundary,f[0],&q),1);obs("cache-initial-literal",q,'F');
 seed(f[1],"B",1);q=0xcc;obs("cache-second-read",cache_read(boundary,f[0],&q),1);obs("cache-second-literal",q,'B');
 /* A capability absent from the first call must never pass the negative part. */
 need(errors==0,"initial-capability-required");
 /* Non-PIE weak undefined functions can be resolved to literal zero by the
  * static linker. Query the actual constructor-bearing loaded leaf instead. */
 uint64_t(*trap_count)(uint64_t)=dlsym(RTLD_DEFAULT,"reverie_liteinst_site_trap_count");
 uint64_t(*hook_count)(uint64_t)=dlsym(RTLD_DEFAULT,"reverie_liteinst_site_hook_count");
 need((trap_count!=0)==(hook_count!=0),"both-route-counters-required");
 if(trap_count){uint64_t traps=trap_count((uintptr_t)site),hooks=hook_count((uintptr_t)site);text("COUNTS present=1 trap=");number(traps);text(" hook=");number(hooks);text("\n");obs("cache-traps",traps,2);obs("cache-installed-hooks",hooks,0);}
 else text("COUNTS present=0\n");
 if(same(name,"cache-mutate"))site[3]=0xd2;
 else if(same(name,"metadata-replace"))replace_page((uintptr_t)__GNU_EH_FRAME_HDR&~(uintptr_t)4095,site,0,0);
 else if(same(name,"metadata-read-restored")){
  uintptr_t page=(uintptr_t)__GNU_EH_FRAME_HDR&~(uintptr_t)4095;unsigned char copy[4096];for(size_t i=0;i<sizeof copy;i++)copy[i]=((unsigned char*)page)[i];
  /* Do not print or dereference the protected metadata/string page between
   * these calls. Only the aligned raw helper and ordinary C text run there. */
  long down=r(SYS_mprotect,page,4096,PROT_NONE,0,0,0);
  long up=r(SYS_mprotect,page,4096,PROT_READ,0,0,0);
  obs("metadata-read-removed",down,0);obs("metadata-read-restored",up,0);need(up==0,"metadata-restored-before-observation");
  long wrong=0;for(size_t i=0;i<sizeof copy;i++)if(((unsigned char*)page)[i]!=copy[i])wrong++;
  obs("restored-full-page",wrong,0);
 }
 else if(same(name,"pkey-overlap"))obs("pkey-mprotect-key0",r(SYS_pkey_mprotect,(uintptr_t)cache_page,4096,PROT_READ|PROT_EXEC,0,0,0),0);
 else replace_page(boundary?(uintptr_t)site+2:(uintptr_t)cache_page,site,1,1);
 text("CHANGED start=0x");address(boundary?(void*)((uintptr_t)site+2):(metadata?(void*)((uintptr_t)__GNU_EH_FRAME_HDR&~(uintptr_t)4095):(void*)cache_page));text(" len=4096\n");
 seed(f[1],"S",1);q=0xcc;long got=cache_read(boundary,f[0],&q);policy_obs("cached-after-change",got);
 if(got==1){obs("cache-native-literal",q,'S');obs("cache-native-residual",r(SYS_read,f[0],(long)&q,1,0,0,0),-EAGAIN);}
 else if(got==-EOPNOTSUPP){obs("cache-refused-untouched",q,0xcc);obs("cache-refused-residual",r(SYS_read,f[0],(long)&q,1,0,0,0),1);obs("cache-refused-residual-literal",q,'S');}
 else errors++;
 exact_cache_window(site,before,changed);closefd(f[0]);closefd(f[1]);
}
struct fork_report { long value[7]; unsigned char window[32]; };
_Static_assert(sizeof(struct fork_report)==88,"fixed fork report ABI");
static void fork_cache_case(void){
 unsigned char before[25];for(size_t i=0;i<25;i++)before[i]=cache_site[i];bytes("cache-before",before,25);
 text("CACHE site=0x");address(cache_site);text("\n");
 need(r(SYS_mprotect,(uintptr_t)cache_page,4096,PROT_READ|PROT_WRITE|PROT_EXEC,0,0,0)==0,"fork-cache-write-enable");
 int initial[2];unsigned char q=0;pipefds(initial,O_NONBLOCK);seed(initial[1],"F",1);
 obs("fork-initial-read",cache_read(0,initial[0],&q),1);obs("fork-initial-literal",q,'F');closefd(initial[0]);closefd(initial[1]);need(errors==0,"fork-initial-capability-required");
 int result[2];pipefds(result,0);long child=r(SYS_fork,0,0,0,0,0,0);need(child>=0,"native-fork");
 if(child==0){
  closefd(result[0]);int f[2];pipefds(f,O_NONBLOCK);seed(f[1],"C",1);q=0xcc;
  struct fork_report record={0};long*report=record.value;report[0]=cache_read(0,f[0],&q);report[1]=q;cache_site[3]=0xd2;
  seed(f[1],"D",1);q=0xcc;report[2]=cache_read(0,f[0],&q);report[3]=q;
  report[4]=r(SYS_read,f[0],(long)&q,1,0,0,0);report[5]=q;report[6]=1;
  for(size_t i=0;i<25;i++)if(cache_site[i]!=(i==3?0xd2:before[i]))report[6]=0;
  for(size_t i=0;i<25;i++)record.window[i]=cache_site[i];
  seed(result[1],&record,sizeof record);r(SYS_exit_group,0,0,0,0,0,0);__builtin_unreachable();
 }
 closefd(result[1]);struct fork_report record={0};long*report=record.value;obs("fork-report-read",r(SYS_read,result[0],(long)&record,sizeof record,0,0,0),sizeof record);closefd(result[0]);need(errors==0,"complete-fork-report-required");bytes("fork-child-cache",record.window,25);
 int status=-1;obs("fork-wait",r(SYS_wait4,child,(long)&status,0,0,0,0),child);obs("fork-child-status",status,0);
 obs("fork-child-cached-read",report[0],1);obs("fork-child-cached-literal",report[1],'C');policy_obs("fork-child-after-change",report[2]);
 if(report[2]==1){obs("fork-child-native-literal",report[3],'D');obs("fork-child-native-residual",report[4],-EAGAIN);}
 else if(report[2]==-EOPNOTSUPP){obs("fork-child-refused-untouched",report[3],0xcc);obs("fork-child-refused-residual",report[4],1);obs("fork-child-refused-literal",report[5],'D');}
 else errors++;
 obs("fork-child-exact-window",report[6],1);int f[2];pipefds(f,O_NONBLOCK);seed(f[1],"P",1);q=0;
 obs("fork-parent-read",cache_read(0,f[0],&q),1);obs("fork-parent-literal",q,'P');closefd(f[0]);closefd(f[1]);exact_cache_window(cache_site,before,0);
}

int main(int argc,char**argv){need(argc==2,"one-fixed-case-required");const char*name=argv[1];windows_before();text("CASE ");text(name);text("\n");
 if(same(name,"data"))data_case(0);else if(same(name,"eof"))eof_case();else if(same(name,"zero"))zero_case();else if(same(name,"partial-read"))data_case(1);else if(same(name,"partial-write"))partial_write_case();else if(same(name,"eagain-read"))again_case(0);else if(same(name,"eagain-write"))again_case(1);else if(same(name,"ebadf"))badfd_case();else if(same(name,"efault"))fault_case();else if(same(name,"pkru"))pkey_case();else if(same(name,"pkru-explicit-rights"))pkey_permission_case();else if(same(name,"prior-ignore")||same(name,"prior-unknown"))profile_case();else if(same(name,"sigpipe-ignore"))sigpipe_ignore_case();else if(same(name,"sigpipe-default"))sigpipe_default_case();else if(same(name,"live-tail"))live_tail_case();else if(same(name,"saved-frame-pkru"))frame_pkru_case();else if(same(name,"contrast"))contrast_case();else if(same(name,"other-number"))other_case();else if(same(name,"handler-eintr")||same(name,"handler-restart")||same(name,"handler-partial")||same(name,"trap-default")||same(name,"trap-ignore"))async_case(name);else if(same(name,"cache-mutate")||same(name,"mapping-replace")||same(name,"metadata-replace")||same(name,"metadata-read-restored")||same(name,"boundary-replace")||same(name,"pkey-overlap"))cached_refusal_case(name);else if(same(name,"fork-cache"))fork_cache_case();else need(0,"unknown-case");
 windows_after();text("END errors=");number(errors);text("\n");return errors?1:0;
}
