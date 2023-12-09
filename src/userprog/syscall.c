#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "lib/string.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "vm/page.h"
#define Max_Sys 17
#define STDIN 0
#define STDOUT 1
typedef void syscall_handler_func (struct intr_frame*);
/* These are defined in threads/thread.c */
/*
extern struct list open_file_list;
extern int file_open_count;
*/


struct syscall_handler_t {
  syscall_handler_func* func;
  char name[80]; // for debuging
  char argc;
};


struct semaphore* file_handle_lock;

static struct file* find_file_by_fd(int fd,struct thread* cur) {
  struct list_elem* iter;
  struct file* f_iter;
  struct list* open_file_list=&cur->open_file_list;
  for(iter=list_begin(open_file_list);iter!=list_end(open_file_list);iter=list_next(iter)) {
    f_iter=list_entry(iter,struct file,elem);
    if(f_iter->fd==fd){
      return f_iter;
    }
  }
  return NULL;
}
bool is_open_file_executing(const char* file){

  struct list_elem* iter;
  struct thread* t_iter;

  for(iter=list_begin(&all_list);iter!=list_end(&all_list);iter=list_next(iter)) {
    t_iter=list_entry(iter,struct thread,allelem);
    // printf("%s %s\n",file,t_iter->name);
    if(!strcmp(file,t_iter->name)){
      // printf("Return true\n\n");
      return true;
    }
  }
  return false;
}
static inline void _exit(int status){
  thread_current()->exit_status=status;
  thread_exit();
}

static void syscall_handler (struct intr_frame *);

static void syscall_halt(struct intr_frame* f);

static void syscall_exit(struct intr_frame* f);

static void syscall_exec(struct intr_frame* f);

static void syscall_wait(struct intr_frame* f);

static void syscall_create(struct intr_frame* f);

static void syscall_remove(struct intr_frame* f);

static void syscall_open(struct intr_frame* f);

static void syscall_filesize(struct intr_frame* f);

static void syscall_read(struct intr_frame* f);

static void syscall_write(struct intr_frame* f);

static void syscall_seek(struct intr_frame* f);
 
static void syscall_tell(struct intr_frame* f);

static void syscall_close(struct intr_frame* f);

static void syscall_max_of_four_int(struct intr_frame* f);

static void syscall_fibonacci(struct intr_frame* f);

static void syscall_mmap(struct intr_frame* f);

static void syscall_munmap(struct intr_frame* f);

//Những cái có 1 đối số bắt đầu từ esp + 4 và những cái có 2 đối số trở lên bắt đầu từ esp + 20 .
struct syscall_handler_t syscall_handlers[]=
                      {{syscall_halt,"halt",0 /*args number 0*/},{syscall_exit,"exit",1},{syscall_exec,"exec",1},
                        {syscall_wait,"wait",1},{syscall_create,"create",2},{syscall_remove,"remove",1},
                        {syscall_open,"open",1},{syscall_filesize,"filesize",1},{syscall_read,"read",1},
                        {syscall_write,"write",3},{syscall_seek,"seek",2},{syscall_tell,"tell",1},
                        {syscall_close,"close",1},{syscall_max_of_four_int,"max_of_four_int",4},
                        {syscall_fibonacci,"fibonacci",1},{syscall_mmap,"mmap",2},{syscall_munmap,"munmap",1}};


static inline bool is_valid_vaddr(uint32_t * esp){

  int i;
  if(*esp>Max_Sys){
    return false;
  }
  if(!is_user_vaddr(esp)){
    return false;
  }
  for(i=0;i<=syscall_handlers[*esp].argc;++i){
    if(!is_user_vaddr(*(esp+i))){
      return false;
    }
  }
  return true;
}


void
syscall_init (void) 
{
  file_handle_lock=malloc(sizeof *file_handle_lock);
  sema_init(file_handle_lock,1);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  
  
  uint32_t* esp=f->esp;

  if(!is_valid_vaddr(esp)){
    thread_current()->exit_status=-1;
    thread_exit();
  }  

  uint32_t syscall_nr=*((uint32_t*)esp);
  struct syscall_handler_t* handler=&syscall_handlers[syscall_nr];
  handler->func(f);
}

static void syscall_halt(struct intr_frame* f)
{
  shutdown_power_off();
}

static void syscall_exit(struct intr_frame* f)
{
  printf("%s: exit(%d)\n", thread_name(), f);
   // thread_current() -> status = THREAD_DYING; / * Điều này được xử lý trong Thread_exit () */
  uint32_t* esp= f->esp;
  thread_current()->exit_status=*(++esp);
  thread_exit();
}

static void syscall_exec(struct intr_frame* f)
{ 

  uint32_t* esp= f->esp;
  const char* file=*(++esp);

  f->eax=process_execute(file);
}

static void syscall_wait(struct intr_frame* f)
{
  uint32_t* esp= f->esp;
  int tid=*(++esp);

//printf(" SYSCALL: wait \n");
  f->eax=process_wait(tid);
}

static void syscall_create(struct intr_frame* f)
{

  uint32_t* esp= f->esp;
  const char* file=*(++esp);
  unsigned initial_size=*(++esp);
  if(file==NULL){
    _exit(-1);
  }
  sema_down(file_handle_lock);
  f->eax=filesys_create(file,initial_size);

  sema_up(file_handle_lock);
  // ASSERT(file_handle_lock->value==1);
}

static void syscall_remove(struct intr_frame* f)
{

  uint32_t* esp= f->esp;
  const char* file=*(++esp);
  sema_down(file_handle_lock);
  filesys_remove(file);
  sema_up(file_handle_lock);
}

static void syscall_open(struct intr_frame* f)
{  
  //printf(" SYSCALL: open \n");
  uint32_t* esp= f->esp;
  const char* file=*(++esp);
  struct thread* cur=thread_current();
  if(file==NULL){
    return;
  }
  sema_down(file_handle_lock);


  struct file* file_struct=filesys_open(file);
  if(is_open_file_executing(file)){
    file_deny_write(file_struct);
  }
  sema_up(file_handle_lock);
  if(file_struct==NULL){
    f->eax=-1;
     /* open failed */
  }else{
    file_struct->fd=++cur->cur_max_fd;
    f->eax=file_struct->fd;
    // Mô tả tệp được đánh số 0 và 1 được dành cho bảng điều khiển
  }
}

static void syscall_filesize(struct intr_frame* f)
{
  uint32_t* esp= f->esp;
  int fd=*(++esp);
  struct file* file_struct=find_file_by_fd(fd,thread_current());
  int ret=0;
  sema_down(file_handle_lock);
  if(file_struct){
    ret=file_length(file_struct);
  }
  sema_up(file_handle_lock);
  f->eax=ret;
} 

static void syscall_read(struct intr_frame* f)
{
  uint32_t* esp= f->esp;
  int fd=*(++esp);
  uint8_t* buffer=*(++esp);
  unsigned size=*(++esp);
  

  if(!is_user_vaddr(buffer) ){
    _exit(-1);
  }
  
  if(fd==STDOUT||fd<0){
    _exit(-1);
  }

  if(fd==STDIN){

  /* Fd 0 reads from the keyboard using input_getc(). */
    uint8_t ch;
    int i=0;
    sema_down(file_handle_lock);
    while((ch=input_getc())!=-1 &&i<size ){
      buffer[i]=ch;
    }
    sema_up(file_handle_lock);
    f->eax=i;
    return;
  }

  struct file* file_struct=find_file_by_fd(fd,thread_current());

  if(file_struct==NULL){
    _exit(-1);
     /* -1 if the file could not be read (due to a condition other than end of file) */
  }else{
    sema_down(file_handle_lock);
    f->eax=file_read(file_struct,buffer,size);
    sema_up(file_handle_lock);
  }
}

static void syscall_write(struct intr_frame* f)
{
  uint32_t* esp= f->esp;
  int fd=*(++esp);
  char* buffer=*(++esp);
  int size=*(++esp);
  int ret;
  if(!is_user_vaddr(buffer)||!is_user_vaddr(*buffer)||fd<0 ){
    ret=-1;
  }
  
  if(fd==STDOUT){
    /* putbuf() Sử dụng chức năng để nhập nội dung của bộ đệm vào bảng điều khiển.
     Tại thời điểm này, bạn phải trả lại vòng lặp nhiều như kích thước bạn cần.. */
    putbuf(buffer,size);
  }else{
    struct file* file =find_file_by_fd(fd,thread_current());
    if(file==NULL){
      ret=-1;
    }else{
      if(file->deny_write){
        ret=0;
      }else{
        sema_down(file_handle_lock);
        ret=file_write(file,buffer,size);
        sema_up(file_handle_lock);
      }
      // ret=file_write(file,buffer,size);
    }
  }
  
  f->eax=ret;
}

static void syscall_seek(struct intr_frame* f)
{
  uint32_t* esp= f->esp;
  int fd=*(++esp);
  off_t pos=*(++esp);
  struct file* file=find_file_by_fd(fd,thread_current());
  sema_down(file_handle_lock);
  file_seek(file,pos);
  sema_up(file_handle_lock);
}
 
static void syscall_tell(struct intr_frame* f)
{
  uint32_t* esp= f->esp;
  int fd=*(++esp);
  struct file* file=find_file_by_fd(fd,thread_current());
  int ret=-1;
  if(file){
    sema_down(file_handle_lock);
    ret=file_tell(file);
    sema_up(file_handle_lock);
  }
  f->eax=ret;
}

static void syscall_close(struct intr_frame* f)
{
  uint32_t* esp=f->esp;
  int fd=*(++esp);
  struct file* file_struct= find_file_by_fd(fd,thread_current());
  
  if(file_struct){
    sema_down(file_handle_lock);
    list_remove(&file_struct->elem);
    file_allow_write(file_struct);
    file_close(file_struct);
    sema_up(file_handle_lock);
  }
}

static void syscall_max_of_four_int(struct intr_frame* f){
  uint32_t* esp=f->esp;
  int a=*(++esp);
  int b=*(++esp);
  int c=*(++esp);
  int d=*(++esp);
  int ret=max(a,b);
  ret=max(ret,c);
  ret=max(ret,d);

  f->eax=ret;
}

static int fibo(int n){
  if(n==1||n==0){
    return n;
  }
  return fibo(n-1)+fibo(n-2);
}

static void syscall_fibonacci(struct intr_frame *f){
  uint32_t* esp=f->esp;
  int n=*(++esp);
  int ret;
  if(n<0){
    ret=0;
  }else{
    ret=fibo(n);
  }
  f->eax=ret;
}
static void syscall_mmap(struct intr_frame* f){
  uint32_t* esp=f->esp;
  int fd=*(++esp);
  void* addr=*(++esp);
  void* vaddr;
  struct thread* cur=thread_current();
  size_t fsize;
  size_t page_n;
  off_t off;

  if(addr!=pg_round_down(addr)||addr==NULL){
    f->eax=MAP_FAILED;
    return;
  }
  struct vm_entry* vme;
  struct file* file=find_file_by_fd(fd,thread_current());
  if(file==NULL){
    f->eax=MAP_FAILED;
    return;
  }
  file=file_reopen(file);

  fsize=file_length(file);
  page_n=(fsize/PGSIZE)+1;
  for(vaddr=addr;vaddr<addr+fsize;vaddr+=PGSIZE){
    if(find_vme(vaddr)!=NULL){
      f->eax=MAP_FAILED;
      return;
    }
    if(vaddr>=LOADER_PHYS_BASE-ULIMIT){
      // printf("4 base addr %p  vaddr %p\n",addr,vaddr);
      
      f->eax=MAP_FAILED;
      return;
    }
    EXPECT_EQ(vaddr,pg_round_down(vaddr));
  }


  struct mmap_file* mmap_file=malloc(sizeof (struct mmap_file));
  if(mmap_file==NULL){
    f->eax=MAP_FAILED;
    return;
  }
  mmap_file->file=file;
  mmap_file->mapid=++cur->cur_max_mapid;
  list_init(&mmap_file->vme_list);



  for(vaddr=addr,off=0; off<fsize; vaddr+=PGSIZE,off+=PGSIZE)
  {
    vme=malloc(sizeof *vme);
    if(vme==NULL){
      // printf("6\n");
      f->eax=MAP_FAILED;
      return;
    }
    vme->file=file;
    vme->loaded_on_phys=false;
    vme->type=VM_FILE;
    vme->offset=off;
    vme->read_bytes= fsize-off >= (PGSIZE) ? (PGSIZE) : fsize-off;
    // printf("mmap readbytes :%ld\n",vme->read_bytes);
    vme->swap_sector=-1;
    vme->vaddr= vaddr;
    vme->writable=true;
    vme->mmap_file=mmap_file;
    list_push_back(&mmap_file->vme_list,&vme->mmap_elem);
    insert_vme(&cur->vm,vme);
    EXPECT_EQ(vaddr,pg_round_down(vaddr));
  }
  
  list_push_back(&cur->mmap_list,&mmap_file->elem);
  f->eax=mmap_file->mapid;
}

static void syscall_munmap(struct intr_frame* f){
  uint32_t* esp=f->esp;
  int mapid=*(++esp);
  struct thread* cur=thread_current();
  struct mmap_file* mm_iter;
  struct mmap_file* mmap_file=NULL;
  struct list_elem* iter;
  for(iter=list_begin(&cur->mmap_list);iter!=list_end(&cur->mmap_list);iter=list_next(iter)){
    mm_iter=list_entry(iter,struct mmap_file,elem);
    if(mm_iter->mapid==mapid){
      mmap_file=mm_iter;
      break;     
    }
  }
  if(mmap_file==NULL){
    // _exit(-1);
    return;
  }
  list_remove(&mmap_file->elem);
  mmap_destroy(mmap_file,true);
  free(mmap_file);

}