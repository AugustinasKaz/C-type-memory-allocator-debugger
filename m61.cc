#define M61_DISABLE 1
#include "m61.hh"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
typedef char ALIGN[16];

union header{
  struct{
    size_t size;
    unsigned is_free;
    union header* next;
  }s;
  ALIGN stub;
};
typedef union header header_t;
header_t *head = NULL, *tail = NULL;
pthread_mutex_t global_malloc_lock;

header_t *get_free_block(size_t sz)
{
    header_t* curr = head;
    while(curr){
        if(curr->s.is_free && curr->s.size >= sz)
           return curr;
        curr = curr->s.next;   
    }
    return NULL;
}
struct m61_statistics statistics;

void* m61_malloc(size_t sz, const char* file, long line) {
    (void) file, (void) line;
    size_t total_sz;
    header_t* header;
    void* block;
    
    if(!sz)
        return NULL;
    pthread_mutex_lock(&global_malloc_lock);
    header = get_free_block(sz);
    if(header){
        header->s.is_free = 0;
        pthread_mutex_unlock(&global_malloc_lock);
        return (void*)(header+1);
    }
    
    total_sz = sizeof(header_t) + sz;
    if(total_sz <= sz){
        pthread_mutex_unlock(&global_malloc_lock);
        statistics.nfail ++;
        statistics.fail_size += sz;
        return NULL;
    }
    block = base_malloc(total_sz);
    
    if(!block){ // check if malloc returns null
        pthread_mutex_unlock(&global_malloc_lock);
        statistics.fail_size += sz;
        statistics.nfail ++;
        return NULL;
    }
    statistics.ntotal ++;
    statistics.nactive ++;     
    statistics.total_size += sz;
    statistics.active_size += 8;

    header = (header_t*)block;
    header->s.size = sz;
    header->s.is_free = 0;
    header->s.next = NULL;
    if(!head)
        head = header;
    if(tail)
        tail->s.next = header;
            
    if (statistics.heap_max){ //check for biggest allocated address in heap
        if (statistics.heap_max < (char*) block + sz) 
            statistics.heap_max = (char*) block + sz;
    }
    else 
        statistics.heap_max = (char*)block + sz;

    if (statistics.heap_min){ //check for smallest allocated address in heap
        if (statistics.heap_min > (char*) block)
            statistics.heap_min = (char*) block;
    }
    else 
        statistics.heap_min = (char*)block;
    tail = header;
    pthread_mutex_unlock(&global_malloc_lock);               
    return block;
}


/// m61_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`, which must have been
///    returned by a previous call to m61_malloc. If `ptr == NULL`,
///    does nothing. The free was called at location `file`:`line`.

void m61_free(void* ptr, const char* file, long line) {
    (void) file, (void) line;   
    header_t* header, *tmp;
    void *p_break;

    if(ptr){
     statistics.nactive --;
     statistics.active_size -= 8;
     if ((char*) ptr < statistics.heap_min || (char*) ptr > statistics.heap_max){
         fprintf(stderr, "MEMORY BUG: %c: invalid free of pointer %p, not in heap",*file, ptr);
         pthread_mutex_unlock(&global_malloc_lock);
         abort();
     }
     pthread_mutex_lock(&global_malloc_lock);
     header = (header_t*)ptr -1;
     if(header->s.is_free == 1){
         fprintf(stderr, "MEMORY BUG???: invalid free of pointer %p, not in heap",ptr);
         pthread_mutex_unlock(&global_malloc_lock);
         abort();
     }
     if(ptr != statistics.heap_min){
         printf("ER");
              }    
        

     p_break = sbrk(0);
     if((char*)ptr + header->s.size == p_break){
         if(head == tail)
             head = tail = NULL;
     else{
         tmp = head;
         while(tmp){
             if(tmp->s.next == tail){
                 tmp->s.next = NULL;
                 tail = tmp;
             }
             tmp = tmp->s.next;
        }
     }
     base_free(header);
     pthread_mutex_unlock(&global_malloc_lock);
     return;
     }
     header->s.is_free = 1;
     pthread_mutex_unlock(&global_malloc_lock);
    }
}
/// m61_calloc(nmemb, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `nmemb` elements of `sz` bytes each. If `sz == 0`,
///    then must return a unique, newly-allocated pointer value. Returned
///    memory should be initialized to zero. The allocation request was at
///    location `file`:`line`.

void* m61_calloc(size_t nmemb, size_t sz, const char* file, long line) {
    void *ptr = NULL;
    size_t total_sz = nmemb*sz;
    if(total_sz/nmemb == sz)
       ptr = m61_malloc(nmemb * sz, file, line);
    else
       statistics.nfail ++;
    
    if (ptr) {
        memset(ptr, 0, nmemb * sz);
        statistics.active_size = nmemb * sz;
    }
    return ptr;
}

void m61_getstatistics(m61_statistics* stats) {
    // Stub: set all statistics to enormous numbers
    memset(stats, 255, sizeof(m61_statistics));
    
    *stats = statistics;
}

void m61_printstatistics() {
    m61_statistics stats;
    m61_getstatistics(&stats);
    
    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}


/// m61_printleakreport()
///    Print a report of all currently-active allocated blocks of dynamic
///    memory.

void m61_printleakreport() {
    // Your code here.
}


thread_local const char* m61_file = "?";
thread_local int m61_line = 1;

void* operator new(size_t sz) {
    return m61_malloc(sz, m61_file, m61_line);
}
void* operator new[](size_t sz) {
    return m61_malloc(sz, m61_file, m61_line);
}
void operator delete(void* ptr) noexcept {
    m61_free(ptr, m61_file, m61_line);
}
void operator delete(void* ptr, size_t) noexcept {
    m61_free(ptr, m61_file, m61_line);
}
void operator delete[](void* ptr) noexcept {
    m61_free(ptr, m61_file, m61_line);
}
void operator delete[](void* ptr, size_t) noexcept {
    m61_free(ptr, m61_file, m61_line);
}
