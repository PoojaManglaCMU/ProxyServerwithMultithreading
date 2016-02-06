/*
 * 
 * cache.h: Header file containing declaration of APIs 
 * implementation of cache
 *			
 */

#include "csapp.h"

#define MAX_CACHE_SIZE 1049000
#define MAX_OBJECT_SIZE 102400

typedef struct cache_element {
    char *id;
    struct cache_element *next;
    void *data;
    unsigned int length;
} cache_element;

typedef struct cache_queue {
    cache_element *head;
    cache_element *rear;
    unsigned remaining_length;
    sem_t r_mutex, w;
    unsigned int readcnt;
} cache_queue;

cache_queue *init_cache();
cache_element *init_cache_element(char *id, int length);
void destory_cache_element(cache_element *element);
cache_element *search_cache_element(cache_queue *queue, char *id);
void add_cache_element_to_rear(cache_queue *queue, cache_element *node);
void add_cache_element_to_rear_sync(cache_queue *queue, cache_element *node);
cache_element *delete_cache_element_from_head(cache_queue *queue);
void evict_cache_element_lru(cache_queue *queue);
cache_element *delete_cache_element(cache_queue *queue, char *id);

int read_cache_element_lru_sync(cache_queue *queue, char *id,
                             void *content, unsigned int *length);
int add_data_to_cache_sync(cache_queue *queue, char *id,
                              void *content, unsigned int length);

