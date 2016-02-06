/*
 *
 * cache.c: APIs for implementation of cache.
 *			Cache is implemented as a FIFO queue
 *
 * Author : Pooja Mangla <pmangla@andrew.cmu.edu>
 *
 */

#include "cache.h"

/*
 * queue_init - initialize a queue for cache
 *
 */
cache_queue *init_cache() {
    cache_queue *queue = (cache_queue *)malloc(sizeof(cache_queue));

    queue->head = NULL;
    queue->rear = NULL;
    queue->remaining_length = MAX_CACHE_SIZE;

    Sem_init(&queue->r_mutex, 0, 1);
    Sem_init(&queue->w, 0, 1);

    queue->readcnt = 0;
    return queue;
}

/*
 * init_cache_element - initialize a cache element
 *
 */
cache_element *init_cache_element(char *id, int length) {
    cache_element *node = (cache_element *)malloc(sizeof(cache_element));

    if (node == NULL) {
        return NULL;
    }
    node->id = (char *)Malloc(sizeof(char) * (strlen(id) + 1));
    if (node->id == NULL) {
        return NULL;
    }

    strcpy(node->id, id);
    node->length = 0;

    node->data = Malloc(length);
    if (node->data == NULL) {
        return NULL;
    }

    node->next = NULL;

    return node;
}

/*
 * search_cache_element: 
 * Search for a cache element whose id is
 * equal to the specified id.
 *
 */
cache_element *search_cache_element(cache_queue *list, char *id) {
    cache_element *cur_node = list->head;
    while (cur_node != NULL) {
        if (strcmp(cur_node->id, id) == 0) {
            return cur_node;
        }
        cur_node = cur_node->next;
    }

    return NULL;
}

/*
 * add_cache_element_to_rear: 
 * Add a cache node to the rear of the cache queue
 */
void add_cache_element_to_rear(cache_queue *list, cache_element *node) {
    if (list->head == NULL) {
        list->head = list->rear = node;
        list->remaining_length -= node->length;
    } else {
        list->rear->next = node;
        list->rear = node;
        list->remaining_length -= node->length;
    }
}

/*
 * add_cache_element_to_rear_sync:
 *
 * Add cache element to the queue in synchronized manner
 */
void add_cache_element_to_rear_sync(cache_queue *queue, cache_element *element) {
    P(&(queue->w));
    while (queue->remaining_length < element->length) {
        evict_cache_element_lru(queue);
    }
    add_cache_element_to_rear(queue, element);
    V(&(queue->w));
}

/*
 * delete_cache_element_from_head: 
 *
 * Delete a cache element from the front of the cache queue.
 *
 */
cache_element *delete_cache_element_from_head(cache_queue *queue) {
    cache_element *cur_node = queue->head;
    if (cur_node == NULL) {
        return NULL;
    }
    queue->head = cur_node->next;

    queue->remaining_length += cur_node->length;

    if (cur_node == queue->rear) {
		queue->rear = NULL;
    }

    return cur_node;
}

/*
 * evict_cache_element_lru:
 * Evict a cache node from the cache list using a 
 * least recently used policy
 */
void evict_cache_element_lru(cache_queue *queue) {
    cache_element *node = delete_cache_element_from_head(queue);
	Free(node->id);
    Free(node->data);
    Free(node);
 
}

/*
 * delete_cache_element: 
 * Delete a cache node whose id is equal to the specified id 
 * from the cache list
 * 
 */
cache_element *delete_cache_element(cache_queue *queue, char *id) {
	cache_element *prev_node = NULL;
    cache_element *cur_node = queue->head;
    while (cur_node != NULL) {
		if (strcmp(cur_node->id, id) == 0) {
            if (queue->head == cur_node) {
                queue->head = cur_node->next;
            }

            if (queue->rear == cur_node) {
                queue->rear = prev_node;
            }

            if (prev_node != NULL) {
                prev_node->next = cur_node->next;
            }

            cur_node->next = NULL;
            queue->remaining_length += cur_node->length;
            return cur_node;
        }
        prev_node = cur_node;
        cur_node = cur_node->next;
    }
    return NULL;
}

/*
 * search cache: 
 * Write the data of the cache node
 * to the buf and the apply a LRU policy
 */
int read_cache_element_lru_sync(cache_queue *queue, char *id, void *data,
                             unsigned int *length) {
    if (queue == NULL) {
        return -1;
    }

    P(&(queue->r_mutex));
    queue->readcnt++;
    if (queue->readcnt == 1) {
        P(&(queue->w));
    }
    V(&(queue->r_mutex));

    cache_element *node = search_cache_element(queue, id);
    if (node == NULL) {
        P(&(queue->r_mutex));
        queue->readcnt--;
        if (queue->readcnt == 0) {
            V(&(queue->w));
        }
        V(&(queue->r_mutex));
        return -1;
    }
    *length = node->length;
    memcpy(data, node->data, *length);

    P(&(queue->r_mutex));
    queue->readcnt--;
    if (queue->readcnt == 0) {
        V(&(queue->w));
    }
    V(&(queue->r_mutex));

    P(&(queue->w));
    node = delete_cache_element(queue, id);
    add_cache_element_to_rear(queue, node);
    V(&(queue->w));
    return 0;
}

/*
 * add_data_to_cache_sync:
 *
 * Write the data to a cache node and then add the cache node to 
 * the end of the cache list.
 *
 */
int add_data_to_cache_sync(cache_queue *queue, char *id,
                              void *data, unsigned int length) {
    if (queue == NULL) {
        return -1;
    }

    cache_element *node = init_cache_element(id, length);

    if (node == NULL) {
        return -1;
    }
    memcpy(node->data, data, length);
    node->length = length;
    add_cache_element_to_rear_sync(queue, node);
    return 0;
}

