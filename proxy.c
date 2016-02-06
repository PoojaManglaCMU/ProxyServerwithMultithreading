/*
 * File: proxy.c
 *
 * Contains the main function and APIs to implement proxy server
 *
 * Author: Pooja Mangla <pmangla@andrew.cmu.edu>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "csapp.h"
#include "cache.h"

/* fold strings to meet 80 columns */
static const char *user_agent_str = "User-Agent: Mozilla/5.0 \
(X11; Linux x86_64; rv:10.0.3) Gecko/20120305 Firefox/10.0.3\r\n";
static const char *connection_str = "Connection: close\r\n";
static const char *proxy_connection_str = "Proxy-Connection: close\r\n";
static const char *http_version_str = "HTTP/1.0\r\n";
static const char *client_bad_request_str = "HTTP/1.1 400 \
Bad Request\r\nServer: Apache\r\nContent-Length: 140\r\nConnection: \
close\r\nContent-Type: text/html\r\n\r\n<html><head></head><body><p>\
Bad Request</p></body></html>";

/* Cache is maintained as a queue */
cache_queue *cache = NULL;

void thread(void *arg);
int request_server(int fd, int *to_server_fd, char *cache_id,
                      void *cache_content, unsigned int *cache_length);
int serve_client(int to_client_fd, int to_server_fd);
int serve_client_from_cache(int to_client_fd, void *cache_content,
                                 unsigned int cache_length);
int serve_client_and_cache(int to_client_fd, int to_server_fd,
                                char *cache_id, void *cache_content);
/* helper functions */
int parse_request(char *buf, char *method, char *protocol,
                       char *host_port, char *resource, char *version);
void parse_host(char *host_port, char *remote_host, char *remote_port);
void close_conn(int *to_client_fd, int *to_server_fd);

/* Return values when a request is sent to server */

#define ERROR -1
#define READ_FROM_CACHE 1
#define NON_GET_METHOD 2 

int main (int argc, char *argv []) {
    int listenfd, *connfd, clientlen, port = 0;
    struct sockaddr_in clientaddr;
    pthread_t tid;

    Signal(SIGPIPE, SIG_IGN);

    if (argc != 2 ) {
        fprintf(stderr, "usage: %s <port>", argv[0]);
        exit(1);
    }

    port = atoi(argv[1]);
    if (port == 0) {
        fprintf(stderr, "Port number not valid\n");
        exit(1);
    }

	cache = init_cache();
    
	listenfd = Open_listenfd(port);
    if (listenfd < 0) {
        fprintf(stderr, "Error listening on port: %d\n", port);
        exit(1);
    }

    while (1) {
		clientlen = sizeof(clientaddr);
		connfd = (int *)malloc(sizeof(int));
		*connfd = Accept(listenfd, (SA *)&clientaddr,
				(socklen_t *)&clientlen);
		Pthread_create(&tid, NULL, (void *)thread, (void *)connfd);
	}
	return 0;
}

/*
 * thread - function to process http request and response
 *
 */
void thread(void *arg) {
    Pthread_detach(pthread_self());
    int client_fd = *(int *)arg;
    Free(arg);

    int server_fd = -1;
    int ret_val = 0;
    char cache_id[MAXLINE];
    char cache_content[MAX_OBJECT_SIZE];
    unsigned int cache_length;

    ret_val = request_server(client_fd, &server_fd, cache_id,
                           cache_content, &cache_length);
    if (ret_val == ERROR) {
        close_conn(&client_fd, &server_fd);
        Pthread_exit(NULL);
    } else if (ret_val == READ_FROM_CACHE) {
        if (serve_client_from_cache(client_fd, cache_content,
                                         cache_length) == -1) {
            close_conn(&client_fd, &server_fd);
            Pthread_exit(NULL);
        }
    } else if (ret_val == NON_GET_METHOD) {
        if (serve_client(client_fd, server_fd) == -1) {
            close_conn(&client_fd, &server_fd);
            Pthread_exit(NULL);
        }
    } else {
        if (serve_client_and_cache(client_fd, server_fd, cache_id,
                                        cache_content) == -1) {
            close_conn(&client_fd, &server_fd);
            Pthread_exit(NULL);
        }
    }
    close_conn(&client_fd, &server_fd);
    return;
}

/*
 * request_server - API to forward the http request to server
 *
 */
int request_server(int fd, int *to_server_fd, char *cache_id,
                      void *cache_content, unsigned int *cache_length) {
    char buf[MAXLINE], request_buf[MAXLINE];
    char method[MAXLINE], protocol[MAXLINE];
    char host_port[MAXLINE];
    char remote_host[MAXLINE], remote_port[MAXLINE], resource[MAXLINE];
    char version[MAXLINE];
    char origin_request_line[MAXLINE];
    char origin_host_header[MAXLINE];

    rio_t rio_client;

    strcpy(remote_host, "");
    strcpy(remote_port, "80");
    memset(cache_content, 0, MAX_OBJECT_SIZE);

    Rio_readinitb(&rio_client, fd);
    if (Rio_readlineb(&rio_client, buf, MAXLINE) == -1) {
	    printf("%s\n", buf);
        return ERROR;
    }
	    printf("%s\n", buf);
    
    strcpy(origin_request_line, buf);

    if (parse_request(buf, method, protocol, host_port,
                           resource, version) == -1) {
        return -1;
    }
    parse_host(host_port, remote_host, remote_port);

    if (strstr(method, "GET") != NULL) {
        strcpy(request_buf, method);
        strcat(request_buf, " ");
        strcat(request_buf, resource);
        strcat(request_buf, " ");
        strcat(request_buf, http_version_str);

        while (Rio_readlineb(&rio_client, buf, MAXLINE) != 0) {
            if (strcmp(buf, "\r\n") == 0) {
                break;
            } else if (strstr(buf, "User-Agent:") != NULL) {
                strcat(request_buf, user_agent_str);
            } else if (strstr(buf, "Connection:") != NULL) {
                strcat(request_buf, connection_str);
            } else if (strstr(buf, "Proxy Connection:") != NULL) {
                strcat(request_buf, proxy_connection_str);
            } else if (strstr(buf, "Host:") != NULL) {
                strcpy(origin_host_header, buf);
                if (strlen(remote_host) < 1) {
                    sscanf(buf, "Host: %s", host_port);
                    parse_host(host_port, remote_host, remote_port);
                }
                strcat(request_buf, buf);
            } else {
                strcat(request_buf, buf);
            }
        }
        strcat(request_buf, "\r\n");
        if (strcmp(remote_host, "") == 0) {
            return ERROR;
        }

        strcpy(cache_id, method);
        strcat(cache_id, " ");
        strcat(cache_id, remote_host);
        strcat(cache_id, ":");
        strcat(cache_id, remote_port);
        strcat(cache_id, resource);

        if (read_cache_element_lru_sync(cache, cache_id, cache_content,
                                     cache_length) != -1) {
            return READ_FROM_CACHE;
        }
        
		*to_server_fd = Open_clientfd(remote_host, atoi(remote_port),
                                    origin_request_line, origin_host_header);
        if (*to_server_fd == -1) {
            return ERROR;
        } else if (*to_server_fd == -2) {
            strcpy(buf, client_bad_request_str);
            Rio_writen(fd, buf, strlen(buf));
            return ERROR;
        }
        if (Rio_writen(*to_server_fd, request_buf,
                       strlen(request_buf)) == -1) {
            return ERROR;
        }
        return 0;
    } else {
        unsigned int length = 0, size = 0;
        strcpy(request_buf, buf);
        while (strcmp(buf, "\r\n") != 0 && strlen(buf) > 0) {
            if (Rio_readlineb(&rio_client, buf, MAXLINE) == -1) {
                return ERROR;
            }
            if (strstr(buf, "Host:") != NULL) {
                strcpy(origin_host_header, buf);
                if (strlen(remote_host) < 1) {
                    sscanf(buf, "Host: %s", host_port);
                    parse_host(host_port, remote_host, remote_port);
                }
            }
			if (strstr(buf, "Content-Length")) {
				sscanf(buf, "Content-Length: %d", &size);
			}	
			strcat(request_buf, buf);
        }
        if (strcmp(remote_host, "") == 0) {
            return ERROR;
        }
        *to_server_fd = Open_clientfd(remote_host, atoi(remote_port),
                                    origin_request_line, origin_host_header);
        if (*to_server_fd < 0) {
            return ERROR;
        }
        if (Rio_writen(*to_server_fd, request_buf,
                       strlen(request_buf)) == -1) {
            return ERROR;
        }
        while (size > MAXLINE) {
            if ((length = Rio_readnb(&rio_client, buf, MAXLINE)) == -1) {
                return ERROR;
            }
            if (Rio_writen(*to_server_fd, buf, length) == -1) {
                return ERROR;
            }
            size -= MAXLINE;
        }
        if (size > 0) {
            if ((length = Rio_readnb(&rio_client, buf, size)) == -1) {
                return ERROR;
            }
            if (Rio_writen(*to_server_fd, buf, length) == -1) {
                return ERROR;
            }
        }
        return NON_GET_METHOD;
    }
}

/*
 * serve_client - forward without writing to cache
 *
 */
int serve_client(int to_client_fd, int to_server_fd) {
    rio_t rio_server;
    char buf[MAXLINE];
    unsigned int length = 0, size = 0;

    Rio_readinitb(&rio_server, to_server_fd);
    if (Rio_readlineb(&rio_server, buf, MAXLINE) == -1) {
        return -1;
    }
    if (Rio_writen(to_client_fd, buf, strlen(buf)) == -1) {
        return -1;
    }
    while (strcmp(buf, "\r\n") != 0 && strlen(buf) > 0) {
        if (Rio_readlineb(&rio_server, buf, MAXLINE) == -1) {
            return -1;
        }
		if (strstr(buf, "Content-Length")) {
			sscanf(buf, "Content-Length: %d", &size);
		}
		if (Rio_writen(to_client_fd, buf, strlen(buf)) == -1) {
            return -1;
        }
    }
    if (size > 0) {
        while (size > MAXLINE) {
            if ((length = Rio_readnb(&rio_server, buf, MAXLINE)) == -1) {
                return -1;
            }
            if (Rio_writen(to_client_fd, buf, length) == -1) {
                return -1;
            }
            size -= MAXLINE;
        }
        if (size > 0) {
            if ((length = Rio_readnb(&rio_server, buf, size)) == -1) {
                return -1;
            }
            if (Rio_writen(to_client_fd, buf, length) == -1) {
                return -1;
            }
        }
    } else {
        while ((length = Rio_readnb(&rio_server, buf, MAXLINE)) > 0) {
            if (Rio_writen(to_client_fd, buf, length) == -1) {
                return -1;
            }
        }
    }
    return 0;
}

/*
 * serve_client_from_cache - forward directly from cache
 *
 */
int serve_client_from_cache(int to_client_fd, void *cache_content,
                                 unsigned int cache_length) {
    if (Rio_writen(to_client_fd, cache_content, cache_length)) {
        return -1;
    }
    return 0;
}

/*
 * serve_client_and_cache - forward to client and write to cache
 *
 */
int serve_client_and_cache(int to_client_fd, int to_server_fd,
                                char *cache_id, void *cache_content) {
    rio_t rio_server;
    char buf[MAXLINE];
    unsigned int cache_length = 0, length = 0, size = 0;
    void *ptr;
    int valid_obj_size = 1;

    Rio_readinitb(&rio_server, to_server_fd);
    if (Rio_readlineb(&rio_server, buf, MAXLINE) == -1) {
        return -1;
    }
    if (valid_obj_size) {
		if ((cache_length + strlen(buf)) > MAX_OBJECT_SIZE) {
			valid_obj_size = 0;
		} else {
			ptr = (void *)((char *)cache_content + cache_length);
			memcpy(ptr, buf, strlen(buf));
			cache_length = cache_length + strlen(buf);
			valid_obj_size = 1;
		}
	}
    if (Rio_writen(to_client_fd, buf, strlen(buf)) == -1) {
        return -1;
    }
    while (strcmp(buf, "\r\n") != 0 && strlen(buf) > 0) {
        if (Rio_readlineb(&rio_server, buf, MAXLINE) == -1) {
            return -1;
        }
		if (strstr(buf, "Content-Length")) {
			 sscanf(buf, "Content-Length: %d", &size);
		 }

		if (valid_obj_size) {
			if ((cache_length + strlen(buf)) > MAX_OBJECT_SIZE) {
				valid_obj_size = 0;
			} else {
				ptr = (void *)((char *)cache_content + cache_length);
				memcpy(ptr, buf, strlen(buf));
				cache_length = cache_length + strlen(buf);
				valid_obj_size = 1;
			}
		}
        if (Rio_writen(to_client_fd, buf, strlen(buf)) == -1) {
            return -1;
        }
    }
    if (size > 0) {
        while (size > MAXLINE) {
			if ((length = Rio_readnb(&rio_server, buf, MAXLINE)) == -1) {
				return -1;
            }
			if (valid_obj_size) {
				if ((cache_length + strlen(buf)) > MAX_OBJECT_SIZE) {
					valid_obj_size = 0;
				} else {
					ptr = (void *)((char *)cache_content + cache_length);
					memcpy(ptr, buf, strlen(buf));
					cache_length = cache_length + strlen(buf);
					valid_obj_size = 1;
				}
			}

			if (Rio_writen(to_client_fd, buf, length) == -1) {
                return -1;
            }
            size -= MAXLINE;
        }
		if (size > 0) {
            if ((length = Rio_readnb(&rio_server, buf, size)) == -1) {
				return -1;
            }

			if (valid_obj_size) {
				if ((cache_length + strlen(buf)) > MAX_OBJECT_SIZE) {
					valid_obj_size = 0;
				} else {
					ptr = (void *)((char *)cache_content + cache_length);
					memcpy(ptr, buf, strlen(buf));
					cache_length = cache_length + strlen(buf);
					valid_obj_size = 1;
				}
			}

            if (Rio_writen(to_client_fd, buf, length) == -1) {
                return -1;
            }
        }
    } else {
        while ((length = Rio_readnb(&rio_server, buf, MAXLINE)) > 0) {
            
			if (valid_obj_size) {
				if ((cache_length + strlen(buf)) > MAX_OBJECT_SIZE) {
					valid_obj_size = 0;
				} else {
					ptr = (void *)((char *)cache_content + cache_length);
					memcpy(ptr, buf, strlen(buf));
					cache_length = cache_length + strlen(buf);
					valid_obj_size = 1;
				}
			}

			if (Rio_writen(to_client_fd, buf, length) == -1) {
                return -1;
            }
        }
    }
    if (valid_obj_size) {
        if (add_data_to_cache_sync(cache, cache_id, cache_content,
                                      cache_length) == -1) {
            return -1;
        }
    }
    return 0;
}

/*
 * parse_request - parse request line to different parts
 *
 */
int parse_request (char *buf, char *method, char *protocol,
                       char *host_port, char *resource, char *version) {
    char url[MAXLINE];
    if (strstr(buf, "/") == NULL || strlen(buf) < 1) {
        return -1;
    }
    strcpy(resource, "/");
    sscanf(buf, "%s %s %s", method, url, version);
    if (strstr(url, "://") != NULL) {
        sscanf(url, "%[^:]://%[^/]%s", protocol, host_port, resource);
    } else {
        sscanf(url, "%[^/]%s", host_port, resource);
    }
    return 0;
}

/*
 * parse_host - parse host and port to two parts
 */
void parse_host(char *host_port, char *remote_host, char *remote_port) {
    char *tmp = NULL;
    tmp = index(host_port, ':');
    if (tmp != NULL) {
        *tmp = '\0';
        strcpy(remote_port, tmp + 1);
    } else {
        strcpy(remote_port, "80");
    }
    strcpy(remote_host, host_port);
}

/*
 * close_conn - safely close the file descriptors
 *
 */
void close_conn(int *to_client_fd, int *to_server_fd) {
    if (*to_client_fd >= 0) {
        Close(*to_client_fd);
    }
    if (*to_server_fd >= 0) {
        Close(*to_server_fd);
    }
}
