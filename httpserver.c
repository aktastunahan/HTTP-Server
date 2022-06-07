#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <unistd.h>

#include "libhttp.h"
#include "wq.h"

/*
 * Global configuration variables.
 * You need to use these in your implementation of handle_files_request and
 * handle_proxy_request. Their values are set up in main() using the
 * command line arguments (already implemented for you).
 */
wq_t work_queue; // Only used by poolserver
int num_threads; // Only used by poolserver
int server_port; // Default value: 8000
char* server_files_directory;
char* server_proxy_hostname;
int server_proxy_port;

/*
 * Proxy mode helper data structure for threads
 */
typedef struct TwoWaySocs {
  int listen_soc;
  int send_soc;
  char* dest_host;
} TwoWaySocs;

/*
 * Thread server 
 */
typedef struct ServeInfo {
  int client_fd;
  void (*request_handler)(int);
} ServeInfo;

/*****************************************/
/**** Thread Functions ****/
/****************************************/

/*
 * In proxy mode, listen the client socket,
 * create http request for proxy server and 
 * write it to the requested proxy server's socket.
 */

void *request_proxy_thread(void *sockets_ptr) {
  pthread_detach(pthread_self());
  TwoWaySocs *sockets = (TwoWaySocs*) sockets_ptr;
  int src_fd = sockets->listen_soc;
  int dest_fd = sockets->send_soc;
  char* dest_host = sockets->dest_host;
    
  int buff_len = 1 << 13;
  char *coming_buff = (char*) malloc(sizeof(char) * buff_len);
  char *going_buff = (char*) malloc(sizeof(char) * buff_len);
  char *going_buff_ptr = going_buff;
  if(coming_buff == NULL) {
    fprintf(stderr, "Malloc failed.%d: %s\n", errno, strerror(errno));
    close(src_fd);
    close(dest_fd);
    exit(errno);
  }
  if(going_buff == NULL) {
    fprintf(stderr, "Malloc failed.%d: %s\n", errno, strerror(errno));
    free(coming_buff);
    close(src_fd);
    close(dest_fd);
    exit(errno);
  }
  //while(1){
    int read_bytes = recv(src_fd, coming_buff, buff_len, 0);
    if(read_bytes >= 0 && read_bytes < buff_len)
    {
      char *host_start = NULL;
      if((host_start = strstr(coming_buff, "Host: ")) == NULL) {
        free(coming_buff);
        free(going_buff);
        close(src_fd);
        close(dest_fd);
        fprintf(stderr, "'Host' could not found in HTTP.. \n");
        exit(errno);
      }
      char *host_end = NULL;
      int snprint_num = -1;
      if((host_end = strstr(host_start, "\n")) == NULL) {
        free(coming_buff);
        free(going_buff);
        close(src_fd);
        close(dest_fd);
        fprintf(stderr, "Host field cannot found in http message. 1024 bytes buffer length might not be enough to hold field line.\n");
        exit(errno);
      }
      
      snprint_num = snprintf(going_buff_ptr, (host_start - coming_buff + 1), "%s", coming_buff);
      if(snprint_num  == -1) {
        free(coming_buff);
        free(going_buff);
        close(src_fd);
        close(dest_fd);
        fprintf(stderr, "Writing redirected http 'Host' field to the socket failed1.%d: %s\n", errno, strerror(errno));
        exit(errno);
      }
      
      going_buff_ptr += (host_start - coming_buff);
      snprint_num = snprintf(going_buff_ptr, strlen(dest_host) + 9, "Host: %s\r\n", dest_host);
      if(snprint_num  == -1) {
        free(coming_buff);
        free(going_buff);
        close(src_fd);
        close(dest_fd);
        fprintf(stderr, "Writing redirected http 'Host' field to the socket failed2.%d: %s\n", errno, strerror(errno));
        exit(errno);
      }
      
      going_buff_ptr += snprint_num;
      snprint_num = snprintf(going_buff_ptr, read_bytes - (host_end - host_start + 1), "%s", host_end + 1);
      if(snprint_num  == -1) {
        free(coming_buff);
        free(going_buff);
        close(src_fd);
        close(dest_fd);
        fprintf(stderr, "Writing redirected http 'Host' field to the socket failed3.%d: %s\n", errno, strerror(errno));
        exit(errno);
      }
      if(send(dest_fd, going_buff, strlen(going_buff), 0)  == -1) {
        free(coming_buff);
        free(going_buff);
        close(src_fd);
        close(dest_fd);
        fprintf(stderr, "Writing redirected http 'Host' field to the socket failed error %d: %s\n", errno, strerror(errno));
        exit(errno);
      }
    }
    else if(read_bytes == buff_len) {
      free(coming_buff);
      free(going_buff);
      close(src_fd);
      close(dest_fd);
      fprintf(stderr, "Buffer overflow reading HTTP request from client. %d: %s\n", errno, strerror(errno));
      exit(errno);
    }
    else {
      free(coming_buff);
      free(going_buff);
      close(src_fd);
      close(dest_fd);
      if(errno != 104){
        fprintf(stderr, "Read from requested file with fd:%d failed error: %d: %s, read_bytes:%d\n", src_fd, errno, strerror(errno), read_bytes);
        exit(errno);
      }
    }
  //}
  pthread_exit(NULL);
}

/*
 * In proxy mode, listen the response coming from proxy server
 * and write it to the requesting client.
 */
void *response_proxy_thread(void *sockets_ptr){
  pthread_detach(pthread_self());
  TwoWaySocs *sockets = (TwoWaySocs*) sockets_ptr;
  
  char buffer[1 << 17];
  int recv_bytes = -1;
  //while(1) {
    recv_bytes = recv(sockets->listen_soc, buffer, sizeof(buffer), 0);
    if(recv_bytes == -1) {
        close(sockets->listen_soc);
        close(sockets->send_soc);
        if(errno != 9) {
          fprintf(stderr, "Failed to recv from the socket: error %d: %s\n", errno, strerror(errno));
          exit(errno);
        }
        //break;
    }
    else if(recv_bytes >= 0) {
      //printf("recv_bytes inside thread:%d\n", recv_bytes);
      int send_status = send(sockets->send_soc, buffer, sizeof(buffer), 0); 
      if(send_status == -1) {
        close(sockets->listen_soc);
        close(sockets->send_soc);
        if(errno != EBADF) {
          fprintf(stderr, "Failed to send to the socket: error %d: %s\n", errno, strerror(errno));
          exit(errno);
        }
        //break;
      }
    }
  //}
  pthread_exit(NULL);
}

/*
 * In thread server mode, when a client is connected,
 * serve the client
 */
void *server_thread(void *serve_info) {
  pthread_detach(pthread_self());
  ServeInfo *info = (ServeInfo*) serve_info;
  info->request_handler(info->client_fd);
  printf("Client server succesfully!\n");
  pthread_exit(NULL);
}
/*
 * In pool thread server mode, when a client is connected,
 * serve the client
 */
/*
void *poolserver_thread(void *void_request_handler){
  void (*request_handler)(int) = (void (*)(int))void_request_handler;
  request_handler(wq_pop(working_queue));
  pthread_exit(NULL);
}*/
/*
 * Serves the contents the file stored at `path` to the client socket `fd`.
 * It is the caller's reponsibility to ensure that the file stored at `path` exists.
 */
void serve_file(int fd, char* path) {

  /* TODO: PART 2 */
  /* PART 2 BEGIN */
  struct stat sb;
  if (stat(path, &sb) == -1) {
      perror("failed to get stat(path, &sb)");
      exit(EXIT_FAILURE);
  }
  
  char* content_len = (char*) malloc(sizeof(char) * 32);

  http_start_response(fd, 200);
  http_send_header(fd, "Content-Type", http_get_mime_type(path));
  snprintf(content_len, 32, "%d", (int)sb.st_size);
  http_send_header(fd, "Content-Length", content_len);   
  http_end_headers(fd);
  http_write_file_to_body(fd, path);
  /* PART 2 END */
}

void serve_directory(int fd, char* path) {
  http_start_response(fd, 200);
  http_send_header(fd, "Content-Type", http_get_mime_type(".html"));

  /* TODO: PART 3 */
  /* PART 3 BEGIN */

  DIR* dir = opendir(path);
  if(dir == NULL) {
    perror("Failed to open directory");
    exit(EXIT_FAILURE);
  }
  /**
   * TODO: For each entry in the directory (Hint: look at the usage of readdir() ),
   * send a string containing a properly formatted HTML. (Hint: the http_format_href()
   * function in libhttp.c may be useful here)
   */
  struct dirent *dp;
  char content_len[32];
  char path_str[1024];
  struct stat sb;
  size_t html_size = 0;
  while((dp=readdir(dir)) != NULL) {
    if(strcmp(dp->d_name, "index.html") == 0) {
      printf("index.html found\n");
      http_format_index(path_str, path);
      if (stat(path_str, &sb) == -1) {
        perror("Failed to get file stat");
        exit(EXIT_FAILURE);
      }
      snprintf(content_len, 32, "%d", (int)sb.st_size);
      http_send_header(fd, "Content-Length", content_len);       
      http_end_headers(fd);
      http_write_file_to_body(fd, path_str);
      return;
    }
    
    http_format_href(path_str, path, dp->d_name);
    html_size += strlen(path_str);
  }

  dir = opendir(path);
  if(dir == NULL) {
    perror("Failed to open directory");
    exit(EXIT_FAILURE);
  }
  snprintf(content_len, 32, "%d", (int)html_size);
  http_send_header(fd, "Content-Length", content_len);   
  http_end_headers(fd);

  while((dp=readdir(dir)) != NULL) {
    //char server_path[] = "file://192.168.162.162/vagrant/code/personal/hw-http/www/";
    //char *dest = strcat(full_path, path+2);
    http_format_href(path_str, path+3, dp->d_name);
    //printf("strcat():%s\n", path_str);
    http_write_str_to_body(fd, path_str);
  }
  
  /* PART 3 END */
}

/*
 * Reads an HTTP request from client socket (fd), and writes an HTTP response
 * containing:
 *
 *   1) If user requested an existing file, respond with the file
 *   2) If user requested a directory and index.html exists in the directory,
 *      send the index.html file.
 *   3) If user requested a directory and index.html doesn't exist, send a list
 *      of files in the directory with links to each.
 *   4) Send a 404 Not Found response.
 *
 *   Closes the client socket (fd) when finished.
 */
void handle_files_request(int fd) {

  struct http_request* request = http_request_parse(fd);

  if (request == NULL || request->path[0] != '/') {
    http_start_response(fd, 400);
    http_send_header(fd, "Content-Type", "text/html");
    http_end_headers(fd);
    close(fd);
    return;
  }

  if (strstr(request->path, "..") != NULL) {
    http_start_response(fd, 403);
    http_send_header(fd, "Content-Type", "text/html");
    http_end_headers(fd);
    close(fd);
    return;
  }

  /* Remove beginning `./` */
  char* path = malloc(2 + strlen(request->path) + 1);
  path[0] = '.';
  path[1] = '/';
  memcpy(path + 2, request->path, strlen(request->path) + 1);

  /*
   * TODO: PART 2 is to serve files. If the file given by `path` exists,
   * call serve_file() on it. Else, serve a 404 Not Found error below.
   * The `stat()` syscall will be useful here.
   *
   * determine when to call serve_file() or serve_directory() depending
   * on `path`. Make your edits below here in this function.
   */

  /* PART 2 & 3 BEGIN */
  struct stat statbuf;
  if(stat(path, &statbuf) == 0) {
    if(S_ISREG(statbuf.st_mode))
      serve_file(fd, path); 
    else if(S_ISDIR(statbuf.st_mode))
      serve_directory(fd, path);
    else{
      close(fd);
      perror("Requested path exist but it is not a regular file nor a directory");
      exit(EXIT_FAILURE);
    }
    close(fd);
    return;
  }
  http_start_response(fd, 404);
  http_send_header(fd, "Content-Type", "text/html");
  http_end_headers(fd);
  
  /* PART 2 & 3 END */

  close(fd);
  return;
}



/*
 * Opens a connection to the proxy target (hostname=server_proxy_hostname and
 * port=server_proxy_port) and relays traffic to/from the stream fd and the
 * proxy target_fd. HTTP requests from the client (fd) should be sent to the
 * proxy target (target_fd), and HTTP responses from the proxy target (target_fd)
 * should be sent to the client (fd).
 *
 *   +--------+     +------------+     +--------------+
 *   | client | <-> | httpserver | <-> | proxy target |
 *   +--------+     +------------+     +--------------+
 *
 *   Closes client socket (fd) and proxy target fd (target_fd) when finished.
 */
void handle_proxy_request(int fd) {
  /*
  * The code below does a DNS lookup of server_proxy_hostname and
  * opens a connection to it. Please do not modify.
  */
  struct sockaddr_in target_address;
  memset(&target_address, 0, sizeof(target_address));
  target_address.sin_family = AF_INET;
  target_address.sin_port = htons(server_proxy_port);

  // Use DNS to resolve the proxy target's IP address
  struct hostent* target_dns_entry = gethostbyname2(server_proxy_hostname, AF_INET);

  // Create an IPv4 TCP socket to communicate with the proxy target.
  int target_fd = socket(PF_INET, SOCK_STREAM, 0);
  if (target_fd == -1) {
    fprintf(stderr, "Failed to create a new socket: error %d: %s\n", errno, strerror(errno));
    close(fd);
    exit(errno);
  }

  if (target_dns_entry == NULL) {
    fprintf(stderr, "Cannot find host: %s\n", server_proxy_hostname);
    close(target_fd);
    close(fd);
    exit(ENXIO);
  }

  char* dns_address = target_dns_entry->h_addr_list[0];
  // Connect to the proxy target.
  memcpy(&target_address.sin_addr, dns_address, sizeof(target_address.sin_addr));
  int connection_status =
      connect(target_fd, (struct sockaddr*)&target_address, sizeof(target_address));

  if (connection_status < 0) {
    /* Dummy request parsing, just to be compliant. */
    http_request_parse(fd);

    http_start_response(fd, 502);
    http_send_header(fd, "Content-Type", "text/html");
    http_end_headers(fd);
    close(target_fd);
    close(fd);
    return;
  }
  
  /* TODO: PART 4 */
  /* PART 4 BEGIN */
  char client_host[32];
  char proxy_host[32];
  snprintf(client_host, 32, "192.168.162.162:%d", server_port);
  snprintf(proxy_host, 32, "%s:%d", inet_ntoa(target_address.sin_addr), server_proxy_port);
  TwoWaySocs cltotar_soc, tartocl_soc;
  cltotar_soc.listen_soc = fd; /* client to target socket */
  cltotar_soc.send_soc = target_fd;
  cltotar_soc.dest_host = server_proxy_hostname;//proxy_host;
  tartocl_soc.listen_soc = target_fd; /* target to client socket */
  tartocl_soc.send_soc = fd;
  tartocl_soc.dest_host = client_host;

  pthread_t thread_cltotar_id, thread_tartocl_id;
  if(pthread_create(&thread_cltotar_id, NULL, request_proxy_thread, &cltotar_soc) == -1) {
    fprintf(stderr, "Cannot create client-to-target thread\n");
    close(target_fd);
    close(fd);
    exit(ENXIO);
  }

  if(pthread_create(&thread_tartocl_id, NULL, response_proxy_thread, &tartocl_soc) == -1) {
    fprintf(stderr, "Cannot create target-to-client thread\n");
    close(target_fd);
    close(fd);
    exit(ENXIO);
  }

  pthread_join(thread_cltotar_id, NULL);
  pthread_join(thread_tartocl_id, NULL);
  close(fd);
  close(target_fd);
  /* PART 4 END */
}

#ifdef POOLSERVER
/*
 * All worker threads will run this function until the server shutsdown.
 * Each thread should block until a new request has been received.
 * When the server accepts a new connection, a thread should be dispatched
 * to send a response to the client.
 */
void* handle_clients(void* void_request_handler) {
  void (*request_handler)(int) = (void (*)(int))void_request_handler;
  /* (Valgrind) Detach so thread frees its memory on completion, since we won't
   * be joining on it. */
  pthread_detach(pthread_self());

  /* TODO: PART 7 */
  /* PART 7 BEGIN */
  while(1) {
    request_handler(wq_pop(&work_queue));
    printf("Client server succesfully!\n");
  }
  pthread_exit(NULL);
  /* PART 7 END */
}

/*
 * Creates `num_threads` amount of threads. Initializes the work queue.
 */
void init_thread_pool(int num_threads, void (*request_handler)(int)) {

  /* TODO: PART 7 */
  /* PART 7 BEGIN */
  wq_init(&work_queue);
  
  pthread_t poolserver_thread_id[num_threads];
  for(int i = 0; i < num_threads; i++) {
    if(pthread_create(&poolserver_thread_id[i], NULL, handle_clients, request_handler) == -1) {
      fprintf(stderr, "Cannot create pool server thread\n");
      exit(ENXIO);
    }
  }
  /* PART 7 END */
}
#endif

/*
 * Opens a TCP stream socket on all interfaces with port number PORTNO. Saves
 * the fd number of the server socket in *socket_number. For each accepted
 * connection, calls request_handler with the accepted fd number.
 */
void serve_forever(int* socket_number, void (*request_handler)(int)) {

  struct sockaddr_in server_address, client_address;
  size_t client_address_length = sizeof(client_address);
  int client_socket_number;

  // Creates a socket for IPv4 and TCP.
  *socket_number = socket(PF_INET, SOCK_STREAM, 0);
  if (*socket_number == -1) {
    perror("Failed to create a new socket");
    exit(errno);
  }

  int socket_option = 1;
  if (setsockopt(*socket_number, SOL_SOCKET, SO_REUSEADDR, &socket_option, sizeof(socket_option)) ==
      -1) {
    perror("Failed to set socket options");
    exit(errno);
  }

  // Setup arguments for bind()
  memset(&server_address, 0, sizeof(server_address));
  server_address.sin_family = AF_INET;
  server_address.sin_addr.s_addr = INADDR_ANY;
  server_address.sin_port = htons(server_port);

  /*
   * TODO: PART 1
   *
   * Given the socket created above, call bind() to give it
   * an address and a port. Then, call listen() with the socket.
   * An appropriate size of the backlog is 1024, though you may
   * play around with this value during performance testing.
   */

  /* PART 1 BEGIN */
 
  if(bind(*socket_number, (struct sockaddr*)&server_address, sizeof(server_address)) == -1)
  {
    perror("Failed to bind socket to the address");
    exit(errno);
  }

  if(listen(*socket_number, 1024) == -1)
  {
    perror("Failed to listen socket");
    exit(errno);
  }

  /* PART 1 END */
  printf("Listening on port %d...\n", server_port);

#ifdef POOLSERVER
  /*
   * The thread pool is initialized *before* the server
   * begins accepting client connections.
   */
  init_thread_pool(num_threads, request_handler);
#endif

  while (1) {
    client_socket_number = accept(*socket_number, (struct sockaddr*)&client_address,
                                  (socklen_t*)&client_address_length);
    if (client_socket_number < 0) {
      perror("Error accepting socket");
      continue;
    }

    printf("Accepted connection from %s on port %d\n", inet_ntoa(client_address.sin_addr),
           client_address.sin_port);

#ifdef BASICSERVER
    /*
     * This is a single-process, single-threaded HTTP server.
     * When a client connection has been accepted, the main
     * process sends a response to the client. During this
     * time, the server does not listen and accept connections.
     * Only after a response has been sent to the client can
     * the server accept a new connection.
     */
    request_handler(client_socket_number);
    printf("Client server succesfully!\n");
#elif FORKSERVER
    /*
     * TODO: PART 5
     *
     * When a client connection has been accepted, a new
     * process is spawned. This child process will send
     * a response to the client. Afterwards, the child
     * process should exit. During this time, the parent
     * process should continue listening and accepting
     * connections.
     */

    /* PART 5 BEGIN */
    int pid = -1;
    if((pid = fork()) == 0) {
      request_handler(client_socket_number);
      printf("Client server succesfully!\n");
      close(client_socket_number);
      exit(EXIT_SUCCESS);
    }
    else if(pid == -1) {
      fprintf(stderr, "Failed to fork a process to serve a client: error %d: %s\n", errno, strerror(errno));
      close(client_socket_number);
      exit(errno);
    }
    /* PART 5 END */

#elif THREADSERVER
    /*
     * TODO: PART 6
     *
     * When a client connection has been accepted, a new
     * thread is created. This thread will send a response
     * to the client. The main thread should continue
     * listening and accepting connections. The main
     * listening and accepting connections. The main
     * thread will NOT be joining with the new thread.
     */

    /* PART 6 BEGIN */
    ServeInfo serve_info;
    serve_info.client_fd = client_socket_number;
    serve_info.request_handler = request_handler;
    pthread_t server_thread_id;
    if(pthread_create(&server_thread_id, NULL, server_thread, &serve_info) == -1) {
      fprintf(stderr, "Cannot create server thread\n");
      close(client_socket_number);
      exit(ENXIO);
    }
    //close(client_socket_number);
    /* PART 6 END */
#elif POOLSERVER
    /*
     * TODO: PART 7
     *
     * When a client connection has been accepted, add the
     * client's socket number to the work queue. A thread
     * in the thread pool will send a response to the client.
     */

    /* PART 7 BEGIN */
    wq_push(&work_queue, client_socket_number);
   
    /* PART 7 END */
#endif
  }

  shutdown(*socket_number, SHUT_RDWR);
  close(*socket_number);
}

int server_fd;
void signal_callback_handler(int signum) {
  printf("Caught signal %d: %s\n", signum, strsignal(signum));
  printf("Closing socket %d\n", server_fd);
  if (close(server_fd) < 0)
    perror("Failed to close server_fd (ignoring)\n");
  exit(0);
}

char* USAGE =
    "Usage: ./httpserver --files some_directory/ [--port 8000 --num-threads 5]\n"
    "       ./httpserver --proxy inst.eecs.berkeley.edu:80 [--port 8000 --num-threads 5]\n";

void exit_with_usage() {
  fprintf(stderr, "%s", USAGE);
  exit(EXIT_SUCCESS);
}

int main(int argc, char** argv) {
  signal(SIGINT, signal_callback_handler);
  signal(SIGPIPE, SIG_IGN);

  /* Default settings */
  server_port = 8000;
  void (*request_handler)(int) = NULL;

  int i;
  for (i = 1; i < argc; i++) {
    if (strcmp("--files", argv[i]) == 0) {
      request_handler = handle_files_request;
      server_files_directory = argv[++i];
      if (!server_files_directory) {
        fprintf(stderr, "Expected argument after --files\n");
        exit_with_usage();
      }
    } else if (strcmp("--proxy", argv[i]) == 0) {
      request_handler = handle_proxy_request;

      char* proxy_target = argv[++i];
      if (!proxy_target) {
        fprintf(stderr, "Expected argument after --proxy\n");
        exit_with_usage();
      }

      char* colon_pointer = strchr(proxy_target, ':');
      if (colon_pointer != NULL) {
        *colon_pointer = '\0';
        server_proxy_hostname = proxy_target;
        server_proxy_port = atoi(colon_pointer + 1);
      } else {
        server_proxy_hostname = proxy_target;
        server_proxy_port = 80;
      }
    } else if (strcmp("--port", argv[i]) == 0) {
      char* server_port_string = argv[++i];
      if (!server_port_string) {
        fprintf(stderr, "Expected argument after --port\n");
        exit_with_usage();
      }
      server_port = atoi(server_port_string);
    } else if (strcmp("--num-threads", argv[i]) == 0) {
      char* num_threads_str = argv[++i];
      if (!num_threads_str || (num_threads = atoi(num_threads_str)) < 1) {
        fprintf(stderr, "Expected positive integer after --num-threads\n");
        exit_with_usage();
      }
    } else if (strcmp("--help", argv[i]) == 0) {
      exit_with_usage();
    } else {
      fprintf(stderr, "Unrecognized option: %s\n", argv[i]);
      exit_with_usage();
    }
  }

  if (server_files_directory == NULL && server_proxy_hostname == NULL) {
    fprintf(stderr, "Please specify either \"--files [DIRECTORY]\" or \n"
                    "                      \"--proxy [HOSTNAME:PORT]\"\n");
    exit_with_usage();
  }

#ifdef POOLSERVER
  if (num_threads < 1) {
    fprintf(stderr, "Please specify \"--num-threads [N]\"\n");
    exit_with_usage();
  }
#endif

  chdir(server_files_directory);
  serve_forever(&server_fd, request_handler);

  return EXIT_SUCCESS;
}
