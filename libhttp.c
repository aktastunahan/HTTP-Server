#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "libhttp.h"

#define LIBHTTP_REQUEST_MAX_SIZE 8192

void http_fatal_error(char* message) {
  fprintf(stderr, "%s\n", message);
  exit(ENOBUFS);
}

struct http_request* http_request_parse(int fd) {
  struct http_request* request = malloc(sizeof(struct http_request));
  if (!request)
    http_fatal_error("Malloc failed");

  char* read_buffer = malloc(LIBHTTP_REQUEST_MAX_SIZE + 1);
  if (!read_buffer)
    http_fatal_error("Malloc failed");

  int bytes_read = read(fd, read_buffer, LIBHTTP_REQUEST_MAX_SIZE);
  read_buffer[bytes_read] = '\0'; /* Always null-terminate. */

  char *read_start, *read_end;
  size_t read_size;

  do {
    /* Read in the HTTP method: "[A-Z]*" */
    read_start = read_end = read_buffer;
    while (*read_end >= 'A' && *read_end <= 'Z')
      read_end++;
    read_size = read_end - read_start;
    if (read_size == 0)
      break;
    request->method = malloc(read_size + 1);
    memcpy(request->method, read_start, read_size);
    request->method[read_size] = '\0';

    /* Read in a space character. */
    read_start = read_end;
    if (*read_end != ' ')
      break;
    read_end++;

    /* Read in the path: "[^ \n]*" */
    read_start = read_end;
    while (*read_end != '\0' && *read_end != ' ' && *read_end != '\n')
      read_end++;
    read_size = read_end - read_start;
    if (read_size == 0)
      break;
    request->path = malloc(read_size + 1);
    memcpy(request->path, read_start, read_size);
    request->path[read_size] = '\0';

    /* Read in HTTP version and rest of request line: ".*" */
    read_start = read_end;
    while (*read_end != '\0' && *read_end != '\n')
      read_end++;
    if (*read_end != '\n')
      break;
    read_end++;

    free(read_buffer);
    return request;
  } while (0);

  /* An error occurred. */
  free(request);
  free(read_buffer);
  return NULL;
}

char* http_get_response_message(int status_code) {
  switch (status_code) {
    case 100:
      return "Continue";
    case 200:
      return "OK";
    case 301:
      return "Moved Permanently";
    case 302:
      return "Found";
    case 304:
      return "Not Modified";
    case 400:
      return "Bad Request";
    case 401:
      return "Unauthorized";
    case 403:
      return "Forbidden";
    case 404:
      return "Not Found";
    case 405:
      return "Method Not Allowed";
    default:
      return "Internal Server Error";
  }
}

void http_start_response(int fd, int status_code) {
  dprintf(fd, "HTTP/1.0 %d %s\r\n", status_code, http_get_response_message(status_code));
}

void http_send_header(int fd, char* key, char* value) { dprintf(fd, "%s: %s\r\n", key, value); }

void http_end_headers(int fd) { dprintf(fd, "\r\n"); }

char* http_get_mime_type(char* file_name) {
  char* file_extension = strrchr(file_name, '.');
  if (file_extension == NULL) {
    return "text/plain";
  }

  if (strcmp(file_extension, ".html") == 0 || strcmp(file_extension, ".htm") == 0) {
    return "text/html";
  } else if (strcmp(file_extension, ".jpg") == 0 || strcmp(file_extension, ".jpeg") == 0) {
    return "image/jpeg";
  } else if (strcmp(file_extension, ".png") == 0) {
    return "image/png";
  } else if (strcmp(file_extension, ".css") == 0) {
    return "text/css";
  } else if (strcmp(file_extension, ".js") == 0) {
    return "application/javascript";
  } else if (strcmp(file_extension, ".pdf") == 0) {
    return "application/pdf";
  } else {
    return "text/plain";
  }
}

/*
 * Puts `<a href="/path/filename">filename</a><br/>` into the provided buffer.
 * The resulting string in the buffer is null-terminated. It is the caller's
 * responsibility to ensure that the buffer has enough space for the resulting string.
 */
void http_format_href(char* buffer, char* path, char* filename) {
  int length = strlen("<a href=\"//\"></a><br/>") + strlen(path) + strlen(filename) * 2 + 1;
  snprintf(buffer, length, "<a href=\"/%s/%s\">%s</a><br/>", path, filename, filename);
}

/*
 * Puts `path/index.html` into the provided buffer.
 * The resulting string in the buffer is null-terminated.
 * It is the caller's responsibility to ensure that the
 * buffer has enough space for the resulting string.
 */
void http_format_index(char* buffer, char* path) {
  int length = strlen(path) + strlen("/index.html") + 1;
  snprintf(buffer, length, "%s/index.html", path);
}

/*
 * Copies the 'size' bytes of contents of the file 
 * located in 'path' into the socket 'fd'.
 */
void http_write_file_to_body(int fd, char* path) {
  int file = open(path, O_RDONLY);
  if(file == -1)
    http_fatal_error("open() failed");
  
  size_t buff_len = 1024;
  char *buff = (char*) malloc(sizeof(char) * buff_len);
  if(buff == NULL)
    http_fatal_error("Malloc failed");
 
  ssize_t read_bytes = 0;
  while((read_bytes = read(file, buff, buff_len)) > 0)
  {
    if(write(fd, buff, read_bytes) == -1)
      http_fatal_error("Writing requested file to the socket failed");
  }

  if(read_bytes == -1)
    http_fatal_error("Read from requested file failed");

}

/*
 * Writes 'body' to socket 'fd'
 */
void http_write_str_to_body(int fd, char* body) {
  if(write(fd, body, strlen(body)) == -1)
      http_fatal_error("Writing requested file to the socket failed");
}

/*
 * Reads http message from 'src_fd', changes Host field with 'dest_host',
 * writes it to 'dest_fd'.
 */
void redirect_http_message(int src_fd, int dest_fd, char* dest_host) {
    
  size_t buff_len = 1024;
  char *buff = (char*) malloc(sizeof(char) * buff_len);
  if(buff == NULL)
    http_fatal_error("Malloc failed");
 
  int is_host_found = 0;
  ssize_t read_bytes = 0;
  while((read_bytes = read(src_fd, buff, buff_len)) > 0)
  {
    char *host_start = NULL;
    if(is_host_found == 1 || (host_start = strstr(buff, "Host: ")) == NULL) {
      if(write(dest_fd, buff, read_bytes) == -1) {
        free(buff);
        http_fatal_error("Writing redirected http 'Host' field to the socket failed");
      }
    }
    else {
      is_host_found = 1;
      char *host_end = NULL;
      if((host_end = strstr(host_start, "\n")) == NULL) {
        free(buff);
        http_fatal_error("Host field cannot found in http message. 1024 bytes buffer length might not be enough to hold field line.");
      }
      if(write(dest_fd, "Host ", 5) == -1) {
        free(buff);
        http_fatal_error("Writing redirected http 'Host' field to the socket failed");
      }
      if(write(dest_fd, dest_host, strlen(dest_host)) == -1) {
        free(buff);
        http_fatal_error("Writing redirected http 'Host' field to the socket failed");
      }
      if(write(dest_fd, "\r\n", 2) == -1) {
        free(buff);
        http_fatal_error("Writing redirected http 'Host' field to the socket failed");
      }
      if(write(dest_fd, host_end+1, buff_len - (host_end - host_start + 1)) == -1) {
        free(buff);
        http_fatal_error("Writing redirected http 'Host' field to the socket failed");
      }
    }
  }
  if(read_bytes == -1)
    http_fatal_error("Read from requested file failed");

}


