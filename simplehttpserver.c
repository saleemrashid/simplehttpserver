/*
 * Copyright (c) 2019 Saleem Rashid
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define CONNECTION_FREELIST_MAX 256
#define CONNECTION_REQUEST_BUFFER_MAX 8168
#define CONNECTION_RESPONSE_BUFFER_MAX 8160
#define CONNECTION_RESPONSE_FILE_HEADERS_MAX 8136
#define CONNECTION_RESPONSE_INDEX_BUFFER_MAX 8152

#define SERVER_PORT UINT16_C(8000)
#define SERVER_EVENTS_MAX (CONNECTION_FREELIST_MAX + 1)

/* POSIX.1-2001 allows either error to be returned */
#define ERR_IS_WOULDBLOCK(ERR) ((ERR) == EAGAIN || (ERR) == EWOULDBLOCK)

#define HTTP_DEFINE_ERROR_RESPONSE(NAME, ERR, HEADERS)                       \
  static const char *HTTP_ERROR_RESPONSE_##NAME =                            \
      "HTTP/1.1 " ERR                                                        \
      "\r\n"                                                                 \
      "Content-Type: text/html\r\n" HEADERS                                  \
      "\r\n"                                                                 \
      "<html><head><title>" ERR "</title></head><body><center><h1>" ERR      \
      "</h1></center><hr></body></html>\n";                                  \
  static inline void connection_http_error_##NAME(Connection *connection) {  \
    connection_init_response_string(connection, HTTP_ERROR_RESPONSE_##NAME); \
  }

/*
 * The structure members must be ordered from largest to smallest alignment,
 * to minimize the structure size by eliminating padding.
 */

typedef enum {
  ConnectionStateRequest,
  ConnectionStateResponseBuffer,
  ConnectionStateResponsePtr,
  ConnectionStateResponseFile,
  ConnectionStateResponseIndex,
  ConnectionStateError,
  ConnectionStateFinished,
} ConnectionState;

struct Connection_request {
  size_t offset;
  uint8_t buffer[CONNECTION_REQUEST_BUFFER_MAX];
};

struct Connection_response_buffer {
  size_t offset, count;
  uint8_t buffer[CONNECTION_RESPONSE_BUFFER_MAX];
};

struct Connection_response_ptr {
  const uint8_t *ptr;
  size_t offset, count;
};

struct Connection_response_file {
  off_t file_offset, file_size;
  size_t headers_offset, headers_count;
  int fd;
  char headers[CONNECTION_RESPONSE_FILE_HEADERS_MAX];
};

struct Connection_response_index {
  DIR *dirp;
  size_t offset, count;
  char buffer[CONNECTION_RESPONSE_INDEX_BUFFER_MAX];
};

typedef struct {
  /*
   * We prevent type confusion by handling pointers to the individual fields,
   * rather than the entire Connection structure.
   */
  union {
    struct Connection_request request;
    struct Connection_response_buffer response_buffer;
    struct Connection_response_ptr response_ptr;
    struct Connection_response_file response_file;
    struct Connection_response_index response_index;
  } u;
  int fd;
  ConnectionState state;
  /* Whether to send headers only (HEAD), or include a response body (GET) */
  bool headers_only : 1;
} Connection;

union ConnectionAllocatorItem {
  /*
   * We maintain a freelist (singly linked list) of unused Connection
   * structures, reusing the memory to store the pointer to the next element.
   */
  union ConnectionAllocatorItem *next;
  Connection connection;
};

static union ConnectionAllocatorItem
    connection_freelist[CONNECTION_FREELIST_MAX];

static struct epoll_event server_events[SERVER_EVENTS_MAX];

static inline bool memchr_offset(const uint8_t *buffer, uint8_t ch,
                                 size_t *offset, size_t count);
static inline ssize_t sendbuffer(int fd, const uint8_t *buffer, size_t *offset,
                                 size_t count);
static inline ssize_t recvbuffer(int fd, uint8_t *buffer, size_t *offset,
                                 size_t count);
static inline bool has_request_finished(const uint8_t *buffer, size_t offset,
                                        size_t count);

static ssize_t uridecode(const char *uri, size_t uri_count, char *buffer,
                         size_t count);
static ssize_t uriencode(const uint8_t *str, size_t str_count, char *buffer,
                         size_t count);
static ssize_t normpath(const char *path, size_t path_count, char *buffer,
                        size_t count);
static ssize_t htmlentities(const char *str, char *buffer, size_t count);

static void server_main(uint16_t port);

static Connection *server_bind(int epfd, uint16_t port);
static bool server_handle_accept(int epfd, int sockfd);

static void server_handle_request(Connection *connection);
static void server_handle_request_parse(Connection *connection);
static void server_handle_request_serve(Connection *connection, int fd,
                                        const char *decoded, const char *path,
                                        bool request_dir, bool dir_allowed);

static inline void server_handle_response_buffer(Connection *connection);
static inline void server_handle_response_ptr(Connection *connection);
static void server_handle_response_file(Connection *connection);
static void server_handle_response_index(Connection *connection);

static bool connection_send_buffer(Connection *connection,
                                   const uint8_t *buffer, size_t *offset,
                                   size_t count);

static inline void connection_init_response_ptr(Connection *connection,
                                                const uint8_t *ptr,
                                                size_t count);
static inline void connection_init_response_string(Connection *connection,
                                                   const char *ptr);
static inline void connection_init_response_file(Connection *connection, int fd,
                                                 const struct stat *st);
static inline void connection_init_response_index(Connection *connection,
                                                  int fd, const char *path);
static inline void connection_init_response_redirect_dir(Connection *connection,
                                                         const char *uri);

static inline void connection_cleanup(Connection *connection);
static inline void connection_set_state(Connection *connection,
                                        ConnectionState new_state);

static inline Connection *server_connection_add(int epfd, int fd);
static inline int server_connection_epoll(int epfd, int op,
                                          Connection *connection, int events);
static inline void server_connection_remove(int epfd, Connection *connection,
                                            bool error);

static inline void connection_allocator_init(void);
static inline bool connection_allocator_full(void);
static inline Connection *connection_alloc(void);
static inline void connection_free(Connection *connection);

HTTP_DEFINE_ERROR_RESPONSE(400_bad_request, "400 Bad Request", "")
HTTP_DEFINE_ERROR_RESPONSE(404_not_found, "404 Not Found", "")
HTTP_DEFINE_ERROR_RESPONSE(405_method_not_allowed, "405 Method Not Allowed",
                           "Allow: GET, HEAD\r\n")
HTTP_DEFINE_ERROR_RESPONSE(414_request_uri_too_long, "414 Request-URI Too Long",
                           "")
HTTP_DEFINE_ERROR_RESPONSE(431_request_header_fields_too_large,
                           "431 Request Headers Fields Too Large", "")
HTTP_DEFINE_ERROR_RESPONSE(500_internal_server_error,
                           "500 Internal Server Error", "")

int main(int argc, char **argv) {
  uint16_t port = SERVER_PORT;

  if (argc > 2) {
    goto usage;
  }

  if (argc > 1) {
    errno = 0;
    char *endptr;
    unsigned long n = strtol(argv[1], &endptr, 0);
    if (errno != 0 || *endptr != '\0' || n > UINT16_MAX) {
      goto usage;
    }
    port = n;
  }

  printf("Serving HTTP on 0.0.0.0 port %" PRIu16 " (http://0.0.0.0:%" PRIu16
         "/) ...\n",
         port, port);

  server_main(port);
  return 0;

usage:
  fprintf(stderr, "Usage: %s PORT\n", argv[0]);
  return 1;
}

/* Find the offset of the next occurence of ch in buffer */
static inline bool memchr_offset(const uint8_t *buffer, uint8_t ch,
                                 size_t *offset, size_t count) {
  if (*offset >= count) {
    return false;
  }
  /* We should use memchr because it is likely to be highly optimized */
  const uint8_t *ptr = memchr(buffer + *offset, ch, count - *offset);
  if (ptr == NULL) {
    return false;
  }
  *offset = ptr - buffer;
  return true;
}

/* Write a buffer to a file descriptor */
static inline ssize_t sendbuffer(int fd, const uint8_t *buffer, size_t *offset,
                                 size_t count) {
  if (*offset >= count) {
    errno = EINVAL;
    return -1;
  }
  ssize_t n = write(fd, buffer + *offset, count - *offset);
  if (n > 0) {
    *offset += n;
  }
  return n;
}

/* Read a file descriptor into a buffer */
static inline ssize_t recvbuffer(int fd, uint8_t *buffer, size_t *offset,
                                 size_t count) {
  if (*offset >= count) {
    errno = EINVAL;
    return -1;
  }
  ssize_t n = read(fd, buffer + *offset, count - *offset);
  if (n > 0) {
    *offset += n;
  }
  return n;
}

static inline bool has_request_finished(const uint8_t *buffer, size_t offset,
                                        size_t count) {
  while (memchr_offset(buffer, '\n', &offset, count)) {
    offset++;
    /* Detect LF immediately followed by LF or CRLF (i.e. an empty line) */
    if ((offset + 1 <= count && buffer[offset] == '\n') ||
        (offset + 2 <= count && buffer[offset] == '\r' &&
         buffer[offset + 1] == '\n')) {
      return true;
    }
  }
  return false;
}

static ssize_t uridecode(const char *uri, size_t uri_count, char *buffer,
                         size_t count) {
  /*
   * We set the high nibble to a sentinel to distinguish between invalid hex
   * digits and a valid zero digit. The high nibble is masked off before using
   * the value.
   */
  static const uint8_t hex_table[(size_t)UINT8_MAX + 1] = {
      ['0'] = 0xF0, ['1'] = 0xF1, ['2'] = 0xF2, ['3'] = 0xF3, ['4'] = 0xF4,
      ['5'] = 0xF5, ['6'] = 0xF6, ['7'] = 0xF7, ['8'] = 0xF8, ['9'] = 0xF9,
      ['a'] = 0xFa, ['b'] = 0xFb, ['c'] = 0xFc, ['d'] = 0xFd, ['e'] = 0xFe,
      ['f'] = 0xFf, ['A'] = 0xFA, ['B'] = 0xFB, ['C'] = 0xFC, ['D'] = 0xFD,
      ['E'] = 0xFE, ['F'] = 0xFF,
  };

  /* Need null terminator */
  if (count < 1) {
    return -1;
  }
  size_t offset = 0;

  size_t uri_offset = 0;
  size_t uri_next = 0;
  for (; uri_next < uri_count; uri_offset = ++uri_next) {
    if (!memchr_offset((const uint8_t *)uri, '%', &uri_next, uri_count)) {
      uri_next = uri_count;
    }
    size_t n = uri_next - uri_offset;
    /* Need to fit null terminator and either '%' or decoded byte */
    if (offset + n + 1 >= count) {
      return -1;
    }
    memcpy(buffer + offset, uri + uri_offset, n);
    offset += n;

    uint8_t n1, n2;
    if (uri_next + 2 < uri_count &&
        (n1 = hex_table[(uint8_t)uri[uri_next + 1]]) != 0 &&
        (n2 = hex_table[(uint8_t)uri[uri_next + 2]]) != 0) {
      uint8_t octet = (n1 & 0xf) << 4 | (n2 & 0xf);
      buffer[offset++] = (char)octet;
      uri_next += 2;
    } else if (uri_next < uri_count) {
      buffer[offset++] = '%';
    }
  }

  buffer[offset] = '\0';
  return offset;
}

static ssize_t uriencode(const uint8_t *str, size_t str_count, char *buffer,
                         size_t count) {
  static const char *hex_digits = "0123456789ABCDEF";

  /* Output will be at least as long as input and needs null terminator */
  if (count <= str_count) {
    return -1;
  }
  size_t offset = 0;

  for (size_t i = 0; i < str_count; i++) {
    uint8_t ch = str[i];

    bool escape;
    switch (ch) {
      case '-':
      case '.':
      case '_':
      case '~':
        escape = false;
        break;
      default:
        escape = !isalnum(ch);
        break;
    }

    if (escape) {
      /* Need to fit null terminator */
      if (offset + 3 >= count) {
        return -1;
      }
      buffer[offset++] = '%';
      buffer[offset++] = hex_digits[(ch >> 4) & 0xf];
      buffer[offset++] = hex_digits[ch & 0xf];
    } else {
      /* Need to fit null terminator */
      if (offset + 1 >= count) {
        return -1;
      }
      buffer[offset++] = ch;
    }
  }

  buffer[offset] = '\0';
  return offset;
}

static ssize_t normpath(const char *path, size_t path_count, char *buffer,
                        size_t count) {
  /* Path cannot be empty; will at least contain '.' and null terminator */
  if (count < 2) {
    return -1;
  }
  size_t offset = 0;

  size_t path_offset = 0;
  size_t path_next = 0;
  for (; path_offset < path_count; path_offset = ++path_next) {
    /* path_next is the index of the next path separator */
    if (!memchr_offset((const uint8_t *)path, '/', &path_next, path_count)) {
      /*
       * path_next is one beyond the end of the path; this is safe because the
       * memcpy doesn't include path_next.
       */
      path_next = path_count;
    }
    /* Skip redundant path separator */
    if (path_offset == path_next) {
      continue;
    }
    if (path[path_offset] == '.') {
      /* Skip '.' */
      if (path_offset + 1 == path_next) {
        continue;
      }
      /* Handle '..' */
      if (path_offset + 2 == path_next && path[path_offset + 1] == '.') {
        const char *ptr = memrchr(buffer, '/', offset);
        if (ptr == NULL) {
          offset = 0;
        } else {
          offset = ptr - buffer;
        }
        continue;
      }
    }
    /* Only copy the path separator if it is not the first character */
    if (offset > 0) {
      path_offset--;
    }
    size_t n = path_next - path_offset;
    /* Need to fit null terminator */
    if (offset + n >= count) {
      return -1;
    }
    memcpy(buffer + offset, path + path_offset, n);
    offset += n;
  }

  /* Path must not be empty so we default to '.' */
  if (offset < 1) {
    buffer[offset++] = '.';
  }
  buffer[offset] = '\0';
  return offset;
}

static ssize_t htmlentities(const char *str, char *buffer, size_t count) {
  /* Need null terminator */
  if (count < 1) {
    return -1;
  }
  size_t offset = 0;

  while (true) {
    size_t n = strcspn(str, "&\"<>");
    /* Need to be able to fit null terminator */
    if (offset + n >= count) {
      return -1;
    }
    memcpy(buffer + offset, str, n);
    offset += n;

    char ch = str[n];
    if (ch == '\0') {
      break;
    }
    const char *entity = NULL;
    switch (ch) {
      case '&':
        entity = "&amp;";
        break;
      case '"':
        entity = "&quot;";
        break;
      case '<':
        entity = "&lt;";
        break;
      case '>':
        entity = "&gt;";
        break;
    }

    size_t entity_len = strlen(entity);
    if (offset + entity_len >= count) {
      return -1;
    }
    memcpy(buffer + offset, entity, entity_len);
    offset += entity_len;
    str += n + 1;
  }

  buffer[offset] = '\0';
  return offset;
}

static void server_main(uint16_t port) {
  connection_allocator_init();

  /*
   * We need to ignore SIGPIPE during socket operations and Linux doesn't have
   * SO_NOSIGPIPE.
   */
  if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
    err(1, "server_main: signal");
  }

  int epfd = epoll_create1(0);
  if (epfd < 0) {
    err(1, "server_main: epoll_create1");
  }

  Connection *server_connection = server_bind(epfd, port);
  bool pending_accept = false;

  while (true) {
    /*
     * Handle any pending connections otherwise Edge Triggered eventpoll will
     * never notify us again.
     */
    if (pending_accept) {
      pending_accept = server_handle_accept(epfd, server_connection->fd);
    }
    int numevents = epoll_wait(epfd, server_events, SERVER_EVENTS_MAX, -1);
    if (numevents < 0) {
      err(1, "server_main: epoll_wait");
    }
    for (int i = 0; i < numevents; i++) {
      int events = server_events[i].events;
      Connection *connection = server_events[i].data.ptr;
      if (connection == server_connection) {
        if (events & (EPOLLHUP | EPOLLERR)) {
          errx(1, "server_main: Error on server socket");
        }
        if (events & EPOLLIN) {
          /*
           * Edge Triggered eventpoll will only notify us once that there are
           * pending connections. If we cannot handle all of them immediately,
           * we must manually remember to handle them later.
           */
          pending_accept = server_handle_accept(epfd, server_connection->fd);
        }
      } else {
        if (events & EPOLLERR) {
          warnx("server_main: Error on client socket");
          goto err;
        }
        if (events & EPOLLHUP) {
          warnx("server_main: Hang-up on client socket");
          goto err;
        }
        if (events & EPOLLIN) {
          if (connection->state != ConnectionStateRequest) {
            warnx("server_main: Unexpected EPOLLIN");
            goto err;
          }
          server_handle_request(connection);

          switch (connection->state) {
            case ConnectionStateRequest:
            case ConnectionStateFinished:
              break;
            case ConnectionStateError:
              goto err;

            case ConnectionStateResponseBuffer:
            case ConnectionStateResponsePtr:
            case ConnectionStateResponseFile:
            case ConnectionStateResponseIndex:
              /*
               * Stop receiving EPOLLIN events; we're only interested in
               * EPOLLOUT now.
               */
              if (server_connection_epoll(epfd, EPOLL_CTL_MOD, connection,
                                          EPOLLOUT | EPOLLET) != 0) {
                warn("server_main: epoll_ctl");
                goto err;
              }
              break;
          }
        }
        if (events & EPOLLOUT) {
          switch (connection->state) {
            case ConnectionStateRequest:
            case ConnectionStateError:
            case ConnectionStateFinished:
              warnx("server_main: Unexpected EPOLLOUT");
              goto err;
            case ConnectionStateResponseBuffer:
              server_handle_response_buffer(connection);
              break;
            case ConnectionStateResponsePtr:
              server_handle_response_ptr(connection);
              break;
            case ConnectionStateResponseFile:
              server_handle_response_file(connection);
              break;
            case ConnectionStateResponseIndex:
              server_handle_response_index(connection);
              break;
          }
        }
        if (connection->state == ConnectionStateFinished) {
          server_connection_remove(epfd, connection, false);
          continue;
        }
        if (connection->state == ConnectionStateError) {
        err:
          connection_set_state(connection, ConnectionStateError);
          server_connection_remove(epfd, connection, true);
          continue;
        }
      }
    }
  }
}

static Connection *server_bind(int epfd, uint16_t port) {
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (fd < 0) {
    err(1, "server_bind: socket");
  }
  /* Allow reuse of a recently closed port */
  const int optval = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) != 0) {
    err(1, "server_bind: setsockopt");
  }
  struct sockaddr_in addr = {
      .sin_addr = {.s_addr = htonl(INADDR_ANY)},
      .sin_family = AF_INET,
      .sin_port = htons(port),
  };
  if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
    err(1, "server_bind: bind");
  }
  if (listen(fd, SOMAXCONN) != 0) {
    err(1, "server_bind: listen");
  }
  Connection *connection = server_connection_add(epfd, fd);
  if (connection == NULL) {
    err(1, "server_bind: server_connection_add");
  }
  return connection;
}

/* Accept connections and return whether there are still pending connections */
static bool server_handle_accept(int epfd, int sockfd) {
  while (true) {
    if (connection_allocator_full()) {
      /*
       * Defer a potential pending connection as we cannot allocate a Connection
       * structure.
       */
      return true;
    }
    int fd = accept4(sockfd, NULL, NULL, SOCK_NONBLOCK);
    if (fd < 0) {
      if (ERR_IS_WOULDBLOCK(errno)) {
        return false;
      }
      warn("server_handle_accept: accept4");
      return true;
    }
    if (server_connection_add(epfd, fd) == NULL) {
      warn("server_handle_accept: server_connection_add");
      if (close(fd) != 0) {
        warn("server_handle_accept: close");
      }
      return true;
    }
  }
}

static void server_handle_request(Connection *connection) {
  struct Connection_request *request = &connection->u.request;

  size_t offset = request->offset;
  if (offset >= 1) {
    /*
     * We determine the end of the headers by an empty line, so we need to
     * start parsing from the last character we received, in case it were a
     * line terminator.
     */
    offset--;
  }

  ssize_t n;
  while (true) {
    n = recvbuffer(connection->fd, request->buffer, &request->offset,
                   CONNECTION_REQUEST_BUFFER_MAX);
    if (n <= 0) {
      if (ERR_IS_WOULDBLOCK(errno)) {
        break;
      }
      warn("server_handle_request: recvbuffer");
      connection_set_state(connection, ConnectionStateError);
      return;
    }
    if (request->offset >= CONNECTION_REQUEST_BUFFER_MAX) {
      connection_http_error_431_request_header_fields_too_large(connection);
      return;
    }
  }

  if (!has_request_finished(request->buffer, offset, request->offset)) {
    if (n == 0) {
      /* We cannot receive any more data from the client */
      connection_set_state(connection, ConnectionStateError);
      return;
    } else {
      /* Wait for more data */
      return;
    }
  }

  server_handle_request_parse(connection);
}

/*
 * We naively parse the method and URI as the first two space-separated words
 * of the first line (i.e. before the first LF), and ignore everything else in
 * the request.
 */
static void server_handle_request_parse(Connection *connection) {
  struct Connection_request *request = &connection->u.request;

  size_t count = 0;
  if (!memchr_offset(request->buffer, '\n', &count, request->offset)) {
    connection_http_error_400_bad_request(connection);
    return;
  }
  size_t offset = 0;

  const char *method = (const char *)&request->buffer[offset];
  if (!memchr_offset(request->buffer, ' ', &offset, count)) {
    connection_http_error_400_bad_request(connection);
    return;
  }
  request->buffer[offset++] = '\0';

  char *uri = (char *)&request->buffer[offset];
  if (!memchr_offset(request->buffer, ' ', &offset, count)) {
    connection_http_error_400_bad_request(connection);
    return;
  }
  request->buffer[offset] = '\0';

  /* Remove query parameters or hash */
  uri[strcspn(uri, "?#")] = '\0';

  if (strcmp(method, "GET") == 0) {
    connection->headers_only = false;
  } else if (strcmp(method, "HEAD") == 0) {
    connection->headers_only = true;
  } else {
    connection_http_error_405_method_not_allowed(connection);
    return;
  }

  char decoded[PATH_MAX];
  ssize_t decoded_count = uridecode(uri, strlen(uri), decoded, sizeof(decoded));
  if (decoded_count <= 0) {
    connection_http_error_414_request_uri_too_long(connection);
    return;
  }

  /* Need space for the trailing slash */
  char path[PATH_MAX + 1];
  ssize_t path_count = normpath(decoded, decoded_count, path, sizeof(path) - 1);
  if (path_count <= 0) {
    connection_http_error_414_request_uri_too_long(connection);
    return;
  }

  bool request_dir = false;
  if (decoded[decoded_count - 1] == '/') {
    request_dir = true;
    /* If the Request-URI contained a trailing slash, we need to preserve it */
    path[path_count++] = '/';
    path[path_count] = '\0';
  }

  int fd = open(path, O_NONBLOCK);
  if (fd < 0) {
    warn("server_handle_request_parse: open");
    connection_http_error_404_not_found(connection);
    return;
  }

  server_handle_request_serve(connection, fd, decoded, path, request_dir, true);
}

/*
 * Serves the response for a given file descriptor. If a default page exists in
 * the directory, it will recurse at most once to serve the file. Otherwise, it
 * will generate a directory listing.
 */
static void server_handle_request_serve(Connection *connection, int fd,
                                        const char *decoded, const char *path,
                                        bool request_dir, bool dir_allowed) {
  struct stat st;
  if (fstat(fd, &st) != 0) {
    warn("server_handle_request_serve: fstat");
    connection_http_error_404_not_found(connection);
    return;
  }

  bool is_dir;
  if (S_ISREG(st.st_mode)) {
    is_dir = false;
  } else if (dir_allowed && S_ISDIR(st.st_mode)) {
    is_dir = true;
  } else {
    connection_http_error_404_not_found(connection);
    return;
  }

  if (is_dir) {
    if (!request_dir) {
      connection_init_response_redirect_dir(connection, decoded);
      return;
    }

    int htmlfd;
    if ((htmlfd = openat(fd, "index.html", 0)) < 0 &&
        (htmlfd = openat(fd, "index.htm", 0)) < 0) {
      /* Generate a directory listing because there's no default page */
      connection_init_response_index(connection, fd, path);
      return;
    }

    if (close(fd) != 0) {
      warn("server_handle_request_serve: close");
    }
    /* Because dir_allowed is now false, we will not recurse again */
    server_handle_request_serve(connection, htmlfd, decoded, path, request_dir,
                                false);
  } else {
    connection_init_response_file(connection, fd, &st);
  }
}

static inline void server_handle_response_buffer(Connection *connection) {
  struct Connection_response_buffer *response = &connection->u.response_buffer;
  if (connection_send_buffer(connection, response->buffer, &response->offset,
                             response->count)) {
    /*
     * The entire response has been sent to the client; if we didn't send
     * Content-Length, we are expected to shutdown the socket.
     */
    connection_set_state(connection, ConnectionStateFinished);
  }
}

static inline void server_handle_response_ptr(Connection *connection) {
  struct Connection_response_ptr *response = &connection->u.response_ptr;
  if (connection_send_buffer(connection, response->ptr, &response->offset,
                             response->count)) {
    /*
     * The entire response has been sent to the client; if we didn't send
     * Content-Length, we are expected to shutdown the socket.
     */
    connection_set_state(connection, ConnectionStateFinished);
  }
}

static void server_handle_response_file(Connection *connection) {
  struct Connection_response_file *response = &connection->u.response_file;
  if (!connection_send_buffer(connection, (const uint8_t *)response->headers,
                              &response->headers_offset,
                              response->headers_count)) {
    return;
  }
  if (connection->headers_only) {
    connection_set_state(connection, ConnectionStateFinished);
    return;
  }

  off_t remain;
  while ((remain = response->file_size - response->file_offset) > 0) {
    size_t count = remain > SSIZE_MAX ? SSIZE_MAX : remain;
    ssize_t n =
        sendfile(connection->fd, response->fd, &response->file_offset, count);
    if (n <= 0) {
      if (ERR_IS_WOULDBLOCK(errno)) {
        return;
      }
      warn("server_handle_response_file: sendfile");
      connection_set_state(connection, ConnectionStateError);
      return;
    }
  }

  connection_set_state(connection, ConnectionStateFinished);
}

static void server_handle_response_index(Connection *connection) {
  struct Connection_response_index *response = &connection->u.response_index;
  while (true) {
    if (!connection_send_buffer(connection, (const uint8_t *)response->buffer,
                                &response->offset, response->count)) {
      return;
    }
    if (connection->headers_only) {
      connection_set_state(connection, ConnectionStateFinished);
      return;
    }

    errno = 0;
    struct dirent *dirent = readdir(response->dirp);
    if (errno != 0) {
      warn("server_handle_response_index: readdir");
      connection_set_state(connection, ConnectionStateFinished);
      return;
    }
    if (dirent == NULL) {
      break;
    }

    response->count = 0;

    char href[PATH_MAX];
    if (uriencode((const uint8_t *)dirent->d_name, strlen(dirent->d_name), href,
                  sizeof(href)) <= 0) {
      continue;
    }
    char name[PATH_MAX];
    if (htmlentities(dirent->d_name, name, sizeof(name)) <= 0) {
      continue;
    }

    const char *hrefsuffix;
    const char *suffix;
    switch (dirent->d_type) {
      case DT_DIR:
        hrefsuffix = "/";
        suffix = "/";
        break;
      case DT_LNK:
        hrefsuffix = "";
        suffix = "@";
        break;
      default:
        hrefsuffix = "";
        suffix = "";
        break;
    }

    int n = snprintf(response->buffer, CONNECTION_RESPONSE_INDEX_BUFFER_MAX,
                     "<li><a href=\"%s%s\">%s%s</a></li>", href, hrefsuffix,
                     name, suffix);
    if (n < 0) {
      warn("server_handle_response_index: snprintf");
      continue;
    } else if (n > CONNECTION_RESPONSE_INDEX_BUFFER_MAX) {
      continue;
    } else {
      response->offset = 0;
      response->count = n;
    }
  }

  connection_init_response_string(connection, "</ul><hr></body></html>");

  /*
   * Edge Triggered eventpoll won't notify us about EPOLLOUT again so we need
   * to start writing the footer now.
   */
  server_handle_response_ptr(connection);
}

/* Returns whether the entire buffer was sent */
static bool connection_send_buffer(Connection *connection,
                                   const uint8_t *buffer, size_t *offset,
                                   size_t count) {
  while (*offset < count) {
    ssize_t n = sendbuffer(connection->fd, buffer, offset, count);
    if (n <= 0) {
      if (ERR_IS_WOULDBLOCK(errno)) {
        return false;
      }
      warn("connection_send_buffer: sendbuffer");
      connection_set_state(connection, ConnectionStateError);
      return false;
    }
  }
  return true;
}

static inline void connection_init_response_ptr(Connection *connection,
                                                const uint8_t *ptr,
                                                size_t count) {
  connection_set_state(connection, ConnectionStateResponsePtr);
  connection->u.response_ptr = (const struct Connection_response_ptr){
      .ptr = ptr,
      .count = count,
  };
}

static inline void connection_init_response_string(Connection *connection,
                                                   const char *ptr) {
  connection_init_response_ptr(connection, (const uint8_t *)ptr, strlen(ptr));
}

static inline void connection_init_response_file(Connection *connection, int fd,
                                                 const struct stat *st) {
  connection_set_state(connection, ConnectionStateResponseFile);
  struct Connection_response_file *response = &connection->u.response_file;

  *response = (const struct Connection_response_file){
      .fd = fd,
      .file_size = st->st_size,
  };

  int n = snprintf(response->headers, CONNECTION_RESPONSE_FILE_HEADERS_MAX,
                   "HTTP/1.1 200 OK\r\nContent-Length: %jd\r\n\r\n",
                   (intmax_t)response->file_size);
  if (n < 0) {
    warn("connection_init_response_file: snprintf");
    connection_http_error_500_internal_server_error(connection);
    return;
  } else if (n > CONNECTION_RESPONSE_FILE_HEADERS_MAX) {
    connection_http_error_500_internal_server_error(connection);
    return;
  } else {
    response->headers_count = n;
  }
}

static inline void connection_init_response_index(Connection *connection,
                                                  int fd, const char *path) {
  DIR *dirp = fdopendir(fd);
  if (dirp == NULL) {
    warn("connection_init_response_index: fdopendir");
    if (close(fd) != 0) {
      warn("connection_init_response_index: close");
    }
    connection_http_error_500_internal_server_error(connection);
    return;
  }

  connection_set_state(connection, ConnectionStateResponseIndex);
  struct Connection_response_index *response = &connection->u.response_index;

  /* This should only happen for the root directory as normpath returns '.' */
  if (path[0] == '.' && path[1] == '/') {
    path += 2;
  }

  char name[PATH_MAX];
  if (htmlentities(path, name, sizeof(name)) == -1) {
    connection_http_error_500_internal_server_error(connection);
    return;
  }

  *response = (const struct Connection_response_index){
      .dirp = dirp,
  };
  int n = snprintf(response->buffer, CONNECTION_RESPONSE_INDEX_BUFFER_MAX,
                   "HTTP/1.1 200 OK\r\nContent-Type: "
                   "text/html\r\n\r\n<html><head><title>Directory "
                   "listing for /%s</title></head><body><h1>Directory listing "
                   "for /%s</h1></hr><ul>",
                   name, name);
  if (n < 0) {
    warn("connection_init_response_index: snprintf");
    connection_http_error_500_internal_server_error(connection);
    return;
  } else if (n > CONNECTION_RESPONSE_INDEX_BUFFER_MAX) {
    connection_http_error_500_internal_server_error(connection);
    return;
  } else {
    response->count = n;
  }
}

static inline void connection_init_response_redirect_dir(Connection *connection,
                                                         const char *uri) {
  connection_set_state(connection, ConnectionStateResponseBuffer);
  struct Connection_response_buffer *response = &connection->u.response_buffer;

  *response = (const struct Connection_response_buffer){0};
  int n =
      snprintf((char *)response->buffer, CONNECTION_RESPONSE_BUFFER_MAX,
               "HTTP/1.1 301 Moved Permanently\r\nLocation: %s/\r\n\r\n", uri);
  if (n < 0) {
    warn("connection_init_response_redirect_dir: snprintf");
    connection_http_error_500_internal_server_error(connection);
    return;
  } else if (n > CONNECTION_RESPONSE_BUFFER_MAX) {
    connection_http_error_500_internal_server_error(connection);
    return;
  } else {
    response->count = n;
  }
}

/* Clean-up resources held in the Connection structure */
static inline void connection_cleanup(Connection *connection) {
  switch (connection->state) {
    case ConnectionStateRequest:
    case ConnectionStateError:
    case ConnectionStateFinished:
      break;
    case ConnectionStateResponseBuffer:
    case ConnectionStateResponsePtr:
      break;
    case ConnectionStateResponseFile:
      if (close(connection->u.response_file.fd) != 0) {
        warn("connection_cleanup: close");
      }
      break;
    case ConnectionStateResponseIndex:
      if (closedir(connection->u.response_index.dirp) != 0) {
        warn("connection_cleanup: closedir");
      }
      break;
  }
}

static inline void connection_set_state(Connection *connection,
                                        ConnectionState new_state) {
  connection_cleanup(connection);
  connection->state = new_state;
}

/* Allocate Connection structure and add file descriptor to eventpoll */
static inline Connection *server_connection_add(int epfd, int fd) {
  Connection *connection = connection_alloc();
  if (connection == NULL) {
    /*
     * The caller should have checked this condition before accepting the
     * connection
     */
    warn("server_connection_add: connection_alloc");
    return NULL;
  }
  *connection = (const Connection){.fd = fd};
  if (server_connection_epoll(epfd, EPOLL_CTL_ADD, connection,
                              EPOLLIN | EPOLLRDHUP | EPOLLET) != 0) {
    warn("server_connection_add: epoll_ctl");
    connection_free(connection);
    return NULL;
  }
  return connection;
}

static inline int server_connection_epoll(int epfd, int op,
                                          Connection *connection, int events) {
  struct epoll_event event = {
      .events = events,
      .data = {.ptr = connection},
  };
  return epoll_ctl(epfd, op, connection->fd, &event);
}

static inline void server_connection_remove(int epfd, Connection *connection,
                                            bool error) {
  if (epoll_ctl(epfd, EPOLL_CTL_DEL, connection->fd, NULL) != 0) {
    warn("server_connection_remove: epoll_ctl");
  }
  if (!error) {
    if (shutdown(connection->fd, SHUT_RDWR) != 0) {
      warn("server_connection_remove: shutdown");
    }
  }
  if (close(connection->fd) != 0) {
    warn("server_connection_remove: close");
  }
  connection_free(connection);
}

/* Initialize the freelist as a linked list of unused Connection structures */
static inline void connection_allocator_init(void) {
  for (size_t i = 0; i + 1 < CONNECTION_FREELIST_MAX; i++) {
    connection_freelist[i].next = &connection_freelist[i + 1];
  }
  connection_freelist[CONNECTION_FREELIST_MAX - 1].next = NULL;
}

static inline bool connection_allocator_full(void) {
  return connection_freelist->next == NULL;
}

/* Remove and return a Connection structure from the freelist */
static inline Connection *connection_alloc(void) {
  union ConnectionAllocatorItem *item = connection_freelist->next;
  if (item == NULL) {
    errno = ENOMEM;
    return NULL;
  }
  connection_freelist->next = item->next;
  return &item->connection;
}

/* Return a Connection structure to the freelist */
static inline void connection_free(Connection *connection) {
  union ConnectionAllocatorItem *item =
      (union ConnectionAllocatorItem *)connection;
  item->next = connection_freelist->next;
  connection_freelist->next = item;
}
