#include "EchoAssignment.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <arpa/inet.h>

// !IMPORTANT: allowed system calls.
// !DO NOT USE OTHER NETWORK SYSCALLS (send, recv, select, poll, epoll, fork
// etc.)
//  * socket
//  * bind
//  * listen
//  * accept
//  * read
//  * write
//  * close
//  * getsockname
//  * getpeername
// See below for their usage.
// https://github.com/ANLAB-KAIST/KENSv3/wiki/Misc:-External-Resources#linux-manuals

int EchoAssignment::serverMain(const char *bind_ip, int port,
                               const char *server_hello) {
  // Your server code
  // !IMPORTANT: do not use global variables and do not define/use functions
  // !IMPORTANT: for all system calls, when an error happens, your program must
  // return. e.g., if an read() call return -1, return -1 for serverMain.
  
  int sockfd, new_fd;
  struct sockaddr_in serv_addr, cli_addr, addr;
  socklen_t clilen, addrlen;
  char name[1024];

  char buffer[256];

  sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sockfd < 0)
  {
    printf("Failed socket()\n");
    return -1;
  }

  serv_addr.sin_family = AF_INET;
  inet_pton(AF_INET, bind_ip, &(serv_addr.sin_addr));
  serv_addr.sin_port = htons(port);


  if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
  {
    printf("Failed bind()\n");
    return -1;
  }


  listen(sockfd, 30);



  while (true)
  {
    clilen = sizeof(cli_addr);
    addrlen = sizeof(addr);

    memset(buffer, 0, 255);
    new_fd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
    if (new_fd < 0)
    {
      printf("Failed accept()\n");
      return -1;
    }

    // printf("CLIENT IP is %s \n", inet_ntoa(cli_addr.sin_addr));

    if (read(new_fd, buffer, 255) < 0)
    {
      printf("Failed read()\n");
      return -1;
    }

    submitAnswer(inet_ntoa(cli_addr.sin_addr), buffer);

    if (strcmp(buffer, "hello") == 0)
    {
      memset(buffer, 0, 255);
      strncpy(buffer, server_hello, strlen(server_hello));
      if (write (new_fd, buffer, 255) < 0)
      {
        printf("Failed write()");
        return -1;
      }
    }
    else if (strcmp(buffer, "whoami") == 0)
    {
      if (write (new_fd, inet_ntoa(cli_addr.sin_addr), 255) < 0)
      {
        printf("Failed write()");
        return -1;
      }
    }
    else if (strcmp(buffer, "whoru") == 0)
    {
      getsockname(new_fd, (struct sockaddr*) &addr, &addrlen);
      if (write (new_fd, inet_ntoa(addr.sin_addr), 255) < 0)
      {
        printf("Failed write()");
        return -1;
      }
    }
    else
    {
      if (write (new_fd, buffer, 255) < 0)
      {
        printf("Failed write()");
        return -1;
      }
    }

    close(new_fd);
  }
  close(sockfd);
  
  return 0;
}

int EchoAssignment::clientMain(const char *server_ip, int port,
                               const char *command) {
  // Your client code
  // !IMPORTANT: do not use global variables and do not define/use functions
  // !IMPORTANT: for all system calls, when an error happens, your program must
  // return. e.g., if an read() call return -1, return -1 for clientMain.

  // printf("CLIENT CODE WAS USED -------------------------------------------------------------------- \n");
  int sockfd;
  struct sockaddr_in serv_addr;
  
  char buffer[256];
  memset(buffer, 0, 255);

  sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sockfd < 0)
  {
    printf("Failed socket() CLIENT");
    return -1;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = inet_addr(server_ip);
  serv_addr.sin_port = htons(port);

  if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
  {
    printf("Failed connect() CLIENT");
    return -1;
  }

  strncpy(buffer, command, strlen(command));

  if (write (sockfd, buffer, 255) < 0)
  {
    printf("Failed write() CLIENT");
    return -1;
  }

  memset(buffer, 0, 255);
  if (read(sockfd, buffer, 255) < 0)
  { 
    printf("Failed read() CLIENT \n");
    return -1;
  }

  submitAnswer(inet_ntoa(serv_addr.sin_addr), buffer);


  close(sockfd);
  return 0;
}

static void print_usage(const char *program) {
  printf("Usage: %s <mode> <ip-address> <port-number> <command/server-hello>\n"
         "Modes:\n  c: client\n  s: server\n"
         "Client commands:\n"
         "  hello : server returns <server-hello>\n"
         "  whoami: server returns <client-ip>\n"
         "  whoru : server returns <server-ip>\n"
         "  others: server echos\n"
         "Note: each command is terminated by newline character (\\n)\n"
         "Examples:\n"
         "  server: %s s 0.0.0.0 9000 hello-client\n"
         "  client: %s c 127.0.0.1 9000 whoami\n",
         program, program, program);
}

int EchoAssignment::Main(int argc, char *argv[]) {

  if (argc == 0)
    return 1;

  if (argc != 5) {
    print_usage(argv[0]);
    return 1;
  }

  int port = atoi(argv[3]);
  if (port == 0) {
    printf("Wrong port number\n");
    print_usage(argv[0]);
  }

  switch (*argv[1]) {
  case 'c':
    return clientMain(argv[2], port, argv[4]);
  case 's':
    return serverMain(argv[2], port, argv[4]);
  default:
    print_usage(argv[0]);
    return 1;
  }
}
