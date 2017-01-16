#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

// The following line declares a function pointer with the same prototype as the open function.  
int (*orig_close)(int fd);
int (*orig_open)(const char *pathname, int flags, ...);  // mode_t mode is needed when flags includes O_CREAT
int (*orig_read)(int fd, void *buf, size_t count);  
int (*orig_write)(int fd, const void* buf, size_t count);
int (*orig_lseek)(int fd, off_t offset, int whence);
int (*orig___xstat)(int ver, const char * path, struct stat * stat_buf);
int (*orig_unlink)(const char *pathname);
int (*orig_getdirentries)(int fd, char *buf, size_t nbytes, off_t *basep);
struct dirtreenode* (*orig_getdirtree)( const char *path );
void (*orig_freedirtree)( struct dirtreenode* dt );

#define MAXMSGLEN 100

// Connect to server
int connectServer() {
	char *serverip;
	char *serverport;
	unsigned short port;
	int sockfd, rv;
	struct sockaddr_in srv;
	
	// Get environment variable indicating the ip address of the server
	serverip = getenv("server15440");
	if(!serverip) serverip = "127.0.0.1";
	
	// Get environment variable indicating the port of the server
	serverport = getenv("serverport15440");

	if (!serverport) serverport = "15555";
	port = (unsigned short)atoi(serverport);
	
	// Create socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);	// TCP/IP socket
	if (sockfd<0) err(1, 0);			// in case of error
	
	// setup address structure to point to server
	memset(&srv, 0, sizeof(srv));			// clear it first
	srv.sin_family = AF_INET;			// IP family
	srv.sin_addr.s_addr = inet_addr(serverip);	// IP address of server
	srv.sin_port = htons(port);			// server port

	// actually connect to the server
	rv = connect(sockfd, (struct sockaddr*)&srv, sizeof(struct sockaddr));
	if (rv<0) {
		fprintf(stderr, "failed to connect to the server");
		err(1,0);
	}

	return sockfd;
}

int sendMsg(int sockfd, char* msg){
	// send message to server
	return send(sockfd, msg, strlen(msg), 0);	// send message; should check return value
}

int close(int fd) {
	int sockfd = connectServer();
	sendMsg(sockfd, "close");
	orig_close(sockfd);
	return orig_close(fd);
}

// This is our replacement for the open function from libc.
int open(const char *pathname, int flags, ...) {
	mode_t m=0;
	if (flags & O_CREAT) {
		va_list a;
		va_start(a, flags);
		m = va_arg(a, mode_t);
		va_end(a);
	}
	int sockfd = connectServer();
	sendMsg(sockfd, "open");
	orig_close(sockfd);
	return orig_open(pathname, flags, m);
}

ssize_t read(int fd, void *buf, size_t count) {
	int sockfd = connectServer();
	sendMsg(sockfd, "read");
	orig_close(sockfd);
	return orig_read(fd, buf, count);
}

ssize_t write(int fd, const void* buf, size_t count) {
	int sockfd = connectServer();
	sendMsg(sockfd, "write");
	orig_close(sockfd);
	return orig_write(fd, buf, count);
}

off_t lseek(int fd, off_t offset, int whence) {
	int sockfd = connectServer();
	sendMsg(sockfd, "lseek");
	orig_close(sockfd);
	return orig_lseek(fd, offset, whence);
}

int unlink(const char *pathname) {
	int sockfd = connectServer();
	sendMsg(sockfd, "unlink");
	orig_close(sockfd);
	return orig_unlink(pathname);
}

int __xstat(int ver, const char * path, struct stat * stat_buf) {
	int sockfd = connectServer();
	sendMsg(sockfd, "__xstat");
	orig_close(sockfd);
	return orig___xstat(ver, path, stat_buf);
}

int getdirentries(int fd, char *buf, size_t nbytes, off_t *basep) {
	int sockfd = connectServer();
	sendMsg(sockfd, "getdirentries");
	orig_close(sockfd);
	return orig_getdirentries(fd, buf, nbytes, basep);
}


struct dirtreenode* getdirtree(const char *path ) {
	int sockfd = connectServer();
	sendMsg(sockfd, "getdirtree");
	orig_close(sockfd);
	struct dirtreenode* node = NULL;
	node = orig_getdirtree(path);
	return node;
}

void freedirtree( struct dirtreenode* dt ) {
	int sockfd = connectServer();
	sendMsg(sockfd, "freedirtree");
	orig_close(sockfd);
	orig_freedirtree(dt);
	return;
}

// This function is automatically called when program is started
void _init(void) {
	// set function pointer orig_open to point to the original open function
	orig_open = dlsym(RTLD_NEXT, "open");
	orig_lseek = dlsym(RTLD_NEXT, "lseek");
	orig_read = dlsym(RTLD_NEXT, "read");
	orig_write = dlsym(RTLD_NEXT, "write");
	orig_close = dlsym(RTLD_NEXT, "close");
	orig___xstat = dlsym(RTLD_NEXT, "__xstat");
	orig_unlink = dlsym(RTLD_NEXT, "unlink");
	orig_getdirentries = dlsym(RTLD_NEXT, "getdirentries");
	orig_getdirtree = dlsym(RTLD_NEXT, "getdirtree");
	orig_freedirtree = dlsym(RTLD_NEXT, "freedirtree");
}


