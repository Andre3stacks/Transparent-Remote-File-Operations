#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>

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

#define OP_CLOSE 1
#define OP_OPEN 2
#define OP_WRITE 3
#define FINISH 4

#define MAXMSGLEN 100

int sockfd = -1;

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
		return -1;
	} else{
		int flag = 1;
		// disable the Nagle's algorithm 
        int result = setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
        if (result < 0) {
            err(1, 0);
        }
        return sockfd;
	}
}

int sendMsg(int sockfd, char* msg){
	// send message to server
	return send(sockfd, msg, strlen(msg), 0);	// send message; should check return value
}

int close(int fd) {
    // inform server the packet size
    int total_size = 8;
    int sv = send(sockfd, &total_size, 4, 0);
    if (sv < 0) err(1, 0);

    // send packet to server
    // packet structure: | op_type 4 | fd 4 |
    char *packet = malloc(total_size);
    void *ptr = packet;
    int type = OP_CLOSE;
    memcpy(ptr, &type, 4);
    ptr += 4;
    memcpy(ptr, &fd, 4);
    sv = send(sockfd, packet, 8, 0);
    if (sv < 0) err(1, 0);
    free(packet);

    // receive packet from server
    // packet structure: | return_value 4 | errno 4 |
    char *revBuf = malloc(8);
    int rv = recv(sockfd, revBuf, 8, 0);  
    if (rv < 0) err(1, 0);
    ptr = revBuf;
    int ret = 0;
    memcpy(&ret, ptr, 4);
    ptr += 4;
    memcpy(&errno, ptr, 4);
    free(revBuf);
    return ret;
}

int open(const char *pathname, int flags, ...) {
    mode_t m=0;
    if (flags & O_CREAT) {
        va_list a;
        va_start(a, flags);
        m = va_arg(a, mode_t);
        va_end(a);
    }

    // inform server the packet size
    int total_size = strlen(pathname) + 16;
    int sv = send(sockfd, &total_size, 4, 0);
    if (sv < 0) err(1, 0);

    // send packet to server
    // packet structure: | op_type 4 | flags 4 | m 4 | path_len 4 | pathname |
    char *packet = malloc(total_size);
    void *ptr = packet;
    int type = OP_OPEN;
    memcpy(ptr, &type, 4);
    ptr += 4;
    memcpy(ptr, &flags, 4);
    ptr += 4;
    memcpy(ptr, &m, 4);
    ptr += 4;
    int path_len = strlen(pathname);
    memcpy(ptr, &path_len, 4);
    ptr += 4;
    memcpy(ptr, pathname, path_len);
    sv = send(sockfd, packet, total_size, 0);
    if (sv < 0) err(1, 0);
    free(packet);

    // receive packet from server
    // packet structure: | fd 4 | errno 4 |
    char *revBuf = malloc(8);
    int rv = recv(sockfd, revBuf, 8, 0);    
    if (rv < 0) err(1, 0);
    ptr = revBuf;
    int fd = 0;
    memcpy(&fd, ptr, 4);
    ptr += 4;
    memcpy(&errno, ptr, 4);
    free(revBuf);
    return fd;
}

ssize_t read(int fd, void *buf, size_t n) {
	int sockfd = connectServer();
	sendMsg(sockfd, "read");
	orig_close(sockfd);
	return orig_read(fd, buf, n);
}

ssize_t write(int fd, const void* buf, size_t n) {
    // inform server the packet size
    int total_size = 8 + sizeof(size_t) + n;
    int sv = send(sockfd, &total_size, 4, 0);
    if (sv < 0) err(1, 0);

    // send packet to server
    // packet structure: | op_type 4 | fd 4 | size sizeof(size_t) | buf n |
    char *packet = malloc(total_size);
    void *ptr = packet;
    int type = OP_WRITE;
    memcpy(ptr, &type, 4);
    ptr += 4;
    memcpy(ptr, &fd, 4);
    ptr += 4;
    memcpy(ptr, &n, sizeof(size_t));
    ptr += sizeof(size_t);
    memcpy(ptr, buf, n);
    sv = send(sockfd, packet, total_size, 0);
    free(packet);
    if (sv < 0) err(1, 0);

    // receive packet from server
    // packet structure: | num 4 | errno 4 |
    char *revBuf = malloc(8);
    int rv = recv(sockfd, revBuf, 8, 0);    // get message
    if (rv < 0) err(1, 0);
    ptr = revBuf;
    int num = 0;
    memcpy(&num, ptr, 4);
    ptr += 4;
    memcpy(&errno, ptr, 4);
    free(revBuf);
    return num;
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

	sockfd = connectServer();
    if (sockfd == -1) {
        fprintf(stderr, "fail to connect to server\n");
    }
}

void _fini(void) {
    int size = 4;
    int sv = send(sockfd, &size, 4, 0);
    if (sv < 0) err(1, 0);
    int type = FINISH;
    sv = send(sockfd, &type, 4, 0);
    if (sv < 0) err(1, 0);
    orig_close(sockfd);
}

