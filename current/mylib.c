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
#include "dirtree.h"

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
void send_nbytes(int sockfd, void *buf, size_t len, int flags);
void recv_nbytes(int sockfd, void *buf, size_t len, int flags);
int connectServer();
struct dirtreenode * createtree();

#define OP_CLOSE 1
#define OP_OPEN 2
#define OP_WRITE 3
#define OP_READ 4
#define OP_LSEEK 5
#define OP_UNLINK 6
#define OP_XSTAT 7
#define OP_GETDIRENTRIES 8
#define OP_GETDIRTREE 9

#define MAXFD 2000

int sockfd = -1;

struct dirtreenode * getdirtree(const char *path) {
    // inform server the packet size
    int len = strlen(path);
    int total_size = 8 + len;
    send_nbytes(sockfd, &total_size, 4, 0);
    // send to server: | operation type 4 | path length 4| path len|
    char *packet = malloc(total_size);
    void *ptr = packet;
    int type = OP_GETDIRTREE;
    memcpy(ptr, &type, 4);
    ptr += 4;
    memcpy(ptr, &len, 4);
    ptr += 4;
    memcpy(ptr, path, len);
    send_nbytes(sockfd, packet, total_size, 0);
    free(packet);
    return createtree();
}

struct dirtreenode * createtree() {
    struct dirtreenode *root = malloc(sizeof(struct dirtreenode *));
    int name_len = 0;
    char *buf = malloc(4);
    int i = 0;
    recv_nbytes(sockfd, buf, 4, 0); 
    memcpy(&name_len, buf, 4);
    char *name = malloc(name_len);
    recv_nbytes(sockfd, name, name_len, 0); 
    root->name = name;
    int num_sub = 0;
    recv_nbytes(sockfd, buf, 4, 0); 
    memcpy(&num_sub, buf, 4);
    free(buf);
    root->num_subdirs = num_sub;
    root->subdirs = malloc(sizeof(struct dirtreenode *) * num_sub);
    for(; i < num_sub; i++){
        root->subdirs[i] = createtree();
    }
    return root;
}

ssize_t getdirentries(int fd, char *buf, size_t nbytes, off_t *basep) {
    if (fd < MAXFD) {
        return orig_getdirentries(fd, buf, nbytes, basep);
    } else {
        fd -= MAXFD;
    }
    // inform server the packet size
    int total_size = 8 + sizeof(size_t) + sizeof(off_t);
    send(sockfd, &total_size, 4, 0);
    // send packet : | op_type 4 | fd 4 | nbytes size_t | basep off_t |
    char *packet = malloc(total_size);
    void *ptr = packet;
    int type = OP_GETDIRENTRIES;
    ssize_t size_read = 0;
    memcpy(ptr, &type, 4);
    ptr += 4;
    memcpy(ptr, &fd, 4);
    ptr += 4;
    memcpy(ptr, &nbytes, sizeof(size_t));
    ptr += sizeof(size_t);
    memcpy(ptr, basep, sizeof(off_t));
    send_nbytes(sockfd, packet, total_size, 0);
    free(packet);
    // receive | return value |
    char *revBuf = malloc(sizeof(ssize_t));
    recv_nbytes(sockfd, revBuf, sizeof(ssize_t), 0);   
    memcpy(&size_read, revBuf, sizeof(ssize_t));
    free(revBuf);
    // receive | errno 4 |
    revBuf=malloc(4);
    recv_nbytes(sockfd, revBuf, 4, 0); 
    memcpy(&errno, revBuf, 4);
    free(revBuf);
    if (size_read > 0) {
        // if size_read > 0, udpate buf and basep
        recv_nbytes(sockfd, buf, size_read, 0);
        revBuf = malloc(sizeof(off_t));
        recv_nbytes(sockfd, revBuf, sizeof(off_t), 0);
        memcpy(basep, revBuf, sizeof(off_t));
        free(revBuf);
    }
    return size_read;
}

void freedirtree( struct dirtreenode* dt ) {
    int num = dt->num_subdirs;
    int i = 0;
    // recursively frees the tree;
    for (; i < num; i++) {
        freedirtree(dt->subdirs[i]);
    }
    free(dt->name);
    free(dt->subdirs);
    free(dt);
}

void send_nbytes(int sockfd, void *buf, size_t len, int flags){
    int sv=0;
    void *ptr=buf;
    while(len>0){
        sv = send(sockfd, ptr, len, flags);
        if (sv < 0) err(1, 0);
        ptr+=sv;
        len-= sv;
    }
}

void recv_nbytes(int sockfd, void *buf, size_t len, int flags){
    int rv=0;
    void *ptr = buf;
    while (len > 0){ 
        rv = recv(sockfd, ptr, len, flags);
        if (rv < 0) err(1, 0);
        ptr += rv;
        len -= rv;
    }
}

int unlink(const char *pathname) {
    // inform server the packet size
    int len = strlen(pathname);
    int total_size = 8 + len;
    send_nbytes(sockfd, &total_size, 4, 0);
    // packet structure: | op_type 4 | len 4 | pathname len | 
    char *packet = malloc(total_size);
    void *ptr = packet;
    int type = OP_UNLINK;
    memcpy(ptr, &type, 4);
    ptr += 4;
    memcpy(ptr, &len, 4);
    ptr += 4;
    memcpy(ptr, pathname, len);
    send_nbytes(sockfd, packet, total_size, 0);
    free(packet);
    char *buf = malloc(8);
    // receive: | return value | errno |
    recv_nbytes(sockfd, buf, 8, 0);    
    ptr = buf;
    int ret = 0;
    memcpy(&ret, ptr, 4);
    ptr += 4;
    memcpy(&errno, ptr, 4);
    free(buf);
    return ret;
}

int __xstat(int ver, const char * path, struct stat * stat_buf) {
    // inform server the packet size
    int len = strlen(path);
    int total_size = 12 + len;
    // packet structure: | op_type 4 | ver 4 | len 4 | pathname len |
    send_nbytes(sockfd, &total_size, 4, 0);
    char *packet = malloc(12+ len);
    void *ptr = packet;
    int type = OP_XSTAT;
    memcpy(ptr, &type, 4);
    ptr += 4;
    memcpy(ptr, &ver, 4);
    ptr += 4;
    memcpy(ptr, &len, 4);
    ptr += 4;
    memcpy(ptr, path, len);
    send_nbytes(sockfd, packet, total_size, 0);
    free(packet);
    char *buf = malloc(8 + sizeof(struct stat));
    // receive: | ret | errno | stat_buf |
    recv_nbytes(sockfd, buf, 8 + sizeof(struct stat), 0);    
    ptr = buf;
    int ret = 0;
    memcpy(&ret, ptr, 4);
    ptr += 4;
    memcpy(&errno, ptr, 4);
    ptr += 4;
    memcpy(stat_buf, ptr, sizeof(struct stat));
    free(buf);
    return ret;
}

off_t lseek(int fd, off_t offset, int whence) {
    if (fd < MAXFD) {
        return orig_lseek(fd, offset, whence);
    } else {
        fd -= MAXFD;
    }
    // inform server the packet size
    int total_size = 12 + sizeof(off_t);
    send_nbytes(sockfd, &total_size, 4, 0);

    off_t ret = 0;
    // packet structure: | op_type 4 | fd 4 | offset sizeof(off_t) | whence 4 |
    char *packet = malloc(total_size);
    void *ptr = packet;
    int type = OP_LSEEK;
    memcpy(ptr, &type, 4);
    ptr += 4;
    memcpy(ptr, &fd, 4);
    ptr += 4;
    memcpy(ptr, &offset, sizeof(off_t));
    ptr = ptr + (sizeof(off_t));
    memcpy(ptr, &whence, 4);
    send_nbytes(sockfd, packet, total_size, 0);
    free(packet);
    // receive: | return value | errno |
    char *buf = malloc(sizeof(off_t) + 4);
    ptr = buf;
    recv_nbytes(sockfd, buf, (sizeof(off_t)+4), 0);
    memcpy(&ret, buf, sizeof(off_t));
    ptr = buf + sizeof(off_t);
    memcpy(&errno, ptr, 4);
    free(buf);
    return ret;
}

ssize_t read(int fd, void *buf, size_t n) {
    if (fd < MAXFD) {
        return orig_read(fd, buf, n);
    } else {
        fd -= MAXFD;
    }
    // inform server the packet size
    int total_size = 8 + sizeof(size_t);
    send_nbytes(sockfd, &total_size, 4, 0);
    // packet structure: | op_type 4 | fd 4 | size n |
    char *packet = malloc(total_size);
    void *ptr = packet;
    int type = OP_READ;
    memcpy(ptr, &type, 4);
    ptr += 4;
    memcpy(ptr, &fd, 4);
    ptr += 4;
    memcpy(ptr, &n, sizeof(size_t));
    send_nbytes(sockfd, packet, total_size, 0);
    free(packet);
    char *a = malloc(8);
    // receive : | bytes_read | errno |
    recv_nbytes(sockfd, a, 8, 0); 
    int count = 0;
    memcpy(&count, a, 4);
    ptr=a+4;
    memcpy(&errno, ptr, 4);
    free(a);
    if (count > 0) {
        char *b = malloc(count);
        recv_nbytes(sockfd, b, count, 0);
        memcpy(buf, b, count);
        free(b);
    }
    return count;
}

int close(int fd) {
    if (fd < MAXFD) {
        return orig_close(fd);
    } else {
        fd -= MAXFD;
    }
    // inform server the packet size
    int total_size = 8;
    send_nbytes(sockfd, &total_size, 4, 0);

    // send packet to server
    // packet structure: | op_type 4 | fd 4 |
    char *packet = malloc(total_size);
    void *ptr = packet;
    int type = OP_CLOSE;
    memcpy(ptr, &type, 4);
    ptr += 4;
    memcpy(ptr, &fd, 4);
    send_nbytes(sockfd, packet, 8, 0);
    free(packet);

    // receive packet from server
    // packet structure: | return_value 4 | errno 4 |
    char *buf = malloc(8);
    recv_nbytes(sockfd, buf, 8, 0);  
    ptr = buf;
    int ret = 0;
    memcpy(&ret, ptr, 4);
    ptr += 4;
    memcpy(&errno, ptr, 4);
    free(buf);
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
    int path_len = strlen(pathname);
    int total_size = path_len + 16;
    send_nbytes(sockfd, &total_size, 4, 0);

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
    memcpy(ptr, &path_len, 4);
    ptr += 4;
    memcpy(ptr, pathname, path_len);
    send_nbytes(sockfd, packet, total_size, 0);
    free(packet);

    // receive packet from server
    // packet structure: | fd 4 | errno 4 |
    char *buf = malloc(8);
    recv_nbytes(sockfd, buf, 8, 0);    
    ptr = buf;
    int fd = 0;
    memcpy(&fd, ptr, 4);
    if (fd > 0) {
        fd += MAXFD;
    }
    ptr += 4;
    memcpy(&errno, ptr, 4);
    free(buf);
    return fd;
}

ssize_t write(int fd, const void* buf, size_t n) {
    if (fd < MAXFD) {
        return orig_write(fd, buf, n);
    } else {
        fd -= MAXFD;
    }
    // inform server the packet size
    int total_size = 8 + sizeof(size_t) + n;
    send_nbytes(sockfd, &total_size, 4, 0);

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
    send_nbytes(sockfd, packet, total_size, 0);
    free(packet);

    // receive packet from server
    // packet structure: | num 4 | errno 4 |
    char *revBuf = malloc(8);
    recv_nbytes(sockfd, revBuf, 8, 0);   
    ptr = revBuf;
    int num = 0;
    memcpy(&num, ptr, 4);
    ptr += 4;
    memcpy(&errno, ptr, 4);
    free(revBuf);
    return num;
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
    sockfd = socket(AF_INET, SOCK_STREAM, 0);   // TCP/IP socket
    if (sockfd<0) err(1, 0);            // in case of error
    
    // setup address structure to point to server
    memset(&srv, 0, sizeof(srv));           // clear it first
    srv.sin_family = AF_INET;           // IP family
    srv.sin_addr.s_addr = inet_addr(serverip);  // IP address of server
    srv.sin_port = htons(port);         // server port

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

