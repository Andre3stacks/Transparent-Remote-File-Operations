#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <dirent.h>
#include "dirtree.h"


#define OP_CLOSE 1
#define OP_OPEN 2
#define OP_WRITE 3
#define OP_READ 4
#define OP_LSEEK 5
#define OP_UNLINK 6
#define OP_XSTAT 7
#define OP_GETDIRENTRIES 8
#define OP_GETDIRTREE 9

#define MAXMSGLEN 100

void op_close(void *ptr, int sessfd);
void op_write(void *ptr, int sessfd);
void op_open(void *ptr, int sessfd);
void op_read(void *ptr, int sessfd);
void op_lseek(void *ptr, int sessfd);
void op_xstat(void *ptr, int sessfd);
void op_unlink(void *ptr, int sessfd);
void op_getdirtree(void *ptr, int sessfd);
void op_getdirentries(void *ptr, int sessfd);
void send_nbytes(int sockfd, void *buf, size_t len, int flags);
void recv_nbytes(int sockfd, void *buf, size_t len, int flags);
void freedirtree( struct dirtreenode* dt );
void send_node(struct dirtreenode *root, int sessfd);

int main(int argc, char**argv) {
	char *serverport;
	unsigned short port;
	int sockfd, sessfd, rv, forkv;
	struct sockaddr_in srv, cli;
	socklen_t sa_size;
	
	// Get environment variable indicating the port of the server
	serverport = getenv("serverport15440");
	if (serverport) port = (unsigned short)atoi(serverport);
	else port=15555;
	
	// Create socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);	// TCP/IP socket
	if (sockfd<0) err(1, 0);			// in case of error
	
	// setup address structure to indicate server port
	memset(&srv, 0, sizeof(srv));			// clear it first
	srv.sin_family = AF_INET;			// IP family
	srv.sin_addr.s_addr = htonl(INADDR_ANY);	// don't care IP address
	srv.sin_port = htons(port);			// server port

	// bind to our port
	rv = bind(sockfd, (struct sockaddr*)&srv, sizeof(struct sockaddr));
	if (rv<0) err(1,0);

	int flag = 1;
	// disable the Nagle's algorithm 
    int result = setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));  
    if (result < 0) {
        err(1, 0);
    }
	
	// start listening for connections
	rv = listen(sockfd, 5);
	if (rv<0) err(1,0);
	
	// main server loop, handle clients one at a time, quit after 10 clients
	while (1) { 
        // wait for next client, get session socket
        sa_size = sizeof(struct sockaddr_in);
        sessfd = accept(sockfd, (struct sockaddr *) &cli, &sa_size);
        if (sessfd < 0) {
            close(sessfd);
            err(1, 0);
        }
        forkv = fork();
        if(forkv==0){
        	while(1){
        		char *buf = malloc(4);
		        int op_type; 
		        int total_size = 0;
		        recv_nbytes(sessfd, buf, 4, 0);
		        memcpy(&total_size, buf, 4);
		        free(buf);
		        buf = malloc(total_size);
		        void *ptr = buf;
		        recv_nbytes(sessfd, ptr, total_size, 0);
		        ptr = buf;
		        memcpy(&op_type, ptr, 4);
		        ptr += 4;
		        switch(op_type){
		        	case OP_OPEN:
		        		op_open(ptr, sessfd);
		        		break;
		        	case OP_WRITE:
		        		op_write(ptr, sessfd);
		        		break;
		        	case OP_CLOSE:
		        		op_close(ptr, sessfd);
		        		break;
	        		case OP_READ:
		        		op_read(ptr, sessfd);
		        		break;
		        	case OP_LSEEK:
		        		op_lseek(ptr, sessfd);
		        		break;
		        	case OP_UNLINK:
		        		op_unlink(ptr, sessfd);
		        		break;
		        	case OP_XSTAT:
		        		op_xstat(ptr, sessfd);
		        		break;
		        	case OP_GETDIRENTRIES:
		        		op_getdirentries(ptr, sessfd);
		        		break;
		        	case OP_GETDIRTREE:
		        		op_getdirtree(ptr, sessfd);
		        		break;
		        	default:
                        fprintf(stderr, "ERROR! in switch \n");
		        		free(buf);
		                close(sessfd);
		                exit(0);
		        }
		        free(buf);
        	}  
        }
    }
	fprintf(stderr, "server shutting down cleanly\n");
	// close socket
	close(sockfd);
	return 0;
}

void freedirtree( struct dirtreenode* dt ) {
    if(dt == NULL) return;
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

void op_getdirtree(void *ptr, int sessfd) {
    fprintf(stderr, "enter op_getdirtree\n");
    int len = 0;
    memcpy(&len, ptr, 4);
    ptr += 4;
    char *path = malloc(len+1);
    memcpy(path, ptr, len);
    path[len]=0;
    struct dirtreenode *root;
    root = getdirtree(path);
    send_node(root, sessfd);
    free(path);
    freedirtree(root);
}

void send_node(struct dirtreenode *root, int sessfd) {
    int name_len = strlen(root->name);
    char *buf = malloc(name_len+1);
    void *ptr = buf;
    int i=0;
    send_nbytes(sessfd, &name_len, 4, 0); 
    memcpy(ptr, root->name, name_len);
    buf[name_len] = 0;
    send_nbytes(sessfd, buf, name_len, 0); 
    free(buf);
    int num_sub = root->num_subdirs;
    send_nbytes(sessfd, &num_sub, 4, 0);
    for(; i < num_sub; i++) {
        send_node(root->subdirs[i], sessfd);
    }
}

void op_getdirentries(void *ptr, int sessfd) {
    fprintf(stderr, "enter op_getdirentries\n");
    // ptr: | fd 4 | nbytes size_t | basep off_t |
    int fd = 0;
    memcpy(&fd, ptr, 4);
    ptr += 4;
    size_t nbytes = 0;
    memcpy(&nbytes, ptr, sizeof(size_t));
    ptr += sizeof(size_t);
    off_t basep = 0;
    memcpy(&basep, ptr, sizeof(off_t));
    char *buf = malloc(nbytes);
    ssize_t rv = getdirentries(fd, buf, nbytes, &basep);
    send_nbytes(sessfd, &rv, sizeof(ssize_t), 0); // send return value
    send_nbytes(sessfd, &errno, 4, 0); // send errno
    if(rv>0){
        send_nbytes(sessfd, buf, rv, 0); // send buffer
        send_nbytes(sessfd, &basep, sizeof(off_t), 0); // update basep
    }
    free(buf);
}

void op_unlink(void *ptr, int sessfd){
	fprintf(stderr, "enter op_unlink\n");
	// ptr: | len 4 | pathname len |
    int len = 0;
    memcpy(&len, ptr, 4);
    ptr += 4;
    char *name = malloc(len+1);
    memcpy(name, ptr, len);
    name[len]=0;
    int ret = unlink(name);
    // send: | return value | errno |
    char *buf = malloc(8);
    ptr = buf;
    memcpy(ptr, &ret, 4);
    ptr += 4;
    memcpy(ptr, &errno, 4);
    send_nbytes(sessfd, buf, 8, 0);
    free(buf);
    free(name);
}

void op_xstat(void *ptr, int sessfd) {
	fprintf(stderr, "enter op_xstat\n");
	// ptr: | ver 4 | len 4 | pathname len |
    int ver = 0;
    memcpy(&ver, ptr, 4);
    ptr += 4;
    int len = 0;
    memcpy(&len, ptr, 4);
    ptr += 4;
    char * path = malloc(len+1);
    memcpy(path, ptr, len);
    path[len]=0;
    struct stat * stat_buf = malloc(sizeof(struct stat));
    int ret=__xstat(ver, path, stat_buf);
    char *buf = malloc(8 + sizeof(struct stat));
    // send: | ret | errno | stat_buf |
    memcpy(buf, &ret, 4);
    ptr = buf+4;
    memcpy(ptr, &errno, 4);
    ptr += 4;
    memcpy(ptr, stat_buf, sizeof(struct stat));
    send_nbytes(sessfd, buf, 8 + sizeof(struct stat), 0);
    free(stat_buf);
    free(buf);
    free(path);
}

void op_lseek(void *ptr, int sessfd){
	// ptr: | fd 4 | offset sizeof(off_t) | whence 4 
	fprintf(stderr, "enter op_lseek\n");
	int fd = 0;
    memcpy(&fd, ptr, 4);
    ptr += 4;
    off_t offset = 0;
    memcpy(&offset, ptr, sizeof(off_t));
    ptr += sizeof(off_t);
    int whence = 0;
    memcpy(&whence, ptr, 4);
    off_t rv = lseek(fd, offset, whence);
    // send: | return value | errno |
    void *buf = malloc(sizeof(off_t) + 4);
    ptr = buf;
    memcpy(ptr, &rv, sizeof(off_t));
    ptr += sizeof(off_t);
    memcpy(ptr, &errno, 4);
    send_nbytes(sessfd, buf, sizeof(off_t) + 4, 0);
    free(buf);
}

void op_read(void *ptr, int sessfd) {
	// ptr 	: | fd 4 | num sizeof(size_t) |
	fprintf(stderr, "enter op_read\n");
    int fd = 0;
    memcpy(&fd, ptr, 4);
    ptr += 4;
    size_t num = 0;
    memcpy(&num, ptr, sizeof(size_t));
    void *content = malloc(num);
    int count = read(fd, content, num);
    void *buf = malloc(8);
    memcpy(buf, &count, 4);
    ptr = buf+4;
    memcpy(ptr, &errno, 4);
    // send : | the number of bytes read | errno |
	send_nbytes(sessfd, buf, 8, 0);
    free(buf);
	if(count>0) {
        // send : | content |
        buf = malloc(count);
        memcpy(buf, content, count);
        send_nbytes(sessfd, buf, count, 0);
        free(buf);     
    }
    free(content);
}

void op_close(void *ptr, int sessfd) {
    // ptr   : | fd 4 |  
    fprintf(stderr, "enter op_close\n");
    int fd = 0;
    memcpy(&fd, ptr, 4);
    int return_value = close(fd);
    char *buf = malloc(8);
    ptr = buf;
    memcpy(ptr, &return_value, 4);
    ptr += 4;
    memcpy(ptr, &errno, 4);
    // send  : | ret 4 | errno 4 | 
    send_nbytes(sessfd, buf, 8, 0); 
    free(buf);
}

void op_open(void *ptr, int sessfd) {
	// ptr 	: | flags 4 | m 4 | path_len 4 | pathname |
    fprintf(stderr, "enter op_open\n");
    int flags = 0;
    memcpy(&flags, ptr, 4);
    ptr += 4;
    mode_t m = 0;
    memcpy(&m, ptr, 4);
    ptr += 4;
    int path_len = 0;
    memcpy(&path_len, ptr, 4);
    ptr += 4;
    char *buf = malloc(path_len);
    memcpy(buf, ptr, path_len);
    int fd = open(buf, flags, m);
    free(buf);
    buf = malloc(8);
    ptr = buf;
    memcpy(ptr, &fd, 4);
    ptr += 4;
    memcpy(ptr, &errno, 4);
	// send	: | fd 4 | errno 4 |	
    send_nbytes(sessfd, buf, 8, 0);
    free(buf);
}

void op_write(void *ptr, int sessfd) {
	// ptr 	: | fd 4 | size sizeof(size_t) | buf n |
    fprintf(stderr, "enter op_write\n");
    int fd = 0;
    memcpy(&fd, ptr, 4);
    ptr += 4;
    size_t size = 0;
    memcpy(&size, ptr, sizeof(size_t));
    ptr += sizeof(size_t);
    char *buf = malloc(size);
    memcpy(buf, ptr, size);
    int return_value = write(fd, buf, size);
	// send: | num 4 | errno 4 |
    char *ret = malloc(8);
    ptr = ret;
    memcpy(ptr, &return_value, 4);
    ptr += 4;
    memcpy(ptr, &errno, 4);
    send_nbytes(sessfd, ret, 8, 0);
    free(ret);
    free(buf);
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
