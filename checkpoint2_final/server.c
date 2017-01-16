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

#define OP_CLOSE 1
#define OP_OPEN 2
#define OP_WRITE 3

#define MAXMSGLEN 100

void op_close(void *ptr, int sessfd);
void op_write(void *ptr, int sessfd);
void op_open(void *ptr, int sessfd, int nfd);

int main(int argc, char**argv) {
	char *serverport;
	unsigned short port;
	int sockfd, sessfd, rv, forkv;
	struct sockaddr_in srv, cli;
	socklen_t sa_size;
	int nfd;
	
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
		        rv = recv(sessfd, buf, 4, 0);
		        if (rv < 0) err(1, 0);
		        memcpy(&total_size, buf, 4);
		        free(buf);
		        buf = malloc(total_size);
		        void *ptr = buf;
		        while (total_size > 0) {
		            rv = recv(sessfd, ptr, total_size, 0);
		            if (rv < 0) err(1, 0);
		            ptr += rv;
		            total_size -= rv;
		        }
		        ptr = buf;
		        memcpy(&op_type, ptr, 4);
		        ptr += 4;
		        switch(op_type){
		        	case OP_OPEN:
		        		op_open(ptr, sessfd, nfd);
		        		break;
		        	case OP_WRITE:
		        		op_write(ptr, sessfd);
		        		break;
		        	case OP_CLOSE:
		        		op_close(ptr, sessfd);
		        		break;
		        	default:
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

void op_open(void *ptr, int sessfd, int nfd) {
	// In 	: | flags 4 | m 4 | path_len 4 | pathname |
	// Out 	: | fd 4 | errno 4 |	
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
    nfd = open(buf, flags, m);
    char *ret = malloc(8);
    ptr = ret;
    memcpy(ptr, &nfd, 4);
    ptr += 4;
    memcpy(ptr, &errno, 4);
    int sv = send(sessfd, ret, 8, 0);
    if (sv < 0) err(1, 0);
    free(ret);
    free(buf);
}

void op_write(void *ptr, int sessfd) {
	// In 	: | fd 4 | size sizeof(size_t) | buf n |
	// Out 	: | num 4 | errno 4 |
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
    char *ret = malloc(8);
    ptr = ret;
    memcpy(ptr, &return_value, 4);
    ptr += 4;
    memcpy(ptr, &errno, 4);
    int sv = send(sessfd, ret, 8, 0);
    if (sv < 0) err(1, 0);
    free(ret);
    free(buf);
}

void op_close(void *ptr, int sessfd) {
	// In 	: | fd 4 |	
	// Out 	: | ret 4| errno 4 | 
	fprintf(stderr, "enter op_close\n");
    int fd = 0;
    memcpy(&fd, ptr, 4);
    int return_value = close(fd);
    char *ret = malloc(8);
    ptr = ret;
    memcpy(ptr, &return_value, 4);
    ptr += 4;
    memcpy(ptr, &errno, 4);
    int sv = send(sessfd, ret, 8, 0); 
    if (sv < 0) err(1, 0);
    free(ret);
}

