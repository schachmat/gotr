#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

// where are we talking
#define ROOMDIR "/tmp/gotrusers/"
#define UNIX_PATH_MAX 108
#define BUFLEN 2048

typedef struct sockaddr sockaddr;
typedef struct sockaddr_un sockaddr_un;
typedef struct timeval timeval;

// variables
static char* nick;

// prototypes
void die(const char *message);
static int send_all(const char* message);
static int send_user(const char* message, const char* user);
int main(int argc, char* argv[]);

void die(const char *message) {
	fprintf(stderr, "err: %s\n", message);
	exit(1);
}

// sends the message to all clients in the room
static int
send_all(const char* message) {
	DIR *directory;
	struct dirent *dir;
	int socket_fd;
	char socket_path[128];
	struct sockaddr_un address;
	
	socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	
	directory = opendir(ROOMDIR);
	
	if(directory) {
		while((dir = readdir(directory)) != NULL) {
			if((dir->d_type == DT_SOCK) && (!strcmp(nick, dir->d_name))) {
				strcpy(socket_path, ROOMDIR);
				strcat(socket_path, dir->d_name);
				memset(&address, 0, sizeof(struct sockaddr_un));
				address.sun_family = AF_UNIX;
				snprintf(address.sun_path, 100, "%s", socket_path);
				
				if (connect(socket_fd, (struct sockaddr *) &address, sizeof(struct sockaddr_un)) != 0) {
					die("connect() failed");
				}
				
				write(socket_fd, message, strlen(message));
				
				close(socket_fd);
			}
		}
		
		closedir(directory);
	}
}

// sends the message to the user
static int
send_user(const char* message, const char* user) {
	return 0;
}

int
main(int argc, char* argv[]) {
	int res;
	timeval timeout;
	fd_set reads;
	fd_set errs;
	sockaddr_un address;
	int socket_fd;
	char fname[109];
	char buf[BUFLEN];

	if(argc < 2) {
		fprintf(stderr, "client nickname required\n");
		return 1;
	}

	nick = argv[1];
	printf("entering room as %s\n", nick);

	send_all("hi there, do you like cake?");

	socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(socket_fd < 0) {
		fprintf(stderr, "socket() failed\n");
		return 1;
	}

	mkdir(ROOMDIR, 0755);
	sprintf(fname, "%s%s", ROOMDIR, nick);
	fname[108] = '\0';
	unlink(fname);

	memset(&address, 0, sizeof(sockaddr_un));
	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, UNIX_PATH_MAX, "%s", fname);

	if(bind(socket_fd, (sockaddr*)&address, sizeof(sockaddr_un)) != 0) {
		fprintf(stderr, "bind() failed\n");
		return 1;
	}

	if(listen(socket_fd, 10) != 0) {
		fprintf(stderr, "listen() failed\n");
		return 1;
	}

	while(1) {
		FD_ZERO(&reads);
		FD_SET(STDIN_FILENO, &reads);
		FD_SET(socket_fd, &reads);
		FD_ZERO(&errs);
		FD_SET(socket_fd, &errs);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		if((res = select(socket_fd + 1, &reads, (fd_set*) 0, &errs, &timeout)) < 0) {
			fprintf(stderr, "select() failed\n");
			goto quit;
		} else if(res != 0) {
			if(FD_ISSET(socket_fd, &errs)) {
				fprintf(stderr, "our socket died. k thx bye.\n");
				return 1;
			}
			if(FD_ISSET(socket_fd, &reads)) {
				fprintf(stderr, "we got a massage!\n");
			}
			if(FD_ISSET(STDIN_FILENO, &reads)) {
				if(fgets(buf, BUFLEN, stdin)) {
					if(*buf == '/') { // command
						if(!strncmp(buf, "/quit", 5)) {
							goto quit;
						} else {
							fprintf(stderr, "unknown command: %s\n", buf);
						}
					} else {
						send_all(buf);
					}
				}
			}
		}
	}

quit:
	unlink(fname);
	return 0;
}
