#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

/* where are we talking */
#define ROOMDIR "/tmp/gotrusers/"
#define UNIX_PATH_MAX 104
#define BUFLEN 2048
#define USAGE "usage: client NICKNAME"

typedef struct sockaddr sockaddr;
typedef struct sockaddr_un sockaddr_un;
typedef struct timeval timeval;
typedef struct dirent dirent;

/* variables */
static char* nick;

/* prototypes */
static void die(const char *message);
static int send_all(const char* message);
static int send_user(const char* message, const char* user);
int main(int argc, char* argv[]);

static void
die(const char *message) {
	fprintf(stderr, "%s\n", message);
	exit(1);
}

/* sends the message to all clients in the room */
static int
send_all(const char* message) {
	DIR *directory;
	dirent *dir;
	int socket_fd;
	sockaddr_un address;

	if((socket_fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("send_all: socket() failed");
		return 1;
	}

	if(!(directory = opendir("."))) {
		perror("send_all: opendir(\".\") failed");
		return 1;
	}

	memset(&address, 0, sizeof(sockaddr_un));
	address.sun_family = AF_UNIX;

	while((dir = readdir(directory))) {
		strncpy(address.sun_path, dir->d_name, UNIX_PATH_MAX);
		if(dir->d_type != DT_SOCK || !strcmp(dir->d_name, nick)
		|| connect(socket_fd, (sockaddr*) &address, sizeof(sockaddr_un))) {
			continue;
		}
		printf("This is the name we write to: %s\n", dir->d_name);
		write(socket_fd, message, strlen(message));
		close(socket_fd);
	}

	closedir(directory);
	return 0;
}

/* sends the message to the user */
static int
send_user(const char* message, const char* user) {
	int socket_fd;
	sockaddr_un address;

	if((socket_fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("send_user: socket failed");
		return 1;
	}

	memset(&address, 0, sizeof(sockaddr_un));
	address.sun_family = AF_UNIX;
	strncpy(address.sun_path, user, UNIX_PATH_MAX);

	if(connect(socket_fd, (sockaddr *) &address, sizeof(sockaddr_un)) == -1) {
		perror("send_user: connect failed");
		close(socket_fd);
		return 1;
	}

	write(socket_fd, message, strlen(message));
	close(socket_fd);
	return 0;
}

int
main(int argc, char* argv[]) {
	struct stat finfo;
	timeval timeout = {1, 0};
	fd_set reads;
	sockaddr_un address;
	int socket_fd;
	char buf[BUFLEN];

	errno = 0;

	if(argc < 2) {
		die(USAGE);
	}
	printf("entering room as %s\n", nick = argv[1]);

	if((socket_fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("main: socket failed");
		return 1;
	}

	mkdir(ROOMDIR, 0755);
	chdir(ROOMDIR);
	if(!stat(nick, &finfo)) {
		close(socket_fd);
		die("main: Nickname already in use!");
	}
	unlink(nick);

	memset(&address, 0, sizeof(sockaddr_un));
	address.sun_family = AF_UNIX;
	strncpy(address.sun_path, nick, UNIX_PATH_MAX);

	if(bind(socket_fd, (sockaddr*)&address, sizeof(sockaddr_un)) == -1) {
		perror("main: bind() failed");
		goto fail;
	}

	if(listen(socket_fd, 10) == -1) {
		perror("main: listen() failed");
		goto fail;
	}

	while(1) {
		FD_ZERO(&reads);
		FD_SET(STDIN_FILENO, &reads);
/*		FD_SET(socket_fd, &reads); */
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		switch(select(socket_fd + 1, &reads, (fd_set*) 0, (fd_set*) 0, &timeout)) {
			default:
				if(FD_ISSET(socket_fd, &reads)) {
					fprintf(stderr, "we got a massage!\n");
				}
				if(FD_ISSET(STDIN_FILENO, &reads)) {
					if(fgets(buf, BUFLEN, stdin)) {
						if(buf[0] == '/') { /* command */
							if(!strncmp(buf, "/quit", 5)) {
								close(socket_fd);
								unlink(nick);
								return 0;
							} else {
								fprintf(stderr, "unknown command: %s\n", buf);
							}
						} else {
							send_all(buf);
						}
					}
				}
				break;
			case 0: /* timeout, do nothing */
				break;
			case -1:
				perror("main: select() failed");
				goto fail;
				break;
		}
	}

fail:
	close(socket_fd);
	unlink(nick);
	return 1;
}
