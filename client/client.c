#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>

// where are we talking
#define ROOMDIR "/tmp/gotrusers/"


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
	struct sockaddr_un address;
	int socket_fd;
	int connection_fd;
	socklen_t address_length;
	char* fname;

	if(argc < 2) {
		fprintf(stderr, "client nickname required");
		return 1;
	}

	nick = argv[1];
	printf("entering room as %s\n", nick);

	send_all("hi there, do you like cake?");

	socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(socket_fd < 0) {
		printf("socket() failed\n");
		return 1;
	}

	asprintf(&fname, "%s%s", ROOMDIR, nick);
	unlink(fname);

	return 0;
}
