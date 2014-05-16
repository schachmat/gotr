#include <stdio.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/un.h>

// where are we talking
#define ROOMDIR "/tmp/gotrusers/"

// variables
static char* nick;

// prototypes
int send_all(const char* message);
int send_user(const char* message, const char* user);
int main(int argc, char* argv[]);

// sends the message to all clients in the room
int
send_all(const char* message) {
	DIR *d;
	struct dirent *dir;
	
	d = opendir(ROOMDIR);
	
	if (d) {
		while ((dir = readdir(d)) != NULL) {
			if (dir->d_type == DT_SOCK) {
				printf("%s\n", dir->d_name);
			}
		}
		
		closedir(d);
	}
	
	
}

// sends the message to the user
int
send_user(const char* message, const char* user) {
	return 0;
}

int
main(int argc, char* argv[]) {
	struct sockaddr_un address;
	int socket_fd;
	int connection_fd;
	socklen_t address_length;

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
	
	return 0;
}
