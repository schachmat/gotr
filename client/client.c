#include <stdio.h>
#include <dirent.h>

// variables
static char* nick;

// prototypes
int send_all(const char* message);
int send_user(const char* message, const char* user);
int main(int argc, char* argv[]);

// sends the message to all clients in the room
int
send_all(const char* message)
{
	DIR *d;
	struct dirent *dir;
	
	d = opendir("/tmp/gotrusers/");
	
	if (d) {
		while ((dir = readdir(d)) != NULL) {
			if (dir->d_type == DT_SOCK) {
				printf("%s\n", dir->d_name);
			}
		}
		
		closedir(d);
	}
	
	
	
	return 0;
}

// sends the message to the user
int
send_user(const char* message, const char* user)
{
	return 0;
}

int
main(int argc, char* argv[])
{
	if(argc < 2) {
		fprintf(stderr, "client nickname required");
		return 1;
	}
		
	nick = argv[1];
	printf("nick: %s", nick);
	
	return 0;
}
