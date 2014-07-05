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

#include "gotr.h"

/* where are we talking */
#define ROOMDIR "/tmp/gotrusers/"
#define UNIX_PATH_MAX 104
#define BUFLEN 2048
#define USAGE "usage: client NICKNAME [KEYFILE]"

/* variables */
static char *nick;
int sock_fd;
static struct sockaddr_un receiver;

/* prototypes */
static void die(const char *message);
static int send_all(void *room_data, const char *message);
static int send_user(void *room_data, void *user_data, const char *message);
static void receive_user(void *room_data, void *user_data, const char *message);
int main(int argc, char* argv[]);

static void
die(const char *message)
{
	fprintf(stderr, "%s\n", message);
	exit(1);
}

/* sends the message to all clients in the room */
static int
send_all(void *room_data, const char *message)
{
	DIR *directory;
	struct dirent *dir;

	if (!(directory = opendir("."))) {
		perror("send_all: opendir(\".\") failed");
		return 0;
	}

	while ((dir = readdir(directory))) {
		strncpy(receiver.sun_path, dir->d_name, UNIX_PATH_MAX);
		if (!strcmp(dir->d_name, nick))
			continue;
		if (sendto(sock_fd, message, strlen(message), 0,
				(struct sockaddr *) &receiver, sizeof(struct sockaddr_un)) == -1
				&& errno != ECONNREFUSED && errno != ENOTSOCK)
			perror("client: sendto failed");
	}

	closedir(directory);
	return 1;
}

/* sends the message to the user */
static int
send_user(void *room_data, void *user_data, const char *message)
{
	strncpy(receiver.sun_path, (char *)user_data, UNIX_PATH_MAX);
	if (sendto(sock_fd, message, strlen(message), 0, (struct sockaddr *) &receiver,
			sizeof(struct sockaddr_un)) == -1) {
		perror("could not send message");
		return 0;
	}
	return 1;
}

/* displays message */
static void
receive_user(void *room_data, void *user_data, const char *message)
{
	fprintf(stderr, "%s: %s", (char *)user_data, message);
}

int
main(int argc, char *argv[])
{
	struct stat finfo;
	struct timeval timeout = {1, 0};
	fd_set reads;
	struct sockaddr_un address;
	struct sockaddr_un recv_address;
	socklen_t recv_address_len;
	char buf[BUFLEN];
	ssize_t buf_len;
	struct gotr_chatroom *room = NULL;

	errno = 0;

	if (argc < 2)
		die(USAGE);
	printf("entering room as %s\n", nick = argv[1]);

	if ((sock_fd = socket(PF_UNIX, SOCK_DGRAM, 0)) == -1) {
		perror("main: incoming socket() failed");
		return 1;
	}

	mkdir(ROOMDIR, 0755);
	chdir(ROOMDIR);
	if (!stat(nick, &finfo)) {
		close(sock_fd);
		die("main: Nickname already in use!");
	}
	unlink(nick);

	memset(&receiver, 0, sizeof(struct sockaddr_un));
	receiver.sun_family = AF_UNIX;

	memset(&address, 0, sizeof(struct sockaddr_un));
	address.sun_family = AF_UNIX;
	strncpy(address.sun_path, nick, UNIX_PATH_MAX);

	if (bind(sock_fd, (struct sockaddr *)&address, sizeof(struct sockaddr_un)) == -1) {
		perror("main: bind() failed");
		goto fail;
	}

	if (!gotr_init())
		goto fail;

	room = gotr_join(&send_all, &send_user, &receive_user, NULL, argc > 2 ? argv[2] : NULL);
	while (1) {
		FD_ZERO(&reads);
		FD_SET(STDIN_FILENO, &reads);
		FD_SET(sock_fd, &reads);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		switch(select(sock_fd + 1, &reads, (fd_set *) 0, (fd_set *) 0, &timeout)) {
		default:
			if (FD_ISSET(sock_fd, &reads)) {
				recv_address_len = sizeof(struct sockaddr);
				buf_len = recvfrom(sock_fd, buf, BUFLEN - 1, 0, (struct sockaddr *)&recv_address, &recv_address_len);
				buf[buf_len] = '\0';
				gotr_receive(room, buf);
				//fprintf(stderr, "nice massage from %s: %s", recv_address.sun_path, buf);
			}
			if (FD_ISSET(STDIN_FILENO, &reads)) {
				if (fgets(buf, BUFLEN, stdin)) {
					if (buf[0] == '/') { /* command */
						if (buf[1] == 'q') {
							close(sock_fd);
							unlink(nick);
							gotr_leave(room);
							room = NULL;
							return 0;
						} else {
							fprintf(stderr, "unknown command: %s", buf);
						}
					} else {
						gotr_send(room, buf);
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
	close(sock_fd);
	unlink(nick);
	gotr_leave(room);
	return 1;
}
