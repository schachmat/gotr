#include <dirent.h>
#include <errno.h>
#include <signal.h>
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

struct link {
	char *name;
	struct gotr_user *user;
	struct link *next;
	char online;
};

/* variables */
static char *nick;
static struct link *links;
static int sock_fd;
static struct sockaddr_un receiver;
static struct gotr_chatroom *room = NULL;

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

static int
for_all(void (*fn)(char* name, void* data), void* data)
{
	DIR *directory;
	struct dirent *dir;

	if (!(directory = opendir("."))) {
		perror("send_all: opendir(\".\") failed");
		return 0;
	}

	while ((dir = readdir(directory)) && fn)
		if (strcmp(dir->d_name, nick) &&
			strcmp(dir->d_name, "..") &&
			strcmp(dir->d_name, "."))
			fn(dir->d_name, (char *)data);

	closedir(directory);
	return 1;
}

static void
clean(char *name, void *unused)
{
	struct link *cur;

	for (cur = links; cur; cur = cur->next)
		if (!strcmp(cur->name, name)) {
			cur->online = 1;
			return;
		}
}

static void
clean_all()
{
	struct link *lnk;
	struct link *tmp;

	for (lnk = links; lnk; lnk = lnk->next)
		lnk->online = 0;

	for_all(&clean, NULL);

	lnk = links;
	while (links && !links->online) {
		printf("%s left\n", lnk->name);
		gotr_user_left(room, lnk->user);
		links = lnk->next;
		free(lnk->name);
		free(lnk);
	}

	for (lnk = links; lnk && lnk->next; lnk = lnk->next)
		if (!lnk->next->online) {
			tmp = lnk->next;
			printf("%s left\n", tmp->name);
			gotr_user_left(room, tmp->user);
			free(tmp->name);
			lnk->next = tmp->next;
			free(tmp);
		}
}

static void
join(char *name, void *unused)
{
	struct link *lnk;

	lnk = malloc(sizeof(struct link));
	lnk->name = malloc(strlen(name) + 1);
	strncpy(lnk->name, name, strlen(name) + 1);
	lnk->next = links;
	if ((lnk->user = gotr_user_joined(room, lnk->name))) {
		links = lnk;
	} else {
		free(lnk->name);
		free(lnk);
	}
}

static void
send_msg(char *name, void *message)
{
	strncpy(receiver.sun_path, name, UNIX_PATH_MAX);
	if (strcmp(name, nick) && sendto(sock_fd, (char *)message, strlen((char *)message), 0,
				(struct sockaddr *) &receiver, sizeof(struct sockaddr_un)) == -1
			&& errno != ECONNREFUSED && errno != ENOTSOCK)
		perror("client: sendto failed");
}

/* sends the message to all clients in the room */
static int
send_all(void *room_data, const char *message)
{
	char *nm;

	nm = malloc(strlen(message) + 2);
	snprintf(nm, strlen(message) + 2, "a%s", message);

	for_all(&send_msg, (void *)nm);

	free(nm);
	return 1;
}

/* sends the message to the user */
static int
send_user(void *room_data, void *user_data, const char *message)
{
	char *nm = malloc(strlen(message) + 2);
	snprintf(nm, strlen(message) + 2, "u%s", message);
	send_msg((char *)user_data, nm);
	free(nm);
	return 1;
}

/* displays message */
static void
receive_user(void *room_data, void *user_data, const char *message)
{
	printf("%s: %s", (char *)user_data, message);
}

static void
cleanup()
{
	close(sock_fd);
	unlink(nick);
	gotr_leave(room);
}

static void
handle_sig(int signum)
{
	cleanup();
}

static struct gotr_user *
derive_user(const char *name)
{
	struct link *cur = links;
	for (cur = links; cur; cur = cur->next)
		if (!strcmp(cur->name, name))
			return cur->user;
	return NULL;
}

int
main(int argc, char *argv[])
{
	struct link *lnk;
	struct gotr_user *new_user;
	struct stat finfo;
	struct timeval timeout = {1, 0};
	fd_set reads;
	struct sockaddr_un address;
	struct sockaddr_un recv_address;
	socklen_t recv_address_len;
	char buf[BUFLEN];
	ssize_t buf_len;

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

	signal(SIGINT, &handle_sig);
	signal(SIGABRT, &handle_sig);
	signal(SIGSEGV, &handle_sig);
	atexit(&cleanup);

	if (!gotr_init())
		goto fail;

	room = gotr_join(&send_all, &send_user, &receive_user, NULL, argc > 2 ? argv[2] : NULL);

	for_all(&join, NULL);

	while (1) {
		clean_all();

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
//				printf("got msg: %s\n", buf);
				if ('a' == buf[0]) {
					gotr_receive(room, buf+1);
				} else if ('u' == buf[0]) {
					new_user = derive_user(recv_address.sun_path);
					if (!new_user) {
						lnk = malloc(sizeof(struct link));
						lnk->name = malloc(strlen(recv_address.sun_path) + 1);
						strncpy(lnk->name, recv_address.sun_path, strlen(recv_address.sun_path) + 1);
						lnk->next = links;
						if ((lnk->user = gotr_receive_user(room, NULL, lnk->name, buf+1))) {
							links = lnk;
							printf("%s joined\n", lnk->name);
						} else {
							free(lnk->name);
							free(lnk);
						}
					} else {
						gotr_receive_user(room, new_user, recv_address.sun_path, buf+1);
					}
				}
				//fprintf(stderr, "nice massage from %s: %s", recv_address.sun_path, buf);
			}
			if (FD_ISSET(STDIN_FILENO, &reads)) {
				if (fgets(buf, BUFLEN, stdin)) {
					if (buf[0] == '/') { /* command */
						if (buf[1] == 'q') {
							cleanup();
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
