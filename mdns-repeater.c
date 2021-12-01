/*
 * mdns-repeater.c - mDNS repeater daemon
 * Copyright (C) 2011 Darell Tan
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>

#define PACKAGE "mdns-repeater"
#define MDNS_ADDR "224.0.0.251"
#define MDNS_PORT 5353

#ifndef PIDFILE
#define PIDFILE "/var/run/" PACKAGE ".pid"
#endif

#define MAX_SOCKS 16
#define MAX_SUBNETS 16

struct if_sock {
	const char *ifname;		/* interface name  */
	int sockfd;				/* socket filedesc */
	struct in_addr addr;	/* interface addr  */
	struct in_addr mask;	/* interface mask  */
	struct in_addr net;		/* interface network (computed) */
};

struct subnet {
	struct in_addr addr;    /* subnet addr */
	struct in_addr mask;    /* subnet mask */
	struct in_addr net;     /* subnet net (computed) */
};

int server_sockfd = -1;

int num_socks = 0;
struct if_sock socks[MAX_SOCKS];

int num_blacklisted_subnets = 0;
struct subnet blacklisted_subnets[MAX_SUBNETS];

int num_whitelisted_subnets = 0;
struct subnet whitelisted_subnets[MAX_SUBNETS];

#define PACKET_SIZE 65536
void *pkt_data = NULL;

int foreground = 0;
int shutdown_flag = 0;

char *pid_file = PIDFILE;

void log_message(int loglevel, char *fmt_str, ...) {
	va_list ap;
	char buf[2048];

	va_start(ap, fmt_str);
	vsnprintf(buf, 2047, fmt_str, ap);
	va_end(ap);
	buf[2047] = 0;

	if (foreground) {
		fprintf(stderr, "%s: %s\n", PACKAGE, buf);
	} else {
		syslog(loglevel, "%s", buf);
	}
}

static int create_recv_sock() {
	int sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
		log_message(LOG_ERR, "recv socket(): %s", strerror(errno));
		return sd;
	}

	int r = -1;

	int on = 1;
	if ((r = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0) {
		log_message(LOG_ERR, "recv setsockopt(SO_REUSEADDR): %s", strerror(errno));
		return r;
	}

	/* bind to an address */
	struct sockaddr_in serveraddr;
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(MDNS_PORT);
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);	/* receive multicast */
	if ((r = bind(sd, (struct sockaddr *)&serveraddr, sizeof(serveraddr))) < 0) {
		log_message(LOG_ERR, "recv bind(): %s", strerror(errno));
	}

	// enable loopback in case someone else needs the data
	if ((r = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, &on, sizeof(on))) < 0) {
		log_message(LOG_ERR, "recv setsockopt(IP_MULTICAST_LOOP): %s", strerror(errno));
		return r;
	}

#ifdef IP_PKTINFO
	if ((r = setsockopt(sd, SOL_IP, IP_PKTINFO, &on, sizeof(on))) < 0) {
		log_message(LOG_ERR, "recv setsockopt(IP_PKTINFO): %s", strerror(errno));
		return r;
	}
#endif

	return sd;
}

static int create_send_sock(int recv_sockfd, const char *ifname, struct if_sock *sockdata) {
	int sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
		log_message(LOG_ERR, "send socket(): %s", strerror(errno));
		return sd;
	}

	sockdata->ifname = ifname;
	sockdata->sockfd = sd;

	int r = -1;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	struct in_addr *if_addr = &((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;

#ifdef SO_BINDTODEVICE
	if ((r = setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(struct ifreq))) < 0) {
		log_message(LOG_ERR, "send setsockopt(SO_BINDTODEVICE): %s", strerror(errno));
		return r;
	}
#endif

	// get netmask
	if (ioctl(sd, SIOCGIFNETMASK, &ifr) == 0) {
		memcpy(&sockdata->mask, if_addr, sizeof(struct in_addr));
	}

	// .. and interface address
	if (ioctl(sd, SIOCGIFADDR, &ifr) == 0) {
		memcpy(&sockdata->addr, if_addr, sizeof(struct in_addr));
	}

	// compute network (address & mask)
	sockdata->net.s_addr = sockdata->addr.s_addr & sockdata->mask.s_addr;

	int on = 1;
	if ((r = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0) {
		log_message(LOG_ERR, "send setsockopt(SO_REUSEADDR): %s", strerror(errno));
		return r;
	}

	// bind to an address
	struct sockaddr_in serveraddr;
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(MDNS_PORT);
	serveraddr.sin_addr.s_addr = if_addr->s_addr;
	if ((r = bind(sd, (struct sockaddr *)&serveraddr, sizeof(serveraddr))) < 0) {
		log_message(LOG_ERR, "send bind(): %s", strerror(errno));
	}

#if __FreeBSD__
	if((r = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_IF, &serveraddr.sin_addr, sizeof(serveraddr.sin_addr))) < 0) {
		log_message(LOG_ERR, "send ip_multicast_if(): errno %d: %s", errno, strerror(errno));
	}
#endif

	// add membership to receiving socket
	struct ip_mreq mreq;
	memset(&mreq, 0, sizeof(struct ip_mreq));
	mreq.imr_interface.s_addr = if_addr->s_addr;
	mreq.imr_multiaddr.s_addr = inet_addr(MDNS_ADDR);
	if ((r = setsockopt(recv_sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) < 0) {
		log_message(LOG_ERR, "recv setsockopt(IP_ADD_MEMBERSHIP): %s", strerror(errno));
		return r;
	}

	// enable loopback in case someone else needs the data
	if ((r = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, &on, sizeof(on))) < 0) {
		log_message(LOG_ERR, "send setsockopt(IP_MULTICAST_LOOP): %s", strerror(errno));
		return r;
	}

    int ttl = 255; // IP TTL should be 255: https://datatracker.ietf.org/doc/html/rfc6762#section-11
    if ((r = setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl))) < 0) {
        log_message(LOG_ERR, "send setsockopt(IP_MULTICAST_TTL): %s", strerror(errno));
        return r;
    }

	char *addr_str = strdup(inet_ntoa(sockdata->addr));
	char *mask_str = strdup(inet_ntoa(sockdata->mask));
	char *net_str  = strdup(inet_ntoa(sockdata->net));
	log_message(LOG_INFO, "dev %s addr %s mask %s net %s", ifr.ifr_name, addr_str, mask_str, net_str);
	free(addr_str);
	free(mask_str);
	free(net_str);

	return sd;
}

static ssize_t send_packet(int fd, const void *data, size_t len) {
	static struct sockaddr_in toaddr;
	if (toaddr.sin_family != AF_INET) {
		memset(&toaddr, 0, sizeof(struct sockaddr_in));
		toaddr.sin_family = AF_INET;
		toaddr.sin_port = htons(MDNS_PORT);
		toaddr.sin_addr.s_addr = inet_addr(MDNS_ADDR);
	}

	return sendto(fd, data, len, 0, (struct sockaddr *) &toaddr, sizeof(struct sockaddr_in));
}

static void mdns_repeater_shutdown(int sig) {
	shutdown_flag = 1;
}

static pid_t already_running() {
	FILE *f;
	int count;
	pid_t pid;

	f = fopen(pid_file, "r");
	if (f != NULL) {
		count = fscanf(f, "%d", &pid);
		fclose(f);
		if (count == 1) {
			if (kill(pid, 0) == 0)
				return pid;
		}
	}

	return -1;
}

static int write_pidfile() {
	FILE *f;
	int r;

	f = fopen(pid_file, "w");
	if (f != NULL) {
		r = fprintf(f, "%d", getpid());
		fclose(f);
		return (r > 0);
	}

	return 0;
}

static void daemonize() {
	pid_t running_pid;
	pid_t pid = fork();
	if (pid < 0) {
		log_message(LOG_ERR, "fork(): %s", strerror(errno));
		exit(1);
	}

	// exit parent process
	if (pid > 0)
		exit(0);

	// signals
	signal(SIGCHLD, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGTERM, mdns_repeater_shutdown);

	setsid();
	umask(0027);
	chdir("/");

	// close all std fd and reopen /dev/null for them
	int i;
	for (i = 0; i < 3; i++) {
		close(i);
		if (open("/dev/null", O_RDWR) != i) {
			log_message(LOG_ERR, "unable to open /dev/null for fd %d", i);
			exit(1);
		}
	}

	// check for pid file
	running_pid = already_running();
	if (running_pid != -1) {
		log_message(LOG_ERR, "already running as pid %d", running_pid);
		exit(1);
	} else if (! write_pidfile()) {
		log_message(LOG_ERR, "unable to write pid file %s", pid_file);
		exit(1);
	}
}

static void show_help(const char *progname) {
	fprintf(stderr, "mDNS repeater (version " HGVERSION ")\n");
	fprintf(stderr, "Copyright (C) 2011 Darell Tan\n\n");

	fprintf(stderr, "usage: %s [ -f ] <ifdev> ...\n", progname);
	fprintf(stderr, "\n"
					"<ifdev> specifies an interface like \"eth0\"\n"
					"packets received on an interface is repeated across all other specified interfaces\n"
					"maximum number of interfaces is 5\n"
					"\n"
					" flags:\n"
					"	-f	runs in foreground for debugging\n"
					"	-b	blacklist subnet (eg. 192.168.1.1/24)\n"
					"	-w	whitelist subnet (eg. 192.168.1.1/24)\n"
					"	-p	specifies the pid file path (default: " PIDFILE ")\n"
					"	-h	shows this help\n"
					"\n"
		);
}

int parse(char *input, struct subnet *s) {
	int delim = 0;
	int end = 0;
	while (input[end] != 0) {
		if (input[end] == '/') {
			delim = end;
		}
		end++;
	}

	if (end == 0 || delim == 0 || end == delim) {
		return -1;
	}

	char *addr = (char*) malloc(end);

	memset(addr, 0, end);
	strncpy(addr, input, delim);
	if (inet_pton(AF_INET, addr, &s->addr) != 1) {
		free(addr);
		return -2;
	}

	memset(addr, 0, end);
	strncpy(addr, input+delim+1, end-delim-1);
	int mask = atoi(addr);
	free(addr);

	if (mask < 0 || mask > 32) {
		return -3;
	}

	s->mask.s_addr = ntohl((uint32_t)0xFFFFFFFF << (32 - mask));
	s->net.s_addr = s->addr.s_addr & s->mask.s_addr;

	return 0;
}

int tostring(struct subnet *s, char* buf, int len) {
	char *addr_str = strdup(inet_ntoa(s->addr));
	char *mask_str = strdup(inet_ntoa(s->mask));
	char *net_str = strdup(inet_ntoa(s->net));
	int l = snprintf(buf, len, "addr %s mask %s net %s", addr_str, mask_str, net_str);
	free(addr_str);
	free(mask_str);
	free(net_str);

	return l;
}

static int parse_opts(int argc, char *argv[]) {
	int c, res;
	int help = 0;
	struct subnet *ss;
	char *msg;
	while ((c = getopt(argc, argv, "hfp:b:w:")) != -1) {
		switch (c) {
			case 'h': help = 1; break;
			case 'f': foreground = 1; break;
			case 'p':
				if (optarg[0] != '/')
					log_message(LOG_ERR, "pid file path must be absolute");
				else
					pid_file = optarg;
				break;

			case 'b':
				if (num_blacklisted_subnets >= MAX_SUBNETS) {
					log_message(LOG_ERR, "too many blacklisted subnets (maximum is %d)", MAX_SUBNETS);
					exit(2);
				}

				if (num_whitelisted_subnets != 0) {
					log_message(LOG_ERR, "simultaneous whitelisting and blacklisting does not make sense");
					exit(2);
				}

				ss = &blacklisted_subnets[num_blacklisted_subnets];
				res = parse(optarg, ss);
				switch (res) {
					case -1:
						log_message(LOG_ERR, "invalid blacklist argument");
						exit(2);
					case -2:
						log_message(LOG_ERR, "could not parse netmask");
						exit(2);
					case -3:
						log_message(LOG_ERR, "invalid netmask");
						exit(2);
				}

				num_blacklisted_subnets++;

				msg = malloc(128);
				memset(msg, 0, 128);
				tostring(ss, msg, 128);
				log_message(LOG_INFO, "blacklist %s", msg);
				free(msg);
				break;
			case 'w':
				if (num_whitelisted_subnets >= MAX_SUBNETS) {
					log_message(LOG_ERR, "too many whitelisted subnets (maximum is %d)", MAX_SUBNETS);
					exit(2);
				}

				if (num_blacklisted_subnets != 0) {
					log_message(LOG_ERR, "simultaneous whitelisting and blacklisting does not make sense");
					exit(2);
				}

				ss = &whitelisted_subnets[num_whitelisted_subnets];
				res = parse(optarg, ss);
				switch (res) {
					case -1:
						log_message(LOG_ERR, "invalid whitelist argument");
						exit(2);
					case -2:
						log_message(LOG_ERR, "could not parse netmask");
						exit(2);
					case -3:
						log_message(LOG_ERR, "invalid netmask");
						exit(2);
				}

				num_whitelisted_subnets++;

				msg = malloc(128);
				memset(msg, 0, 128);
				tostring(ss, msg, 128);
				log_message(LOG_INFO, "whitelist %s", msg);
				free(msg);
				break;
			case '?':
			case ':':
				fputs("\n", stderr);
				break;

			default:
				log_message(LOG_ERR, "unknown option %c", optopt);
				exit(2);
		}
	}

	if (help) {
		show_help(argv[0]);
		exit(0);
	}

	return optind;
}

int main(int argc, char *argv[]) {
	pid_t running_pid;
	fd_set sockfd_set;
	int r = 0;

	parse_opts(argc, argv);

	if ((argc - optind) <= 1) {
		show_help(argv[0]);
		log_message(LOG_ERR, "error: at least 2 interfaces must be specified");
		exit(2);
	}

	openlog(PACKAGE, LOG_PID | LOG_CONS, LOG_DAEMON);
	if (! foreground)
		daemonize();
	else {
		// check for pid file when running in foreground
		running_pid = already_running();
		if (running_pid != -1) {
			log_message(LOG_ERR, "already running as pid %d", running_pid);
			exit(1);
		}
	}

	// create receiving socket
	server_sockfd = create_recv_sock();
	if (server_sockfd < 0) {
		log_message(LOG_ERR, "unable to create server socket");
		r = 1;
		goto end_main;
	}

	// create sending sockets
	int i;
	for (i = optind; i < argc; i++) {
		if (num_socks >= MAX_SOCKS) {
			log_message(LOG_ERR, "too many sockets (maximum is %d)", MAX_SOCKS);
			exit(2);
		}

		int sockfd = create_send_sock(server_sockfd, argv[i], &socks[num_socks]);
		if (sockfd < 0) {
			log_message(LOG_ERR, "unable to create socket for interface %s", argv[i]);
			r = 1;
			goto end_main;
		}
		num_socks++;
	}

	pkt_data = malloc(PACKET_SIZE);
	if (pkt_data == NULL) {
		log_message(LOG_ERR, "cannot malloc() packet buffer: %s", strerror(errno));
		r = 1;
		goto end_main;
	}

	while (! shutdown_flag) {
		struct timeval tv = {
			.tv_sec = 10,
			.tv_usec = 0,
		};

		FD_ZERO(&sockfd_set);
		FD_SET(server_sockfd, &sockfd_set);
		int numfd = select(server_sockfd + 1, &sockfd_set, NULL, NULL, &tv);
		if (numfd <= 0)
			continue;

		if (FD_ISSET(server_sockfd, &sockfd_set)) {
			struct sockaddr_in fromaddr;
			socklen_t sockaddr_size = sizeof(struct sockaddr_in);

			ssize_t recvsize = recvfrom(server_sockfd, pkt_data, PACKET_SIZE, 0,
				(struct sockaddr *) &fromaddr, &sockaddr_size);
			if (recvsize < 0) {
				log_message(LOG_ERR, "recv(): %s", strerror(errno));
			}

			int j;
			char self_generated_packet = 0;
			for (j = 0; j < num_socks; j++) {
				// check for loopback
				if (fromaddr.sin_addr.s_addr == socks[j].addr.s_addr) {
					self_generated_packet = 1;
					break;
				}
			}

			if (self_generated_packet)
				continue;

			if (num_whitelisted_subnets != 0) {
				char whitelisted_packet = 0;
				for (j = 0; j < num_whitelisted_subnets; j++) {
					// check for whitelist
					if ((fromaddr.sin_addr.s_addr & whitelisted_subnets[j].mask.s_addr) == whitelisted_subnets[j].net.s_addr) {
						whitelisted_packet = 1;
						break;
					}
				}

				if (!whitelisted_packet) {
					if (foreground)
						printf("skipping packet from=%s size=%zd\n", inet_ntoa(fromaddr.sin_addr), recvsize);
					continue;
				}
			} else {
				char blacklisted_packet = 0;
				for (j = 0; j < num_blacklisted_subnets; j++) {
					// check for blacklist
					if ((fromaddr.sin_addr.s_addr & blacklisted_subnets[j].mask.s_addr) == blacklisted_subnets[j].net.s_addr) {
						blacklisted_packet = 1;
						break;
					}
				}

				if (blacklisted_packet) {
					if (foreground)
						printf("skipping packet from=%s size=%zd\n", inet_ntoa(fromaddr.sin_addr), recvsize);
					continue;
				}
			}

			if (foreground)
				printf("data from=%s size=%zd\n", inet_ntoa(fromaddr.sin_addr), recvsize);

			for (j = 0; j < num_socks; j++) {
				// do not repeat packet back to the same network from which it originated
				if ((fromaddr.sin_addr.s_addr & socks[j].mask.s_addr) == socks[j].net.s_addr)
					continue;

				if (foreground)
					printf("repeating data to %s\n", socks[j].ifname);

				// repeat data
				ssize_t sentsize = send_packet(socks[j].sockfd, pkt_data, (size_t) recvsize);
				if (sentsize != recvsize) {
					if (sentsize < 0)
						log_message(LOG_ERR, "send(): %s", strerror(errno));
					else
						log_message(LOG_ERR, "send_packet size differs: sent=%zd actual=%zd",
							recvsize, sentsize);
				}
			}
		}
	}

	log_message(LOG_INFO, "shutting down...");

end_main:

	if (pkt_data != NULL)
		free(pkt_data);

	if (server_sockfd >= 0)
		close(server_sockfd);

	for (i = 0; i < num_socks; i++)
		close(socks[i].sockfd);

	// remove pid file if it belongs to us
	if (already_running() == getpid())
		unlink(pid_file);

	log_message(LOG_INFO, "exit.");

	return r;
}
