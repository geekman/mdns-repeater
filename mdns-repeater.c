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
#include <pwd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <errno.h>
#include <stdbool.h>
#include <poll.h>

#include "list.h"

#define PACKAGE "mdns-repeater"
#define MDNS_ADDR4 "224.0.0.251"
#define MDNS_ADDR6 "FF02::FB"
static const struct in6_addr mdns_addr_in6 = { .s6_addr = {
	0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb,
}};
#define MDNS_PORT 5353

#ifndef PIDFILE
#define PIDFILE "/var/run/" PACKAGE ".pid"
#endif

#define MIN(a, b) ((a) < (b) ? (a) : (b))

struct _in6_pktinfo {
	struct in6_addr ipi6_addr;    /* src/dst IPv6 address */
	unsigned int    ipi6_ifindex; /* send/recv interface index */
};

union sockaddr_u {
	struct sockaddr_storage ss;		/* socket addr		*/
	struct sockaddr_in6 sin6;		/* socket addr (IPv6)	*/
	struct sockaddr_in sin;			/* socket addr (IPv4)	*/
};

union in_addr_u {
	struct in6_addr in6;			/* address (IPv6)	*/
	struct in_addr in;			/* address (IPv4)	*/
};

struct addr_mask {
	union sockaddr_u addr;			/* socket addr		*/
	union in_addr_u mask;			/* socket mask		*/
	union in_addr_u net;			/* socket net		*/
	struct list_head list;			/* addr_mask list	*/
};
LIST_HEAD(blacklisted_subnets);
LIST_HEAD(whitelisted_subnets);

struct send_sock6 {
	const char *ifname;			/* interface name	*/
	unsigned ifindex;			/* interface index	*/
	int sockfd;				/* socket fd		*/
	struct list_head ams;			/* socket addr/mask/nets*/
	struct list_head list;			/* socket list		*/
};
LIST_HEAD(send_socks6);

struct send_sock4 {
	const char *ifname;			/* interface name	*/
	int sockfd;				/* socket fd		*/
	struct addr_mask am;			/* socket addr/mask/net	*/
	struct list_head list;			/* socket list		*/
};
LIST_HEAD(send_socks4);

#define PACKET_SIZE 65536
struct recv_sock {
	const char *name;			/* name of this socket  */
	int sockfd;				/* socket fd            */
	char pkt_data[PACKET_SIZE];		/* incoming packet data */
	ssize_t pkt_size;			/* incoming packet len	*/
	union sockaddr_u addr;			/* socket addr		*/
	union sockaddr_u from;			/* sender addr		*/
	char from_str[INET6_ADDRSTRLEN];	/* sender addr (str)	*/
	struct list_head list;			/* socket list          */
};
LIST_HEAD(recv_socks);

bool foreground = false;

int signal_pipe_fds[2];
#define PIPE_RD 0
#define PIPE_WR 1

char *pid_file = PIDFILE;

const struct passwd* user = NULL;

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

static char *
addr6_mask_to_string(struct sockaddr_in6 *addr,
		     struct in6_addr *mask,
		     struct in6_addr *net) {
	const char *fmt = "addr %s mask %s net %s";
	/* sizeof(fmt) = some extra bytes, and it's compile-time constant */
	static char msg[sizeof(fmt) + 3 * INET6_ADDRSTRLEN];
	char addrbuf[INET6_ADDRSTRLEN];
	char maskbuf[INET6_ADDRSTRLEN];
	char netbuf[INET6_ADDRSTRLEN];

	snprintf(msg, sizeof(msg), fmt,
		 inet_ntop(AF_INET6, &addr->sin6_addr,
			   addrbuf, sizeof(addrbuf)),
		 inet_ntop(AF_INET6, mask, maskbuf, sizeof(maskbuf)),
		 inet_ntop(AF_INET6, net, netbuf, sizeof(netbuf)));

	return msg;
}

static char *
addr4_mask_to_string(struct sockaddr_in *addr,
		     struct in_addr *mask,
		     struct in_addr *net) {
	const char *fmt = "addr %s mask %s net %s";
	/* sizeof(fmt) = some extra bytes, and it's compile-time constant */
	static char msg[sizeof(fmt) + 3 * INET_ADDRSTRLEN];
	char addrbuf[INET_ADDRSTRLEN];
	char maskbuf[INET_ADDRSTRLEN];
	char netbuf[INET_ADDRSTRLEN];

	snprintf(msg, sizeof(msg), fmt,
		 inet_ntop(AF_INET, &addr->sin_addr,
			   addrbuf, sizeof(addrbuf)),
		 inet_ntop(AF_INET, mask, maskbuf, sizeof(maskbuf)),
		 inet_ntop(AF_INET, net, netbuf, sizeof(netbuf)));

	return msg;
}

static char *
addr_mask_to_string(struct addr_mask *nm)
{
	switch (nm->addr.ss.ss_family) {
	case AF_INET6:
		return addr6_mask_to_string(&nm->addr.sin6,
					    &nm->mask.in6,
					    &nm->net.in6);
	case AF_INET:
		return addr4_mask_to_string(&nm->addr.sin,
					    &nm->mask.in,
					    &nm->net.in);
	default:
		return "ERROR";
	}
}

static struct recv_sock *
create_recv_sock6() {
	struct recv_sock *sock;
	int sd;
	int on = 1;

	sock = malloc(sizeof(*sock));
	if (!sock) {
		log_message(LOG_ERR, "malloc(): %s", strerror(errno));
		goto out;
	}

	sd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sd < 0) {
		log_message(LOG_ERR, "recv socket6(): %s", strerror(errno));
		goto out;
	}
	sock->sockfd = sd;

	// make sure that the socket uses only IPv6
	if (setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0) {
		log_message(LOG_ERR, "send setsockopt(IPV6_V6ONLY): %s", strerror(errno));
		goto out;
	}

	// make sure that the address can be used by other applications
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		log_message(LOG_ERR, "recv setsockopt6(SO_REUSEADDR): %s", strerror(errno));
		goto out;
	}

	// enable loopback in case someone else needs the data
	if (setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &on, sizeof(on)) < 0) {
		log_message(LOG_ERR, "recv setsockopt(IPV6_MULTICAST_LOOP): %s", strerror(errno));
		goto out;
	}

	// provides info on which interface a packet arrived via
	if (setsockopt(sd, IPPROTO_IPV6, IPV6_RECVPKTINFO,  &on, sizeof(on)) < 0) {
		log_message(LOG_ERR, "recv setsockopt(IPV6_RECVPKTINFO): %s", strerror(errno));
		goto out;
	}

	// bind to an address
	memset(&sock->addr, 0, sizeof(sock->addr));
	sock->addr.sin6.sin6_family = AF_INET6;
	sock->addr.sin6.sin6_port = htons(MDNS_PORT);
	sock->addr.sin6.sin6_addr = in6addr_any;
	if (bind(sd, (struct sockaddr *)&sock->addr.sin6, sizeof(sock->addr.sin6)) < 0) {
		log_message(LOG_ERR, "recv bind6(): %s", strerror(errno));
		goto out;
	}

	return sock;

out:
	free(sock);
	return NULL;
}

static struct recv_sock *
create_recv_sock4() {
	struct recv_sock *sock;
	int sd;
	int on = 1;

	sock = malloc(sizeof(*sock));
	if (!sock) {
		log_message(LOG_ERR, "malloc(): %s", strerror(errno));
		goto out;
	}

	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
		log_message(LOG_ERR, "recv socket(): %s", strerror(errno));
		goto out;
	}
	sock->sockfd = sd;

	// make sure that the address can be used by other applications
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		log_message(LOG_ERR, "recv setsockopt(SO_REUSEADDR): %s", strerror(errno));
		goto out;
	}

	// bind to an address
	memset(&sock->addr, 0, sizeof(sock->addr));
	sock->addr.sin.sin_family = AF_INET;
	sock->addr.sin.sin_port = htons(MDNS_PORT);
	sock->addr.sin.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sd, (struct sockaddr *)&sock->addr.sin, sizeof(sock->addr.sin)) < 0) {
		log_message(LOG_ERR, "recv bind(): %s", strerror(errno));
		goto out;
	}

	// enable loopback in case someone else needs the data
	if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, &on, sizeof(on)) < 0) {
		log_message(LOG_ERR, "recv setsockopt(IP_MULTICAST_LOOP): %s", strerror(errno));
		goto out;
	}

#ifdef IP_PKTINFO
	if (setsockopt(sd, SOL_IP, IP_PKTINFO, &on, sizeof(on)) < 0) {
		log_message(LOG_ERR, "recv setsockopt(IP_PKTINFO): %s", strerror(errno));
		goto out;
	}
#endif

	return sock;

out:
	free(sock);
	return NULL;
}

static struct send_sock6 *
create_send_sock6(const char *ifname, struct list_head *recv_socks) {
	struct send_sock6 *sock = NULL;
	struct addr_mask *am, *tmp_am;
	int sd = -1;
	int ifindex;
	int on = 1;
	int ttl = 255; // https://datatracker.ietf.org/doc/html/rfc6762#section-11
	struct ipv6_mreq mreq6;
	struct recv_sock *recv_sock;
	struct ifaddrs *ifa, *ifap = NULL;
	struct sockaddr_in6 *bindaddr = NULL;

	ifindex = if_nametoindex (ifname);
	if (ifindex < 1) {
		log_message(LOG_ERR, "if_nametoindex(%s): %s", ifname, strerror(errno));
		goto out;
	}

	sock = malloc(sizeof(*sock));
	if (!sock) {
		log_message(LOG_ERR, "malloc(): %s", strerror(errno));
		goto out;
	}
	memset(sock, 0, sizeof(*sock));
	INIT_LIST_HEAD(&sock->ams);
	sock->ifname = ifname;
	sock->ifindex = ifindex;

	if (getifaddrs(&ifap) < 0) {
		log_message(LOG_ERR, "getifaddrs(): %s", strerror(errno));
		goto out;
	}

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr)
			continue;
		else if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		else if (!ifa->ifa_netmask)
			continue;
		else if (strcmp(ifa->ifa_name, ifname))
			continue;

		am = malloc(sizeof(*am));
		if (!am) {
			log_message(LOG_ERR, "malloc(): %s", strerror(errno));
			goto out;
		}
		memset(am, 0, sizeof(*am));

		am->addr.ss.ss_family = AF_INET6;
		am->addr.sin6.sin6_port = htons(MDNS_PORT);
		am->addr.sin6.sin6_addr = ((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
		am->addr.sin6.sin6_scope_id = ifindex;
		am->mask.in6 = ((struct sockaddr_in6 *)ifa->ifa_netmask)->sin6_addr;
		for (int i = 0; i < sizeof(am->net.in6.s6_addr); i++)
		     am->net.in6.s6_addr[i] = am->addr.sin6.sin6_addr.s6_addr[i] &
					      am->mask.in6.s6_addr[i];
		list_add(&am->list, &sock->ams);

		if (IN6_IS_ADDR_LINKLOCAL(&am->addr.sin6.sin6_addr))
			bindaddr = &am->addr.sin6;
	}

	if (!bindaddr) {
		log_message(LOG_ERR, "no IPv6 link-local address for dev %s", ifname);
		goto out;
	}

	sd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sd < 0) {
		log_message(LOG_ERR, "send socket6(): %s", strerror(errno));
		goto out;
	}
	sock->sockfd = sd;

	// make sure that the socket uses only IPv6
	if (setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0) {
		log_message(LOG_ERR, "send setsockopt(IPV6_V6ONLY): %s", strerror(errno));
		goto out;
	}

	// make sure that the address can be used by other applications
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		log_message(LOG_ERR, "send setsockopt6(SO_REUSEADDR): %s", strerror(errno));
		goto out;
	}

	// bind to the address
	if (bind(sd, (struct sockaddr *)bindaddr, sizeof(*bindaddr)) < 0) {
		log_message(LOG_ERR, "send bind6(): %s %i %i", strerror(errno), errno, EINVAL);
		goto out;
	}

	// bind to the device
	if (setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) < 0) {
		log_message(LOG_ERR, "send setsockopt(IPV6_MULTICAST_IF): %s", strerror(errno));
		goto out;
	}

	// enable loopback in case someone else needs the data
	if (setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &on, sizeof(on)) < 0) {
		log_message(LOG_ERR, "send setsockopt(IPV6_MULTICAST_LOOP): %s", strerror(errno));
		goto out;
	}

	// set the TTL per RFC6762
	if (setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl)) < 0) {
		log_message(LOG_ERR, "send setsockopt(IPV6_MULTICAST_HOPS): %s", strerror(errno));
		goto out;
	}

	// add membership to receiving sockets
	memset(&mreq6, 0, sizeof(mreq6));
	inet_pton(AF_INET6, MDNS_ADDR6, &mreq6.ipv6mr_multiaddr.s6_addr);
	mreq6.ipv6mr_interface = ifindex;

	list_for_each_entry(recv_sock, recv_socks, list) {
		if (recv_sock->addr.ss.ss_family != AF_INET6)
			continue;

		if (setsockopt(recv_sock->sockfd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
			       &mreq6, sizeof(mreq6)) < 0) {
			log_message(LOG_ERR, "recv setsockopt(IPV6_ADD_MEMBERSHIP): %s", strerror(errno));
			goto out;
		}
	}

	list_for_each_entry(am, &sock->ams, list)
		log_message(LOG_INFO, "dev %s %s", sock->ifname, addr_mask_to_string(am));

	freeifaddrs(ifap);
	return sock;

out:
	if (sock) {
		list_for_each_entry_safe(am, tmp_am, &sock->ams, list) {
			list_del(&am->list);
			free(am);
		}
		free(sock);
	}
	close(sd);
	freeifaddrs(ifap);
	return NULL;
}

static struct send_sock4 *
create_send_sock4(const char *ifname, struct list_head *recv_socks) {
	struct send_sock4 *sock;
	int sd = -1;
	struct ifreq ifr;
	struct in_addr *if_addr = &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
	int on = 1;
	int ttl = 255; // https://datatracker.ietf.org/doc/html/rfc6762#section-11
	struct ip_mreq mreq;
	struct recv_sock *recv_sock;

	sock = malloc(sizeof(*sock));
	if (!sock) {
		log_message(LOG_ERR, "malloc(): %s", strerror(errno));
		goto out;
	}
	memset(sock, 0, sizeof(*sock));
	sock->ifname = ifname;

	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
		log_message(LOG_ERR, "send socket4(): %s", strerror(errno));
		goto out;
	}
	sock->sockfd = sd;

	// get netmask
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(sd, SIOCGIFNETMASK, &ifr) < 0) {
		log_message(LOG_ERR, "ioctl(SIOCGIFNETMASK): %s", strerror(errno));
		goto out;
	}
	memcpy(&sock->am.mask.in, if_addr, sizeof(*if_addr));

	// ...and interface address
	if (ioctl(sd, SIOCGIFADDR, &ifr) < 0) {
		log_message(LOG_ERR, "ioctl(SIOCGIFADDR): %s", strerror(errno));
		goto out;
	}
	memcpy(&sock->am.addr.sin.sin_addr, if_addr, sizeof(*if_addr));
	sock->am.addr.ss.ss_family = AF_INET;
	sock->am.addr.sin.sin_port = htons(MDNS_PORT);

	// ...then compute the network
	sock->am.net.in.s_addr = sock->am.addr.sin.sin_addr.s_addr & sock->am.mask.in.s_addr;

	// make sure that the address can be used by other applications
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		log_message(LOG_ERR, "send setsockopt4(SO_REUSEADDR): %s", strerror(errno));
		goto out;
	}

	// bind to the address
	if (bind(sd, (struct sockaddr *)&sock->am.addr.sin, sizeof(sock->am.addr.sin)) < 0) {
		log_message(LOG_ERR, "send bind4(): %s", strerror(errno));
		goto out;
	}

	// bind to the device
	if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_IF, &sock->am.addr.sin.sin_addr, sizeof(sock->am.addr.sin)) < 0) {
		log_message(LOG_ERR, "send setsockopt(IP_MULTICAST_IF): %s", strerror(errno));
		goto out;
	}

	// enable loopback in case someone else needs the data
	if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, &on, sizeof(on)) < 0) {
		log_message(LOG_ERR, "send setsockopt(IP_MULTICAST_LOOP): %s", strerror(errno));
		goto out;
	}

	// set the TTL per RFC6762
	if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
		log_message(LOG_ERR, "send setsockopt(IP_MULTICAST_TTL): %s", strerror(errno));
		goto out;
	}

	// add membership to receiving sockets
	memset(&mreq, 0, sizeof(mreq));
	mreq.imr_interface.s_addr = if_addr->s_addr;
	mreq.imr_multiaddr.s_addr = inet_addr(MDNS_ADDR4);

	list_for_each_entry(recv_sock, recv_socks, list) {
		if (recv_sock->addr.ss.ss_family != AF_INET)
			continue;

		if (setsockopt(recv_sock->sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
			       &mreq, sizeof(mreq)) < 0) {
			log_message(LOG_ERR, "recv setsockopt(IP_ADD_MEMBERSHIP): %s", strerror(errno));
			goto out;
		}
	}

	log_message(LOG_INFO, "dev %s %s", sock->ifname, addr_mask_to_string(&sock->am));
	return sock;

out:
	free(sock);
	close(sd);
	return NULL;
}

static ssize_t
send_packet6(int fd, const char *data, size_t len) {
	static struct sockaddr_in6 toaddr6;

	if (toaddr6.sin6_family != AF_INET6) {
		toaddr6.sin6_family = AF_INET6;
		toaddr6.sin6_port = htons(MDNS_PORT);
		toaddr6.sin6_addr = mdns_addr_in6;
	}
	return sendto(fd, data, len, 0, (struct sockaddr *)&toaddr6, sizeof(toaddr6));
}

static ssize_t
send_packet4(int fd, const char *data, size_t len) {
	static struct sockaddr_in toaddr4;

	if (toaddr4.sin_family != AF_INET) {
		toaddr4.sin_family = AF_INET;
		toaddr4.sin_port = htons(MDNS_PORT);
		toaddr4.sin_addr.s_addr = inet_addr(MDNS_ADDR4);
	}
	return sendto(fd, data, len, 0, (struct sockaddr *)&toaddr4, sizeof(toaddr4));
}

static void
signal_shutdown(int sig) {
	write(signal_pipe_fds[PIPE_WR], &sig, 1);
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
	signal(SIGTERM, signal_shutdown);

	setsid();
	umask(0027);
	if (chdir("/") < 0) {
		log_message(LOG_ERR, "unable to change to root directory");
		exit(1);
	}

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

static void switch_user() {
	errno = 0;
	if (setgid(user->pw_gid) != 0) {
		log_message(LOG_ERR, "Failed to switch to group %d - %s", user->pw_gid, strerror(errno));
		exit(2);
	} else if (setuid(user->pw_uid) != 0) {
		log_message(LOG_ERR, "Failed to switch to user %s (%d) - %s", user->pw_name, user->pw_uid, strerror(errno));
		exit(2);
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
					"	-u	run as this user (by name)\n"
					"	-h	shows this help\n"
					"\n"
		);
}

/*
 * Expected input, strings of the form:
 *   192.168.0.12/24
 *   2001:db8::/32
 */
static struct addr_mask *
parse_subnet(const char *input) {
	struct addr_mask *subnet;
	char *addr_str = NULL;
	char *delim;
	struct in6_addr *addr_in6;
	struct in_addr *addr_in;
	int prefix_len;

	subnet = malloc(sizeof(*subnet));
	if (!subnet) {
		log_message(LOG_ERR, "malloc(): %s", strerror(errno));
		goto out;
	}
	memset(subnet, 0, sizeof(*subnet));

	addr_str = strdup(input);
	if (!addr_str) {
		log_message(LOG_ERR, "strdup(): %s", strerror(errno));
		goto out;
	}

	delim = strchr(addr_str, '/');
	if (!delim) {
		log_message(LOG_ERR, "invalid blacklist/whitelist argument: %s", input);
		goto out;
	}

	*delim = '\0';
	delim++;
	prefix_len = atoi(delim);
	if (prefix_len < 0) {
		log_message(LOG_ERR, "invalid blacklist/whitelist prefix length: %s", input);
		goto out;
	}

	addr_in6 = &subnet->addr.sin6.sin6_addr;
	addr_in = &subnet->addr.sin.sin_addr;

	// First, try parsing an IPv6 address
	if (inet_pton(AF_INET6, addr_str, addr_in6) == 1) {
		if (prefix_len > 128) {
			log_message(LOG_ERR, "blacklist/whitelist prefix length > 128: %s", input);
			goto out;
		}

		for (int i = 0; i < sizeof(addr_in6->s6_addr); i++) {
			uint8_t mask = 0xff << (8 - MIN(prefix_len, 8));
			prefix_len -= MIN(prefix_len, 8);
			subnet->mask.in6.s6_addr[i] = mask;
			subnet->net.in6.s6_addr[i] = addr_in6->s6_addr[i] & mask;
		}

		subnet->addr.ss.ss_family = AF_INET6;

	// Second, try parsing an IPv4 address
	} else if (inet_pton(AF_INET, addr_str, addr_in) == 1) {
		if (prefix_len > 32) {
			log_message(LOG_ERR, "blacklist/whitelist prefix length > 32: %s", input);
			goto out;
		}

		subnet->mask.in.s_addr = ntohl(0xFFFFFFFF << (32 - prefix_len));
		subnet->net.in.s_addr = addr_in->s_addr & subnet->mask.in.s_addr;
		subnet->addr.ss.ss_family = AF_INET;

	// Give up
	} else {
		log_message(LOG_ERR, "could not parse blacklist/whitelist netmask: %s", input);
		goto out;
	}

	free(addr_str);
	return subnet;

out:
	free(addr_str);
	free(subnet);
	return NULL;
}

static bool
subnet_match6(struct sockaddr_in6 *from, struct list_head *subnets)
{
	struct addr_mask *subnet;

	list_for_each_entry(subnet, subnets, list) {
		if (subnet->addr.ss.ss_family != AF_INET6)
			continue;

		for (int i = 0; i < sizeof(from->sin6_addr); i++)
			if ((from->sin6_addr.s6_addr[i] & subnet->mask.in6.s6_addr[i]) != subnet->net.in6.s6_addr[i])
				continue;

		return true;
	}

	return false;
}

static bool
subnet_match4(struct sockaddr_in *from, struct list_head *subnets)
{
	struct addr_mask *subnet;

	list_for_each_entry(subnet, subnets, list) {
		if (subnet->addr.ss.ss_family != AF_INET)
			continue;

		if ((from->sin_addr.s_addr & subnet->mask.in.s_addr) == subnet->net.in.s_addr)
			return true;
	}

	return false;
}

static int parse_opts(int argc, char *argv[]) {
	int c;
	bool help = false;
	struct addr_mask *subnet;

	while ((c = getopt(argc, argv, "hfp:b:w:u:")) != -1) {
		switch (c) {
			case 'h':
				help = true;
				break;

			case 'f':
				foreground = true;
				break;

			case 'p':
				if (optarg[0] != '/')
					log_message(LOG_ERR, "pid file path must be absolute");
				else
					pid_file = optarg;
				break;

			case 'b':
				subnet = parse_subnet(optarg);
				if (!subnet)
					exit(2);
				list_add(&subnet->list, &blacklisted_subnets);
				log_message(LOG_INFO, "blacklist %s", addr_mask_to_string(subnet));
				break;

			case 'w':
				subnet = parse_subnet(optarg);
				if (!subnet)
					exit(2);
				list_add(&subnet->list, &whitelisted_subnets);
				log_message(LOG_INFO, "whitelist %s", addr_mask_to_string(subnet));
				break;

			case '?':
			case ':':
				fputs("\n", stderr);
				break;

			case 'u': {
				if ((user = getpwnam(optarg)) == NULL) {
					log_message(LOG_ERR, "No such user '%s'", optarg);
					exit(2);
				}
				break;
			}

			default:
				log_message(LOG_ERR, "unknown option %c", optopt);
				exit(2);
		}
	}

	if (!list_empty(&whitelisted_subnets) && !list_empty(&blacklisted_subnets)) {
		log_message(LOG_ERR, "simultaneous whitelisting and blacklisting does not make sense");
		exit(2);
	}

	if (help) {
		show_help(argv[0]);
		exit(0);
	}

	return optind;
}

static void
repeat_packet6(struct recv_sock *recv_sock, unsigned ifindex)
{
	struct send_sock6 *send_sock;
	struct addr_mask *am;
	ssize_t sentsize;

	list_for_each_entry(send_sock, &send_socks6, list) {
		list_for_each_entry(am, &send_sock->ams, list) {
			if (IN6_ARE_ADDR_EQUAL(&recv_sock->from.sin6.sin6_addr,
					       &am->addr.sin6.sin6_addr)) {
				if (foreground)
					printf("skipping packet from=%s size=%zd (ourself)\n",
					       recv_sock->from_str, recv_sock->pkt_size);
				return;
			}
		}
	}

	if (!list_empty(&whitelisted_subnets) &&
	    !subnet_match6(&recv_sock->from.sin6, &whitelisted_subnets)) {
		if (foreground)
			printf("skipping packet from=%s size=%zd (not whitelisted)\n",
			       recv_sock->from_str, recv_sock->pkt_size);
		return;
	}

	if (subnet_match6(&recv_sock->from.sin6, &blacklisted_subnets)) {
		if (foreground)
			printf("skipping packet from=%s size=%zd (blacklisted)\n",
			       recv_sock->from_str, recv_sock->pkt_size);
		return;
	}

	if (foreground)
		printf("got v6 packet from=%s size=%zd\n", recv_sock->from_str, recv_sock->pkt_size);

	list_for_each_entry(send_sock, &send_socks6, list) {
		// do not repeat packet back to the same interface from which it originated
		if (send_sock->ifindex == ifindex)
			continue;

		if (foreground)
			printf("repeating data to %s\n", send_sock->ifname);

		// repeat data
		sentsize = send_packet6(send_sock->sockfd, recv_sock->pkt_data, recv_sock->pkt_size);
		if (sentsize < 0)
			log_message(LOG_ERR, "send6(): %s", strerror(errno));
		else if (sentsize != recv_sock->pkt_size)
			log_message(LOG_ERR, "send_packet6 size differs: sent=%zd actual=%zd",
				    recv_sock->pkt_size, sentsize);
	}
}

static void
repeat_packet4(struct recv_sock *recv_sock) {
	struct send_sock4 *send_sock;
	bool our_net = false;
	ssize_t sentsize;

	list_for_each_entry(send_sock, &send_socks4, list) {
		// make sure packet originated from specified networks
		if ((recv_sock->from.sin.sin_addr.s_addr & send_sock->am.mask.in.s_addr) == send_sock->am.net.in.s_addr) {
			our_net = true;
		}

		// check for loopback
		if (recv_sock->from.sin.sin_addr.s_addr == send_sock->am.addr.sin.sin_addr.s_addr)
			return;
	}

	if (!our_net)
		return;

	if (!list_empty(&whitelisted_subnets) &&
	    !subnet_match4(&recv_sock->from.sin, &whitelisted_subnets)) {
		if (foreground)
			printf("skipping packet from=%s size=%zd (not whitelisted)\n",
			       recv_sock->from_str, recv_sock->pkt_size);
		return;
	}

	if (subnet_match4(&recv_sock->from.sin, &blacklisted_subnets)) {
		if (foreground)
			printf("skipping packet from=%s size=%zd (blacklisted)\n",
			       recv_sock->from_str, recv_sock->pkt_size);
		return;
	}

	if (foreground)
		printf("got v4 packet from=%s size=%zd\n", recv_sock->from_str, recv_sock->pkt_size);

	list_for_each_entry(send_sock, &send_socks4, list) {
		// do not repeat packet back to the same network from which it originated
		if ((recv_sock->from.sin.sin_addr.s_addr & send_sock->am.mask.in.s_addr) == send_sock->am.net.in.s_addr)
			continue;

		if (foreground)
			printf("repeating data to %s\n", send_sock->ifname);

		// repeat data
		sentsize = send_packet4(send_sock->sockfd, recv_sock->pkt_data, recv_sock->pkt_size);
		if (sentsize < 0)
			log_message(LOG_ERR, "send4(): %s", strerror(errno));
		else if (sentsize != recv_sock->pkt_size)
			log_message(LOG_ERR, "send_packet4 size differs: sent=%zd actual=%zd",
				    recv_sock->pkt_size, sentsize);
	}
}

static void
recv_packet6(struct recv_sock *recv_sock)
{
	uint8_t cmsgbuf[1024];
	struct iovec iov[] = {
		{
			.iov_base = &recv_sock->pkt_data,
			.iov_len = sizeof(recv_sock->pkt_data),
		}
	};
	struct msghdr msg = {
		.msg_name = &recv_sock->from,
		.msg_namelen = sizeof(recv_sock->from),
		.msg_iov = iov,
		.msg_iovlen = 1,
		.msg_control = cmsgbuf,
		.msg_controllen = sizeof(cmsgbuf),
		.msg_flags = 0,
	};
	struct cmsghdr *chdr;
	struct _in6_pktinfo *pktinfo = NULL;

	recv_sock->pkt_size = recvmsg(recv_sock->sockfd, &msg, 0);
	if (recv_sock->pkt_size < 0)
		return;
	else if (msg.msg_flags & MSG_TRUNC)
		return;
	else if (msg.msg_flags & MSG_CTRUNC)
		return;

	for (chdr = CMSG_FIRSTHDR(&msg); chdr; chdr = CMSG_NXTHDR(&msg, chdr)) {
		if (chdr->cmsg_level != IPPROTO_IPV6)
			continue;

		if (chdr->cmsg_type != IPV6_PKTINFO)
			continue;

		pktinfo = (struct _in6_pktinfo *)CMSG_DATA(chdr);
		if (!IN6_ARE_ADDR_EQUAL(&pktinfo->ipi6_addr, &mdns_addr_in6))
			pktinfo = NULL;

		break;
        }

	if (!pktinfo)
		return;

	if (!inet_ntop(AF_INET6,
		       &recv_sock->from.sin6.sin6_addr,
		       recv_sock->from_str,
		       sizeof(recv_sock->from_str)))
		recv_sock->from_str[0] = '\0';
	repeat_packet6(recv_sock, pktinfo->ipi6_ifindex);
}

static void
recv_packet4(struct recv_sock *recv_sock)
{
	socklen_t sockaddr_size = sizeof(recv_sock->from);

	recv_sock->pkt_size = recvfrom(recv_sock->sockfd,
				       recv_sock->pkt_data,
				       sizeof(recv_sock->pkt_data), 0,
				       (struct sockaddr *)&recv_sock->from,
				       &sockaddr_size);
	if (recv_sock->pkt_size < 0)
		return;

	if (!inet_ntop(AF_INET,
		       &recv_sock->from.sin.sin_addr,
		       recv_sock->from_str,
		       sizeof(recv_sock->from_str)))
		recv_sock->from_str[0] = '\0';
	repeat_packet4(recv_sock);
}

static void
recv_packet(struct recv_sock *recv_sock)
{
	switch (recv_sock->addr.ss.ss_family) {
	case AF_INET:
		recv_packet4(recv_sock);
		break;
	case AF_INET6:
		recv_packet6(recv_sock);
		break;
	}
}

int main(int argc, char *argv[]) {
	pid_t running_pid;
	int r = 0;
	struct send_sock6 *send_sock6, *tmp_send_sock6;
	struct send_sock4 *send_sock4, *tmp_send_sock4;
	struct recv_sock *recv_sock, *tmp_recv_sock;
	struct addr_mask *am, *tmp_am;
	int pfds_count = 0;
	int pfds_used = 0;
	struct pollfd *pfds;

	parse_opts(argc, argv);

	if ((argc - optind) <= 1) {
		show_help(argv[0]);
		log_message(LOG_ERR, "error: at least 2 interfaces must be specified");
		exit(2);
	}

	openlog(PACKAGE, LOG_PID | LOG_CONS, LOG_DAEMON);

	// create signal pipe pair
	if (pipe(signal_pipe_fds) < 0) {
		log_message(LOG_ERR, "pipe(): %s", strerror(errno));
		goto end_main;
	}
	pfds_count++;

	// create receiving IPv6 sockets
	recv_sock = create_recv_sock6();
	if (!recv_sock) {
		log_message(LOG_ERR, "unable to create server IPv6 socket");
		r = 1;
		goto end_main;
	}
	list_add(&recv_sock->list, &recv_socks);
	pfds_count++;

	// create receiving IPv4 sockets
	recv_sock = create_recv_sock4();
	if (!recv_sock) {
		log_message(LOG_ERR, "unable to create server IPv4 socket");
		r = 1;
		goto end_main;
	}
	list_add(&recv_sock->list, &recv_socks);
	pfds_count++;

	// create sending IPv6 sockets
	for (int i = optind; i < argc; i++) {
		send_sock6 = create_send_sock6(argv[i], &recv_socks);
		if (!send_sock6) {
			log_message(LOG_ERR, "unable to create IPv6 socket for interface %s", argv[i]);
			r = 1;
			goto end_main;
		}
		list_add(&send_sock6->list, &send_socks6);
	}

	// create sending IPv4 sockets
	for (int i = optind; i < argc; i++) {
		send_sock4 = create_send_sock4(argv[i], &recv_socks);
		if (!send_sock4) {
			log_message(LOG_ERR, "unable to create IPv4 socket for interface %s", argv[i]);
			r = 1;
			goto end_main;
		}
		list_add(&send_sock4->list, &send_socks4);
	}

	if (user) {
		switch_user();
	}

	if (!foreground)
		daemonize();
	else {
		// check for pid file when running in foreground
		running_pid = already_running();
		if (running_pid != -1) {
			log_message(LOG_ERR, "already running as pid %d", running_pid);
			exit(1);
		}
	}

	pfds = calloc(pfds_count, sizeof(struct pollfd));
	if (!pfds) {
		log_message(LOG_ERR, "malloc(): %s", strerror(errno));
		r = 1;
		goto end_main;
	}

	pfds[pfds_used].fd = signal_pipe_fds[PIPE_RD];
	pfds[pfds_used].events = POLLIN;
	pfds_used++;

	list_for_each_entry(recv_sock, &recv_socks, list) {
		pfds[pfds_used].fd = recv_sock->sockfd;
		pfds[pfds_used].events = POLLIN;
		pfds_used++;
	}

	while (true) {
		r = poll(pfds, pfds_used, -1);
		if (r <= 0)
			continue;

		if (pfds[0].revents & POLLIN)
			break;

		for (int i = 1; i < pfds_used; i++) {
			if (!(pfds[i].revents & POLLIN))
				continue;

			list_for_each_entry(recv_sock, &recv_socks, list) {
				if (recv_sock->sockfd == pfds[i].fd) {
					recv_packet(recv_sock);
					break;
				}
			}
		}
	}

	log_message(LOG_INFO, "shutting down...");

end_main:
	list_for_each_entry_safe(recv_sock, tmp_recv_sock, &recv_socks, list) {
		list_del(&recv_sock->list);
		close(recv_sock->sockfd);
		free(recv_sock);
	}

	list_for_each_entry_safe(send_sock6, tmp_send_sock6, &send_socks6, list) {
		list_for_each_entry_safe(am, tmp_am, &send_sock6->ams, list) {
			list_del(&am->list);
			free(am);
		}
		list_del(&send_sock6->list);
		close(send_sock6->sockfd);
		free(send_sock6);
	}

	list_for_each_entry_safe(send_sock4, tmp_send_sock4, &send_socks4, list) {
		list_del(&send_sock4->list);
		close(send_sock4->sockfd);
		free(send_sock4);
	}

	list_for_each_entry_safe(am, tmp_am, &blacklisted_subnets, list) {
		list_del(&am->list);
		free(am);
	}

	list_for_each_entry_safe(am, tmp_am, &whitelisted_subnets, list) {
		list_del(&am->list);
		free(am);
	}

	// remove pid file if it belongs to us
	if (already_running() == getpid())
		unlink(pid_file);

	log_message(LOG_INFO, "exit.");

	return r;
}
