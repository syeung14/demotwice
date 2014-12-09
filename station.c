/*--------------------------------------------------------------------*/
#include <stdio.h>
#include <sys/time.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <errno.h>
#include "common.h"
/*--------------------------------------------------------------------*/
/* Name: Sang Sin Yeung
 * ID: G49743789
 * Changes: Only put code to places marked with "FILL HERE"
 * Date: 12/06/2014
 *
 *    */
/*--------------------------------------------------------------------*/
/* total number of interfaces */
int numfaces;

/* number of active interfaces */
int gudfaces;

/* interface table */
IfaceEntry ifaces[MAXIFACES];

/* get interface given ip addr */
int GetIfaceByIpAddr(IpAddr ipaddr) {
	int face;
	for (face = 0; face < numfaces; face++) {
		if (ifaces[face].ipaddr == ipaddr)
			return (face);
	}
	return (-1);
}

/* get interface given socket */
int GetIfaceBySocket(int socket) {
	int face;
	for (face = 0; face < numfaces; face++) {
		if (ifaces[face].socket == socket)
			return (face);
	}
	return (-1);
}

/* get interface given net name */
int GetIfaceBySubnet(char *subnet) {
	int face;
	for (face = 0; face < numfaces; face++) {
		if (strcmp(ifaces[face].subnet, subnet) == 0)
			return (face);
	}
	return (-1);
}

/* initialize iface table */
int InitIfaces(char *ifacefile) {
	FILE *fp;
	char ifname[MAXSTRING];
	char ipaddr[MAXSTRING];
	char hwaddr[MAXSTRING];
	char subnet[MAXSTRING];
	char mask[MAXSTRING];

	/* open the file */
	fp = fopen(ifacefile, "r");
	if (!fp) {
		fprintf(stderr, "error : unable to open file '%s'\n", ifacefile);
		return (0);
	}

	/* fill in iface entries */
	numfaces = 0;
	gudfaces = 0;
	while (fscanf(fp, "%s %s %s %s %s %d", ifname, subnet, hwaddr, ipaddr, mask,
			&(ifaces[numfaces].dist)) == 6) {
		ifaces[numfaces].ifname = strdup(ifname);
		ifaces[numfaces].subnet = strdup(subnet);
		strtohwaddr(hwaddr, ifaces[numfaces].hwaddr);
		ifaces[numfaces].ipaddr = strtoipaddr(ipaddr);
		ifaces[numfaces].mask = strtoipaddr(mask);
		ifaces[numfaces].socket = hooktolan(subnet);
		if (ifaces[numfaces].socket != -1) {
			gudfaces++;
		} else {
			ifaces[numfaces].dist = INFINITY;
		}
		numfaces++;
	}

	/* done */
	fclose(fp);

	/* return number of active faces */
	return (gudfaces);
}
/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------*/
/* number of entries in the routing table */
int numrouts;

/* routing table */
RouteEntry routes[MAXROUTES];

/* get a route entry given ip addr */
int GetRouteEntry(IpAddr dest) {
	int indx;
	for (indx = 0; indx < numrouts; indx++) {
		if (routes[indx].dist < INFINITY
				&& (dest & routes[indx].mask) == routes[indx].dnet) {
			return (indx);
		}
	}
	return (-1);
}

/* show routing table */
void ShowRouteTable() {
	int indx;

	printf("route table at %s\n", timetostring(getcurtime()));
	printf("%16s | %16s | %16s | %6s | %6s\n", "dnet", "mask", "next", "face",
			"dist");
	for (indx = 0; indx < numrouts; indx++) {
		printf("%16s | %16s | %16s | %6d | %6d\n",
				ipaddrtostr(routes[indx].dnet), ipaddrtostr(routes[indx].mask),
				ipaddrtostr(routes[indx].next), routes[indx].face,
				routes[indx].dist);
	}
}
/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------*/
/* info on each arp entry */
typedef struct __arpentry {
	/* ip address */
	IpAddr ipaddr;

	/* hardware address */
	HwAddr hwaddr;

} ArpEntry;

int numcaches;
ArpEntry arpcache[MAXCACHES];

/* look for an ip addr */
int GetArpEntry(IpAddr ipaddr) {
	/* FILL HERE: look up arp cache for a matching entry
	 if found, return index of the matching entry, -1 otherwise */
	int i = 0;
	for (i = 0; i < numcaches; ++i) {
		if (arpcache[i].ipaddr == ipaddr) {
			return i;
		}
	}
	return -1;
}

/* add an entry */
void AddArpEntry(IpAddr ipaddr, HwAddr hwaddr) {
	char indx;
	char hwaddrstr[MAXSTRING];

	/* check if its already there */
	indx = GetArpEntry(ipaddr);
	if (indx == -1) {
		/* not there, add an entry */
		/* FILL HERE: add an entry in arp cache */
		ArpEntry arpE = {ipaddr, hwaddr};
		hwaddrcpy(arpE.hwaddr, hwaddr);
		arpcache[numcaches++] = arpE;

		/* report the addition */
		hwaddrtostr(hwaddr, hwaddrstr);
		printf("added %s <=> %s to arp cache\n", ipaddrtostr(ipaddr),
				hwaddrstr);
	} else {
		/* already there, update it */
		hwaddrcpy(arpcache[indx].hwaddr, hwaddr);

		/* report the change */
		hwaddrtostr(hwaddr, hwaddrstr);
		printf("updated %s <=> %s to arp cache\n", ipaddrtostr(ipaddr),
				hwaddrstr);
	}

}
/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------*/
/* info on each item in packet queue */
typedef struct __ippktq {
	/* ip pkt */
	IpPkt * pkt;

	/* next hop ip address */
	IpAddr next;

	/* outgoing interface */
	int face;

	/* rest of the q */
	struct __ippktq * rest;

} IpPktQ;

IpPktQ *ippktwaitq = NULL;

/* add the pkt into the q */
void InsertIntoWaitQ(IpPkt *pkt, IpAddr next, int face) {
	IpPktQ *item;

	/* create an item */
	item = (IpPktQ *) calloc(1, sizeof(IpPktQ));
	item->pkt = pkt;
	item->next = next;
	item->face = face;

	/* put this at the head of the q */
	item->rest = ippktwaitq;
	ippktwaitq = item;
}

/* remove a pkt with given next hop from the q */
IpPkt *RemoveFromWaitQ(IpAddr next) {
	IpPktQ *prev;
	IpPktQ *curr;

	/* start at the head */
	curr = ippktwaitq;
	while (curr != NULL) {
		/* break if found */
		if (curr->next == next)
			break;

		/* keep going */
		prev = curr;
		curr = curr->rest;
	}

	/* any such packet? */
	if (curr == NULL) {
		/* no such packet */
		return (NULL);
	} else {
		IpPkt *pkt;

		/* is it at the head */
		if (curr == ippktwaitq) {
			/* reset the head */
			ippktwaitq = curr->rest;
		} else {
			/* delink this item */
			prev->rest = curr->rest;
		}

		/* return the packet */
		pkt = curr->pkt;
		free(curr);
		return (pkt);
	}
}
/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------*/
void SendArpPkt(int face, int operation, IpAddr targetipaddr,
		HwAddr targethwaddr, IpAddr senderipaddr, HwAddr senderhwaddr) {
	ArpPkt *arppkt;
	EthPkt *ethpkt;

	/* form an arp packet */
	arppkt = (ArpPkt *) calloc(1, sizeof(ArpPkt));
	/* FILL HERE: fill in arppkt * e.g: arppkt->operation = operation; */

	arppkt->operation = operation;
	hwaddrcpy(arppkt->targethwaddr, targethwaddr);
	hwaddrcpy(arppkt->senderhwaddr, senderhwaddr);
	arppkt->targetipaddr = targetipaddr;
	arppkt->senderipaddr = senderipaddr;


	 /* encapsulate arp pkt in ether pkt */
	ethpkt = (EthPkt *) calloc(1, sizeof(EthPkt));
	ethpkt->typ = ARP;
	hwaddrcpy(ethpkt->src, senderhwaddr);
	hwaddrcpy(ethpkt->dst, targethwaddr);
	ethpkt->dat = (char *) arppkt;

	/* send the packet */
	if (ifaces[face].socket != -1) {
		/* FILL HERE: send the ethpkt */
		sendethpkt(ifaces[face].socket, ethpkt);
		printf("sent --> ");
	} else {
		printf("disc --> ");
	}
	showethpkt(ethpkt);
}

void SendIpPkt(IpPkt *ippkt, IpAddr next, int face) {
	int arpi;

	/* figure out hw address */
	arpi = GetArpEntry(next);
	if (arpi == -1) {
		/* broadcast arp request */
		/* FILL HERE: broadcast arp request */

		SendArpPkt(face, ARP_REQUEST, next, BCASTADDR,
				ifaces[face].ipaddr, ifaces[face].hwaddr);

		/* queue the packet for later transmission */
		InsertIntoWaitQ(ippkt, next, face);
	} else {
		EthPkt *ethpkt;

		/* encapsulate ip pkt in ether pkt */
		ethpkt = (EthPkt *) calloc(1, sizeof(EthPkt));
		hwaddrcpy(ethpkt->dst, arpcache[arpi].hwaddr);
		hwaddrcpy(ethpkt->src, ifaces[face].hwaddr);
		ethpkt->typ = IP;
		ethpkt->dat = (char *) ippkt;

		/* send the pkt */
		if (ifaces[face].socket != -1) {
			/* FILL HERE: send the ethpkt */
			sendethpkt(ifaces[face].socket, ethpkt);
			printf("sent --> ");
		} else {
			printf("disc --> ");
		}
		showethpkt(ethpkt);
		freeethpkt(ethpkt);
	}
}
/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------*/
/* process an arp packet */
void ProcessArpPkt(ArpPkt *pkt, int face) {
	IpPkt *ippkt;

	/* could be a request or a reply */
	if (pkt->operation == ARP_REQUEST) {
		/* am i the target? */
		if (ifaces[face].ipaddr != pkt->targetipaddr) {
			/* not for us */
			return;
		}

		/* we are the target. should respond */
		SendArpPkt(face, ARP_RESPONS, pkt->senderipaddr, pkt->senderhwaddr,
				ifaces[face].ipaddr, ifaces[face].hwaddr);

		/* update the cache */
		AddArpEntry(pkt->senderipaddr, pkt->senderhwaddr);
	} else {
		/* update the cache */
		AddArpEntry(pkt->senderipaddr, pkt->senderhwaddr);
	}

	/* any pkts pending for this sender */
	while (ippkt = RemoveFromWaitQ(pkt->senderipaddr)) {
		SendIpPkt(ippkt, pkt->senderipaddr, face);
	}
}

/* process an ip packet */
void ProcessIpPkt(IpPkt *pkt) {
	int routindx;

	int face;
	face = GetIfaceByIpAddr(pkt->dst);
	/* see if its meant for us */
	if (pkt->dst == ifaces[face].ipaddr
			/* FILL HERE: is the pkt for this station? */
		) {

		/* for us. display contents */
		printf("%s : %s", ipaddrtoname(pkt->src), pkt->dat);
		freeippkt(pkt);
		return;
	}

	/* not for us. need to route */
	routindx = GetRouteEntry(pkt->dst);
	if (routindx == -1) {
		printf("no route to %s\n", ipaddrtoname(pkt->dst));
		freeippkt(pkt);
		return;
	}

	/* found a route. figure out nexthop */
	if (routes[routindx].next == 0) {
		/* dest can be reached directly */
		/* FILL HERE: send the packet */
		SendIpPkt(pkt, pkt->dst, routes[routindx].face);
	} else {
		/* gotta go thru a router */
		/* FILL HERE: send the packet */
		SendIpPkt(pkt, routes[routindx].next, routes[routindx].face);
	}
}

/* process ether packet */

void ProcessEthPkt(EthPkt *pkt, int frsock) {
	int face;

	/* accept only if our unicast packet or broadcast packet */
	face = GetIfaceBySocket(frsock);
	if (  hwaddrcmp(ifaces[face].hwaddr, pkt->dst)!=0 &&
			hwaddrcmp(pkt->dst, BCASTADDR)!=0
			/* FILL HERE: not our address AND not broadcast address? */
			) {
		/* not for us, just ignore */
		printf("disc --> ");
		showethpkt(pkt);
		freeethpkt(pkt);
		return;
	}
	printf("rcvd --> ");
	showethpkt(pkt);

	/* action depends on packet type */
	switch (pkt->typ) {
	case ARP:
		ProcessArpPkt((ArpPkt *) pkt->dat, face);
		freeethpkt(pkt);
		break;
	case IP:
		ProcessIpPkt((IpPkt *) pkt->dat);
		free(pkt);
		break;
	case DVRP:
		ProcessDvrpPkt((DvrpPkt *) pkt->dat, face);
		freeethpkt(pkt);
		break;
	}
}

/* process the keyboard input */
int ProcessText(char *text) {
	char * destname;
	IpAddr destipaddr;
	IpPkt * ippkt;

	/* figure out the dest host */
	destname = text;
	text = index(text, ' ');
	if (text == NULL) {
		fprintf(stderr, "error: message undecipherable\n");
		return 0;
	}

	*text = '\0';
	text++;

	/* figure out dest's ip address */
	destipaddr = nametoipaddr(destname);
	if (destipaddr == 0) {
		fprintf(stderr, "error: no host named '%s'\n", destname);
		return 0;
	}

	/* form an ip packet */
	ippkt = (IpPkt *) calloc(1, sizeof(IpPkt));
	/* FILL HERE: fill in the ippkt */
	ippkt->dat = strdup(text);
	ippkt->len= strlen(text);
	ippkt->dst = destipaddr;
	ippkt->src = ifaces[0].ipaddr;

	/* treat it like an incoming packet */
	ProcessIpPkt(ippkt);
}
/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------*/
/* interval after which neighbor is marked dead */
int deadint;

/* distance vector refresh interval */
/* we fix this to be 1/3 of deadint */
int refreshint;

/* to or not to split the horizon */
int splithorizon;

/* alarm signal handler */
void timeout();

int main(int argc, char *argv[]) {
	int i;
	fd_set livesdset;
	int livesdmax;

	char ifacesfile[MAXSTRING];
	char hostsfile[MAXSTRING];

	/* check usage */
	// if (argc != 4) {
//    printf("usage : %s <name> <deadinterval> <splithorizon?>\n", argv[0]);
	//  exit(1);
	//}
	/* remember the options */
	//deadint      = atoi(argv[2]);
	//refreshint   = deadint/3;
	//splithorizon = atoi(argv[3]);
	/* init interfaces */
	sprintf(ifacesfile, "%s/%s.if", CONFIGPATH, argv[1]);
	if (!InitIfaces(ifacesfile))
		exit(1);

	/* init arp cache */
	numcaches = 0;

	/* init hosts addresses */
	sprintf(hostsfile, "%s/%s", CONFIGPATH, HOSTSFILE);
	if (!inithosts(hostsfile))
		exit(1);

	/* init distance table */
	InitDistTable();

	/* set the alarm */
	setalarm(refreshint);

	/* setup alarm signal handler */
	signal(SIGALRM, timeout);

	/* mimic a timeout right now */
	timeout();

	/* prepare list of live sockets */
	FD_ZERO(&livesdset);
	livesdmax = 0;
	for (i = 0; i < numfaces; i++) {
		if (ifaces[i].socket == -1)
			continue;

		FD_SET(ifaces[i].socket, &livesdset);
		if (ifaces[i].socket > livesdmax)
			livesdmax = ifaces[i].socket;
	}

	/* watch out stdin too */
	FD_SET(0, &livesdset);

	/* keep processing packets */
	while (1) {
		int frsock, tosock;
		fd_set readset;

		/* wait for packets */
		memcpy(&readset, &livesdset, sizeof(livesdset));
		if (select(livesdmax + 1, &readset, NULL, NULL, NULL) == -1) {
			if (errno == EINTR)
				continue;

			perror("select");
			exit(1);
		}

		/* disable alarm */
		sighold(SIGALRM);
		printf("========== start of packet processing ==========\n");

		/* look for keyboard input */
		if (FD_ISSET(0, &readset)) {
			char bufr[MAXSTRING];
			fgets(bufr, MAXSTRING, stdin);
			ProcessText(bufr);
		}

		/* figure out the socket and read from it */
		for (frsock = 3; frsock <= livesdmax; frsock++) {
			if (FD_ISSET(frsock, &readset)) {
				EthPkt *ethpkt;

				/* get the pkt */
				ethpkt = recvethpkt(frsock);
				if (!ethpkt) {
					int face;

					/* disconnect */
					face = GetIfaceBySocket(frsock);
					printf("disconnect: hub of net '%s' is down.\n",
							ifaces[face].subnet);
					close(ifaces[face].socket);
					FD_CLR(ifaces[face].socket, &livesdset);
					ifaces[face].socket = -1;
					gudfaces--;
					if (gudfaces == 0) {
						printf("all hubs down. me too.\n");
						exit(0);
					}
					MarkFaceDown(face);
				} else {
					/* process the pkt */
					ProcessEthPkt(ethpkt, frsock);
				}
			}
		}

		/* enable alarm */
		sigrelse(SIGALRM);
		printf("==========  end of packet processing  ==========\n");
	}
}
/*--------------------------------------------------------------------*/
