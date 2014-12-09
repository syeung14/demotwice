/*--------------------------------------------------------------------*/
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netdb.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include "common.h"

/* hardware broadcast address */
HwAddr BCASTADDR = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
/*--------------------------------------------------------------------*/

/*----------------------------------------------------------------*/
/* info on each host */
typedef struct __host {
	char * name;
	IpAddr addr;
} Host;

int numhosts;
Host hosts[MAXHOSTS];

/* init hosts table */
int inithosts(char *hostsfile) {
	FILE *fp;
	char name[MAXSTRING];
	char addr[MAXSTRING];

	/* open the file */
	fp = fopen(hostsfile, "r");
	if (!fp) {
		fprintf(stderr, "error : unable to open file '%s'\n", hostsfile);
		return (0);
	}

	/* fill in hosts addresses */
	numhosts = 0;
	while (fscanf(fp, "%s %s", name, addr) == 2) {
		hosts[numhosts].name = strdup(name);
		hosts[numhosts].addr = strtoipaddr(addr);
		numhosts++;
	}
	return (1);
}

/* show hosts table */
void showhosts() {
	int i;
	char addr[32];

	for (i = 0; i < numhosts; i++) {
		printf("%s %s\n", hosts[i].name, ipaddrtostr(hosts[i].addr));
	}
}

/* return ip addr given name */
IpAddr nametoipaddr(char *name) {
	int i;

	for (i = 0; i < numhosts; i++) {
		if (strcmp(hosts[i].name, name) == 0) {
			return (hosts[i].addr);
		}
	}
	return (0);
}

/* return name given ip addr */
char *ipaddrtoname(IpAddr addr) {
	int i;

	for (i = 0; i < numhosts; i++) {
		if (hosts[i].addr == addr) {
			return (hosts[i].name);
		}
	}
	return (NULL);
}
/*----------------------------------------------------------------*/

/*----------------------------------------------------------------*/
/* read n bytes from sd */
int readn(int sd, char *buf, int n) {
	int toberead;
	char * ptr;

	toberead = n;
	ptr = buf;
	while (toberead > 0) {
		int byteread;

		byteread = read(sd, ptr, toberead);
		if (byteread <= 0) {
			if (byteread == -1)
				perror("read");
			return (0);
		}

		toberead -= byteread;
		ptr += byteread;
	}
	return (1);
}

/* recv an ether packet */
EthPkt * recvethpkt(int sd) {
	EthPkt *ethpkt;

	/* allocate space for the ethpkt */
	ethpkt = (EthPkt *) calloc(1, sizeof(EthPkt));
	if (!ethpkt) {
		fprintf(stderr, "error : unable to calloc\n");
		exit(1);
	}

	/* read the header */
	if (!readn(sd, ethpkt->dst, sizeof(HwAddr))) {
		free(ethpkt);
		return (NULL);
	}

	if (!readn(sd, ethpkt->src, sizeof(HwAddr))) {
		free(ethpkt);
		return (NULL);
	}

	if (!readn(sd, (char *) &ethpkt->typ, sizeof(int))) {
		free(ethpkt);
		return (NULL);
	}
	ethpkt->typ = ntohl(ethpkt->typ);

	/* rest depends on type */
	switch (ethpkt->typ) {
	case ARP: {
		ArpPkt *arppkt;
		arppkt = (ArpPkt *) calloc(1, sizeof(ArpPkt));
		if (!arppkt) {
			fprintf(stderr, "error : unable to calloc\n");
			exit(1);
		}
		ethpkt->dat = (char *) arppkt;

		if (!readn(sd, (char *) &arppkt->operation, sizeof(int))) {
			freeethpkt(ethpkt);
			return (NULL);
		}
		arppkt->operation = ntohl(arppkt->operation);

		if (!readn(sd, arppkt->senderhwaddr, sizeof(HwAddr))) {
			freeethpkt(ethpkt);
			return (NULL);
		}

		if (!readn(sd, (char *) &arppkt->senderipaddr, sizeof(int))) {
			freeethpkt(ethpkt);
			return (NULL);
		}

		if (!readn(sd, arppkt->targethwaddr, sizeof(HwAddr))) {
			freeethpkt(ethpkt);
			return (NULL);
		}

		if (!readn(sd, (char *) &arppkt->targetipaddr, sizeof(int))) {
			freeethpkt(ethpkt);
			return (NULL);
		}
	}
		break;
	case IP: {
		IpPkt *ippkt;

		ippkt = (IpPkt *) calloc(1, sizeof(IpPkt));
		if (!ippkt) {
			fprintf(stderr, "error : unable to calloc\n");
			exit(1);
		}
		ethpkt->dat = (char *) ippkt;

		if (!readn(sd, (char *) &ippkt->src, sizeof(int))) {
			freeethpkt(ethpkt);
			return (NULL);
		}

		if (!readn(sd, (char *) &ippkt->dst, sizeof(int))) {
			freeethpkt(ethpkt);
			return (NULL);
		}

		if (!readn(sd, (char *) &ippkt->len, sizeof(int))) {
			freeethpkt(ethpkt);
			return (NULL);
		}
		ippkt->len = ntohl(ippkt->len);

		ippkt->dat = (char *) calloc(ippkt->len, sizeof(char));
		if (!readn(sd, (char *) ippkt->dat, ippkt->len)) {
			freeethpkt(ethpkt);
			return (NULL);
		}
	}
		break;
	case DVRP: {
		DvrpPkt *dvrppkt;
		int i;

		dvrppkt = (DvrpPkt *) calloc(1, sizeof(DvrpPkt));
		if (!dvrppkt) {
			fprintf(stderr, "error : unable to calloc\n");
			exit(1);
		}
		ethpkt->dat = (char *) dvrppkt;

		if (!readn(sd, (char *) &dvrppkt->src, sizeof(int))) {
			freeethpkt(ethpkt);
			return (NULL);
		}

		if (!readn(sd, (char *) &dvrppkt->siz, sizeof(int))) {
			freeethpkt(ethpkt);
			return (NULL);
		}
		dvrppkt->siz = ntohl(dvrppkt->siz);

		dvrppkt->vec = (DvEntry *) calloc(dvrppkt->siz, sizeof(DvEntry));
		for (i = 0; i < dvrppkt->siz; i++) {
			if (!readn(sd, (char *) &dvrppkt->vec[i].dnet, sizeof(int))) {
				freeethpkt(ethpkt);
				return (NULL);
			}
			if (!readn(sd, (char *) &dvrppkt->vec[i].mask, sizeof(int))) {
				freeethpkt(ethpkt);
				return (NULL);
			}
			if (!readn(sd, (char *) &dvrppkt->vec[i].dist, sizeof(int))) {
				freeethpkt(ethpkt);
				return (NULL);
			}
			dvrppkt->vec[i].dist = ntohl(dvrppkt->vec[i].dist);
		}
	}
		break;
	}

	/* done reading */
	return (ethpkt);
}

/* send an ether pkt */
void sendethpkt(int sd, EthPkt *ethpkt) {
	char * buf;
	char * ptr;
	int len;
	int tmp;

	/* allocate space for the buffer */
	len = 2 * sizeof(HwAddr) + sizeof(int);
	switch (ethpkt->typ) {
	case ARP:
		len += 3 * sizeof(int) + 2 * sizeof(HwAddr);
		break;
	case IP:
		len += 3 * sizeof(int) + ((IpPkt *) ethpkt->dat)->len;
		break;
	case DVRP:
		len += 2 * sizeof(int)
				+ 3 * sizeof(int) * (((DvrpPkt *) ethpkt->dat)->siz);
		break;
	}
	buf = (char *) calloc(len, sizeof(char));
	if (!buf) {
		fprintf(stderr, "error : unable to calloc %d bytes\n", len);
		exit(1);
	}

	/* linearize the ethpkt */
	ptr = buf;
	memcpy(ptr, ethpkt->dst, sizeof(HwAddr));
	ptr += sizeof(HwAddr);

	memcpy(ptr, ethpkt->src, sizeof(HwAddr));
	ptr += sizeof(HwAddr);

	tmp = htonl(ethpkt->typ);
	memcpy(ptr, (char *) &tmp, sizeof(int));
	ptr += sizeof(int);

	/* rest depends on ethpkt type */
	switch (ethpkt->typ) {
	case ARP: {
		ArpPkt *arppkt;
		arppkt = (ArpPkt *) ethpkt->dat;

		tmp = htonl(arppkt->operation);
		memcpy(ptr, (char *) &tmp, sizeof(int));
		ptr += sizeof(int);

		memcpy(ptr, (char *) &arppkt->senderhwaddr, sizeof(HwAddr));
		ptr += sizeof(HwAddr);

		memcpy(ptr, (char *) &arppkt->senderipaddr, sizeof(int));
		ptr += sizeof(int);

		memcpy(ptr, (char *) &arppkt->targethwaddr, sizeof(HwAddr));
		ptr += sizeof(HwAddr);

		memcpy(ptr, (char *) &arppkt->targetipaddr, sizeof(int));
		ptr += sizeof(int);
	}
		break;
	case IP: {
		IpPkt *ippkt;
		ippkt = (IpPkt *) ethpkt->dat;

		memcpy(ptr, (char *) &ippkt->src, sizeof(int));
		ptr += sizeof(int);

		memcpy(ptr, (char *) &ippkt->dst, sizeof(int));
		ptr += sizeof(int);

		tmp = htonl(ippkt->len);
		memcpy(ptr, (char *) &tmp, sizeof(int));
		ptr += sizeof(int);

		memcpy(ptr, (char *) ippkt->dat, ippkt->len);
	}
		break;
	case DVRP: {
		int i;
		DvrpPkt *dvrppkt;
		dvrppkt = (DvrpPkt *) ethpkt->dat;

		memcpy(ptr, (char *) &dvrppkt->src, sizeof(int));
		ptr += sizeof(int);

		tmp = htonl(dvrppkt->siz);
		memcpy(ptr, (char *) &tmp, sizeof(int));
		ptr += sizeof(int);

		for (i = 0; i < dvrppkt->siz; i++) {
			memcpy(ptr, (char *) &dvrppkt->vec[i].dnet, sizeof(int));
			ptr += sizeof(int);

			memcpy(ptr, (char *) &dvrppkt->vec[i].mask, sizeof(int));
			ptr += sizeof(int);

			tmp = htonl(dvrppkt->vec[i].dist);
			memcpy(ptr, (char *) &tmp, sizeof(int));
			ptr += sizeof(int);
		}
	}
		break;
	}

	/* send the packet */
	write(sd, buf, len);
	free(buf);
}

/* output eth packet contents */
void showethpkt(EthPkt *ethpkt) {
	char bufr[MAXSTRING];

	/* common header */
	hwaddrtostr(ethpkt->dst, bufr);
	printf("%s", bufr);
	hwaddrtostr(ethpkt->src, bufr);
	printf(" | %s", bufr);

	/* type specific stuff */
	switch (ethpkt->typ) {
	case ARP: {
		ArpPkt *arppkt;

		arppkt = (ArpPkt *) ethpkt->dat;
		printf(" | %s", "ARP");
		if (arppkt->operation == ARP_REQUEST) {
			printf(" | %s", "REQUEST");
		} else {
			printf(" | %s", "RESPONS");
		}

		hwaddrtostr(arppkt->senderhwaddr, bufr);
		printf(" | %s", bufr);
		printf(" | %s", ipaddrtostr(arppkt->senderipaddr));

		hwaddrtostr(arppkt->targethwaddr, bufr);
		printf(" | %s", bufr);
		printf(" | %s\n", ipaddrtostr(arppkt->targetipaddr));
	}
		break;
	case IP: {
		IpPkt *ippkt;

		ippkt = (IpPkt *) ethpkt->dat;
		printf(" | ");
		showippkt(ippkt);
	}
		break;
	case DVRP: {
		DvrpPkt *dvrppkt;

		dvrppkt = (DvrpPkt *) ethpkt->dat;
		printf(" | ");
		showdvrppkt(dvrppkt);
	}
		break;
	}
}

/* output ip packet contents */
void showippkt(IpPkt *ippkt) {
	printf("%s", "IP");

	printf(" | %s", ipaddrtostr(ippkt->src));
	printf(" | %s", ipaddrtostr(ippkt->dst));
	printf(" | %d", ippkt->len);
	printf(" | %s", ippkt->dat);
}

/* output dvrp packet contents */
void showdvrppkt(DvrpPkt *dvrppkt) {
	int i;

	printf("%s", "DVRP");

	printf(" | %s", ipaddrtostr(dvrppkt->src));
	printf(" | %d\n", dvrppkt->siz);
	for (i = 0; i < dvrppkt->siz; i++) {
		printf("\t\t\t\t %s", ipaddrtostr(dvrppkt->vec[i].dnet));
		printf(" | %s", ipaddrtostr(dvrppkt->vec[i].mask));
		printf(" | %d\n", dvrppkt->vec[i].dist);
	}
}

void freeethpkt(EthPkt *pkt) {
	switch (pkt->typ) {
	case IP:
		free(((IpPkt *) (pkt->dat))->dat);
		break;
	case DVRP:
		free(((DvrpPkt *) (pkt->dat))->vec);
		break;
	}

	free(pkt->dat);
	free(pkt);
}

void freeippkt(IpPkt *pkt) {
	free(pkt->dat);
	free(pkt);
}

void freedvrppkt(DvrpPkt *pkt) {
	free(pkt->vec);
	free(pkt);
}
/*----------------------------------------------------------------*/

/*----------------------------------------------------------------*/
/* convert string to ip address */
IpAddr strtoipaddr(char *str) {
	return ((IpAddr) inet_addr(str));
}

/* convert ip addres to string */
char *ipaddrtostr(IpAddr adr) {
	struct in_addr tmp;
	tmp.s_addr = adr;
	return (strdup(inet_ntoa(tmp)));
}

/* convert string to hardware address */
int strtohwaddr(char *str, HwAddr adr) {
	int byte;
	char *ptr;
	int i;

	ptr = str;
	for (i = 0; i < 5; i++) {
		char *tmp;

		if (sscanf(ptr, "%x", &byte) < 1)
			return (0);
		adr[i] = byte;

		tmp = index(ptr, ':');
		if (!tmp)
			return (0);
		ptr = tmp + 1;
	}
	if (sscanf(ptr, "%x", &byte) < 1)
		return (0);
	adr[i] = byte;

	return (1);
}

/* convert hardware address to string */
int hwaddrtostr(HwAddr adr, char *str) {
	int j, k;
	const char hexbuf[] = "0123456789ABCDEF";

	for (j = 0, k = 0; j < 6; j++) {
		str[k++] = hexbuf[(adr[j] >> 4) & 15];
		str[k++] = hexbuf[adr[j] & 15];
		str[k++] = ':';
	}
	str[--k] = 0;

	return (1);
}

/* compare two hardware addresses */
int hwaddrcmp(HwAddr adr1, HwAddr adr2) {
	return (memcmp(adr1, adr2, sizeof(HwAddr)));
}

/* copy hard address from adr2 to adr1 */
void hwaddrcpy(HwAddr adr1, HwAddr adr2) {
	memcpy(adr1, adr2, sizeof(HwAddr));
}
/*----------------------------------------------------------------*/

/*----------------------------------------------------------------*/
/* hub calls this to start the lan */
int initlan(char *lan) {
	int sd;
	struct sockaddr_in myaddr;
	int addrlen;

	char myhostname[MAXSTRING];
	struct hostent *myhostent;

	char linktrgt[MAXSTRING];
	char linkname[MAXSTRING];

	/* create a socket */
	sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sd == -1) {
		perror("socket");
		return (-1);
	}

	/* bind the socket to some port */
	bzero((char *) &myaddr, sizeof(myaddr));
	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	myaddr.sin_port = htons(0);
	if (bind(sd, (struct sockaddr *) &myaddr, sizeof(myaddr)) == -1) {
		perror("bind");
		return (-1);
	}
	listen(sd, 5);

	/* figure out the port of self */
	addrlen = sizeof(myaddr);
	if (getsockname(sd, (struct sockaddr *) &myaddr, &addrlen) == -1) {
		perror("getsockname");
		return (-1);
	}

	/* figure out the name of self */
	gethostname(myhostname, MAXSTRING);
	myhostent = gethostbyname(myhostname);
	if (!myhostent) {
		perror("gethostbyname");
		return (-1);
	}

	/* create a link to let others know about self */
	sprintf(linktrgt, "%s:%d", myhostent->h_name, (int) ntohs(myaddr.sin_port));
	sprintf(linkname, ".%s.info", lan);
	if (symlink(linktrgt, linkname) != 0) {
		fprintf(stderr, "error : hub already exists\n");
		return (-1);
	}

	/* ready to accept requests */
	printf("admin: started hub on '%s' at '%d'\n", myhostent->h_name,
			(int) ntohs(myaddr.sin_port));
	return (sd);
}

/* stations call this to connect to hub */
int hooktolan(char *lan) {
	int sd;

	struct sockaddr_in saddr;
	struct hostent *he;

	char linkname[MAXSTRING];
	char linktrgt[MAXSTRING];
	char *servhost, *servport;
	int bytecnt;

	/* locate server */
	sprintf(linkname, ".%s.info", lan);
	bytecnt = readlink(linkname, linktrgt, MAXSTRING);
	if (bytecnt == -1) {
		fprintf(stderr, "error : no active hub on '%s'\n", lan);
		return (-1);
	}
	linktrgt[bytecnt] = '\0';

	/* split addr into host and port */
	servport = index(linktrgt, ':');
	*servport = '\0';
	servport++;
	servhost = linktrgt;

	/* create a socket */
	sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sd == -1) {
		perror("socket");
		return (-1);
	}

	/* form the server's address */
	bzero((char *) &saddr, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(atoi(servport));
	he = gethostbyname(servhost);
	if (!he) {
		perror(servhost);
		return (-1);
	}
	bcopy(he->h_addr, (char *) &saddr.sin_addr, he->h_length);

	/* get connnected to the server */
	if (connect(sd, (struct sockaddr *) &saddr, sizeof(saddr)) == -1) {
		perror("connect");
		return (-1);
	}

	/* succesful. return socket descriptor */
	printf("admin: connected to hub on '%s' at '%s'\n", servhost, servport);
	return (sd);
}
/*----------------------------------------------------------------*/

/*----------------------------------------------------------------*/
/* get the current time in secs (since 1970) */
int getcurtime() {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec);
}

/* convert secs to hour:min:sec format */
char *timetostring(long secs) {
	struct tm * tm;
	static char curtime[32];
	tm = localtime(&secs);
	sprintf(curtime, "%02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);
	return (curtime);
}

/* set the timer, generates a SIGALRM signal */
void setalarm(int interval) {
	struct itimerval timer;
	timer.it_interval.tv_usec = 0;
	timer.it_interval.tv_sec = interval;
	timer.it_value.tv_usec = 0;
	timer.it_value.tv_sec = interval;
	if (setitimer(ITIMER_REAL, &timer, NULL) == -1) {
		perror("setitimer");
		exit(1);
	}
}
/*----------------------------------------------------------------*/
