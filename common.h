#ifndef COMMON_H
#define COMMON_H

/*--------------------------------------------------------------------*/
#define MAXSTRING   1024
#define MAXIFACES   32
#define MAXROUTES   32
#define MAXCACHES   32
#define MAXHOSTS    32
#define MAXNIGHBORS 32
#define MAXDESTNETS 32

#define INFINITY    100

#define CONFIGPATH "./etc"
#define HOSTSFILE  "hosts"
/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------*/
/* hardware address is 6 bytes */
typedef unsigned char HwAddr[6];

/* IP address is 4 bytes */
typedef unsigned long IpAddr;

/* hardware broadcast address */
extern HwAddr BCASTADDR;
/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------*/
/* packet types */
#define ARP  1
#define IP   2
#define DVRP 3

/* arp operations */
#define ARP_REQUEST 1
#define ARP_RESPONS 2

/* structure of an ethernet pkt */
typedef struct __ethpkt 
{
  /* destination address */
  HwAddr dst;

  /* source address */
  HwAddr src;

  /* type of packet */
  int    typ;

  /* actual payload */
  char * dat;

} EthPkt;

/* structure of an arp pkt */
typedef struct __arppkt 
{
  /* operation */
  int    operation;
  
  /* sender's hw address */
  HwAddr senderhwaddr;

  /* sender's ip address */
  IpAddr senderipaddr;

  /* target's hw address */
  HwAddr targethwaddr;

  /* target's ip address */
  IpAddr targetipaddr;

} ArpPkt;

/* structure of an ip pkt */
typedef struct __ippkt 
{
  /* source address */
  IpAddr  src;

  /* destination address */
  IpAddr  dst;

  /* length of payload */
  int     len;

  /* actual payload */
  char *  dat;

} IpPkt;


/* structure of a distance vector entry */
typedef struct __dventry
{
  /* destination network prefix */
  IpAddr dnet;

  /* network address mask */
  IpAddr mask;

  /* distance to the destination */
  int    dist;
  
} DvEntry;

/* structure of a dvrp pkt */
typedef struct __dvrppkt 
{
  /* source address */
  IpAddr     src;

  /* size of the vector */
  int        siz;

  /* distance vector */
  DvEntry *  vec;

} DvrpPkt;
/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------*/
/* recv an ether packet */
extern EthPkt *recvethpkt(int sd);

/* send an ether pkt */
extern void sendethpkt(int sd, EthPkt *ethpkt);

/* output packet contents */
extern void showethpkt(EthPkt *ethpkt);
extern void showippkt(IpPkt *ippkt);
extern void showdvrppkt(DvrpPkt *dvrppkt);

/* free up space */
extern void freeethpkt(EthPkt *ethpkt);
extern void freeippkt(IpPkt *ippkt);
extern void freedvrppkt(DvrpPkt *dvrppkt);
/*--------------------------------------------------------------------*/

/*----------------------------------------------------------------*/
/* return ip addr given name */
extern IpAddr nametoipaddr(char *name);

/* return name given ip addr */
extern char *ipaddrtoname(IpAddr addr);


/* convert string to ip address */
extern IpAddr strtoipaddr(char *str);

/* convert ip addres to string */
extern char *ipaddrtostr(IpAddr adr);


/* convert string to hardware address */
extern int  strtohwaddr(char *str, HwAddr adr);

/* convert hardware address to string */
extern int  hwaddrtostr(HwAddr adr, char *str);

/* compare two hardware addresses */
extern int  hwaddrcmp(HwAddr adr1, HwAddr adr2);

/* copy hard address from adr2 to adr1 */
extern void hwaddrcpy(HwAddr adr1, HwAddr adr2);
/*----------------------------------------------------------------*/

/*----------------------------------------------------------------*/
/* get the current time in secs (since 1970) */
extern int getcurtime();

/* convert secs to hour:min:sec format */
extern char *timetostring(long secs);

/* set the timer, generates a SIGALRM signal */
extern void setalarm(int interval);
/*----------------------------------------------------------------*/

/*----------------------------------------------------------------*/
/* info on each interface */
typedef struct __ifaceentry
{
  /* interface name */
  char * ifname;

  /* name of the net */
  char * subnet;
  
  /* hardware address */
  HwAddr hwaddr;

  /* ip address */
  IpAddr ipaddr;

  /* network address mask */
  IpAddr mask;

  /* corresponding socket */
  int    socket;

  /* cost to reach the net */
  int    dist;

} IfaceEntry;

/* total number of interfaces */
extern int numfaces;

/* interface table */
extern IfaceEntry ifaces[];
/*----------------------------------------------------------------*/

/*----------------------------------------------------------------*/
/* info on each route */
typedef struct __routeentry
{
  /* destination network prefix */
  IpAddr dnet;

  /* network address mask */
  IpAddr mask;

  /* next hop router */
  IpAddr next;

  /* outgoing interface */
  int    face;

  /* distance to the destination */
  int    dist;
  
} RouteEntry;

/* number of entries in the routing table */
extern int numrouts;

/* routing table */
extern RouteEntry routes[MAXROUTES];
/*----------------------------------------------------------------*/

#endif
