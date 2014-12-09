/*--------------------------------------------------------------------*/
#include <stdio.h>
#include <sys/time.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <errno.h>
#include "common.h"

/* interval after which neighbor is marked dead */
extern int deadint;

/* distance vector refresh interval */
/* we fix this to be 1/3 of deadint */
extern int refreshint;

/* to or not to split the horizon */
extern int splithorizon;

/* time distance vector was sent last */
int lastdvtime;
/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------*/
/* number of destination networks */
int numdestnets;

/* array of destination networks */
IpAddr destnets[MAXDESTNETS];

/* array of network masks */
IpAddr netmasks[MAXDESTNETS];

/* get the index of destination network */
int GetDestNetIndx(IpAddr destnet)
{
  int indx;
  for (indx=0; indx < numdestnets; indx++) {
    if (destnets[indx] == destnet)
      return(indx);
  }
  return(-1);
}
/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------*/
/* info on each neighbor */
typedef struct __nighborentry
{
  /* ip address */
  IpAddr addr;

  /* connecting interface */
  int    face;

  /* last heard time */
  int    last;

  /* up/down status */
  int    live;

} NighborEntry;

/* number of neighbors */
int numnighbors;

/* array of neighbors */
NighborEntry nighbors[MAXNIGHBORS];

/* get the index of neighbor */
int GetNighborIndx(IpAddr addr)
{
  int indx;
  for (indx=0; indx < numnighbors; indx++) {
    if (nighbors[indx].addr == addr)
      return(indx);
  }
  return(-1);
}
/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------*/
/* distance table: a row per destnet, a column per nighbor */
int disttable[MAXDESTNETS][MAXNIGHBORS];

/* get the distance to a destnet thru a nighbor */
int GetDist(IpAddr destnet, IpAddr nighbor)
{
  return(disttable[GetDestNetIndx(destnet)][GetNighborIndx(nighbor)]);
}

/* show the distance table */
void ShowDistTable()
{
  int destnetindx;
  int nighborindx;

  printf("distance table at %s\n", timetostring(getcurtime()));
  printf("%16s | %16s | %12s", "dnet", "mask", "self");
  for (nighborindx = 1; nighborindx < numnighbors; nighborindx++) {
    printf(" | %12s", ipaddrtoname(nighbors[nighborindx].addr));
  }
  printf("\n");

  for (destnetindx=0; destnetindx < numdestnets; destnetindx++) {
    printf("%16s | %16s",
	   ipaddrtostr(destnets[destnetindx]),
 	   ipaddrtostr(netmasks[destnetindx]));
    for (nighborindx = 0; nighborindx < numnighbors; nighborindx++) {
      printf(" | %12d", disttable[destnetindx][nighborindx]);
    }
    printf("\n");
  }
}
/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------*/
/* pick the nighbor with shortest distance */
int GetBestNighbor(int destnetindx)
{
  int bestdist;
  int bestnighbor;
  int nighborindx;

  bestdist    = INFINITY;
  bestnighbor = 0;
  for (nighborindx=0; nighborindx < numnighbors; nighborindx++) {
    if (disttable[destnetindx][nighborindx] < bestdist) {
      bestdist = disttable[destnetindx][nighborindx];
      bestnighbor = nighborindx;
    }
  }
  return(bestnighbor);
}

/* build routing table from distance table */
void BuildRouteTable()
{
  int destnetindx;
  int bestnighbor;
  extern void SendDistVector();

  /* one entry per destination network */
  numrouts = numdestnets;
  for (destnetindx=0; destnetindx < numdestnets; destnetindx++) {
    /* note the dest net and mask */
    routes[destnetindx].dnet = destnets[destnetindx];
    routes[destnetindx].mask = netmasks[destnetindx];

    /* find the best route to this dest net */
    bestnighbor = GetBestNighbor(destnetindx);
    if (bestnighbor == 0) {
      /* direct route is the best */
      routes[destnetindx].next = 0;
      routes[destnetindx].face = destnetindx;
    } else {
      /* better to go thru this neighbor */
      routes[destnetindx].next = nighbors[bestnighbor].addr;
      routes[destnetindx].face = nighbors[bestnighbor].face;
    }

    /* note the best distance */
    routes[destnetindx].dist = disttable[destnetindx][bestnighbor];
  }

  /* send distance vector to neighbors */
  SendDistVector();
}

/* initialize the distance table */
void InitDistTable()
{
  int destnetindx;

  /* consider self as neighbor 0 */
  numnighbors = 1;

  /* info on directly attached networks only */
  numdestnets = numfaces;
  for (destnetindx=0; destnetindx < numdestnets; destnetindx++) {
    destnets[destnetindx] =
      ifaces[destnetindx].ipaddr & ifaces[destnetindx].mask;
    netmasks[destnetindx] = ifaces[destnetindx].mask;
    disttable[destnetindx][0] = ifaces[destnetindx].dist;
  }

  /* build route table */
  BuildRouteTable();

  /* show the tables */
  ShowDistTable();
  ShowRouteTable();
}
/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------*/
/* add a neighbor and return its index */
int AddNighbor(IpAddr addr, int face)
{
  int destnetindx;
  int nighborindx;

  /* one more nighbor */
  nighborindx = numnighbors;
  nighbors[nighborindx].addr = addr;
  nighbors[nighborindx].face = face;
  numnighbors++;

  /* init the distance thru this nighbor to infinity */
  for (destnetindx=0; destnetindx < numdestnets; destnetindx++) {
    disttable[destnetindx][nighborindx] = INFINITY;
  }

  /* return the index of this nighbor */
  return(nighborindx);
}

/* add a destination network and returns its index */
int AddDestNet(IpAddr destnet, IpAddr netmask)
{
  int destnetindx;
  int nighborindx;

  /* one more destination network */
  destnetindx = numdestnets;
  destnets[destnetindx] = destnet;
  netmasks[destnetindx] = netmask;
  numdestnets++;

  /* init the distance to this destnet to infinity */
  for (nighborindx=0; nighborindx < numnighbors; nighborindx++) {
    disttable[destnetindx][nighborindx] = INFINITY;
  }

  /* return the index of this destnet */
  return(destnetindx);
}
/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------*/
/* see if best distance to any destination changed */
int IsAnyBestDistChanged()
{
  int destnetindx;

  /* go thru each destination network */
  for (destnetindx=0; destnetindx < numdestnets; destnetindx++) {
    int bestnighbor;
    int newbestdist;
    int newbestface;
    
    bestnighbor = GetBestNighbor(destnetindx);
    newbestdist = disttable[destnetindx][bestnighbor];
    newbestface = (bestnighbor == 0 ? destnetindx :
		   nighbors[bestnighbor].face);

    /* return 1, if best dist changed or best face changed */
    if (routes[destnetindx].dist != newbestdist ||
	routes[destnetindx].face != newbestface)
      return(1);
  }

  /* no change, return 0 */
  return(0);
}
/*--------------------------------------------------------------------*/


/*--------------------------------------------------------------------*/
/* process a dvrp packet */
void ProcessDvrpPkt(DvrpPkt *pkt, int face)
{
  int i;
  int nighborindx;
  int destnetindx;
  
  /* could be a new neighbor */
  nighborindx = GetNighborIndx(pkt->src);
  if (nighborindx == -1) {
    /* new neighbor */
    nighborindx = AddNighbor(pkt->src,face);
  }

  /* just heard from this nighbor */
  nighbors[nighborindx].last = getcurtime();
  nighbors[nighborindx].live = 1;

  /* update the distance table */
  for (i = 0; i < pkt->siz; i++) {
    /* could be a new destination network */
    destnetindx = GetDestNetIndx(pkt->vec[i].dnet);
    if (destnetindx == -1) {
      /* new destination network */
      destnetindx = AddDestNet(pkt->vec[i].dnet, pkt->vec[i].mask);
    }

    /* update the distance to this destination network */
    disttable[destnetindx][nighborindx] =
      ifaces[face].dist + pkt->vec[i].dist;

    /* make sure distance is never more than infinity */
    if (disttable[destnetindx][nighborindx] > INFINITY)
      disttable[destnetindx][nighborindx] = INFINITY;
  }

  /* rebuild routing table if           */
  /* 1. any new destination networks OR */
  /* 2. any best distance changed       */
  if (numrouts < numdestnets || IsAnyBestDistChanged()) {
    BuildRouteTable();
  }

  /* show the tables */
  ShowDistTable();
  ShowRouteTable();
}

/* send distanace vector to neighbors */
void SendDistVector()
{
  int face, indx;

  /* send a packet thru each interface */
  for (face = 0; face < numfaces; face++) {
    EthPkt *ethpkt;
    DvrpPkt *dvrppkt;

    /* skip if face is not up */
    if (ifaces[face].socket == -1) continue;

    /* form dvrp packet */
    dvrppkt = (DvrpPkt *) calloc(1, sizeof(DvrpPkt));
    dvrppkt->src = ifaces[face].ipaddr;
    dvrppkt->siz = numdestnets;
    dvrppkt->vec = (DvEntry *) calloc(dvrppkt->siz, sizeof(DvEntry));
    for (indx = 0; indx < numdestnets; indx++) {
      dvrppkt->vec[indx].dnet = routes[indx].dnet;
      dvrppkt->vec[indx].mask = routes[indx].mask;
      dvrppkt->vec[indx].dist = routes[indx].dist;

      /* set dist to inifinity if this is the outgoing interface */
      if (splithorizon && face == routes[indx].face)
	dvrppkt->vec[indx].dist = INFINITY;
    }

    /* put it in ether packet */
    ethpkt = (EthPkt *) calloc(1, sizeof(EthPkt));
    hwaddrcpy(ethpkt->dst, BCASTADDR);
    hwaddrcpy(ethpkt->src, ifaces[face].hwaddr);
    ethpkt->typ = DVRP;
    ethpkt->dat = (char *) dvrppkt;

    /* send the pkt */
    sendethpkt(ifaces[face].socket, ethpkt);
    printf("sent --> ");
    showethpkt(ethpkt);
    freeethpkt(ethpkt);
  }

  /* distance vector was sent just now */
  lastdvtime = getcurtime();
}
/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------*/
/* mark a nighbor as dead */
void MarkNighborDead(int nighborindx)
{
  int destnetindx;

  /* no more live */
  nighbors[nighborindx].live = 0;

  /* set the distance to infinity in this nighbor's column */
  for (destnetindx=0; destnetindx < numdestnets; destnetindx++) {
    disttable[destnetindx][nighborindx] = INFINITY;
  }
}

/* mark a face as down */
void MarkFaceDown(int face)
{
  int indx;

  /* network thru this interface is not directly reachable */
  disttable[face][0] = INFINITY;

  /* mark all neighbors thru this interface as dead */
  /* neighbor index should start from 1 (our index is 0) */
  for (indx=1; indx < numnighbors; indx++) {
    if (nighbors[indx].face == face)
      MarkNighborDead(indx);
  }

  /* rebuild routing table if any best distance changed */
  if (IsAnyBestDistChanged()) {
    BuildRouteTable();
  }

  /* show the tables */
  ShowDistTable();
  ShowRouteTable();
}

/* handler for periodic timeout */
void timeout()
{
  int curtime;
  int indx;

  /* re-set the signal handler */
  signal(SIGALRM, timeout);
  
  /* note current time */
  curtime = getcurtime();
  printf("========== start of timer processing ==========\n");

  /* mark neighbors that have died recently */
  /* neighbor index should start from 1 (our index is 0) */
  for (indx=1; indx < numnighbors; indx++) {
    if (nighbors[indx].live &&
	(curtime - nighbors[indx].last) > deadint) {
      MarkNighborDead(indx);
    }
  }

  /* rebuild routing table if any best distance changed */
  if (IsAnyBestDistChanged()) {
    BuildRouteTable();
  }

  /* show the tables */
  ShowDistTable();
  ShowRouteTable();

  /* send dist vector, if not sent for a while */
  if ((curtime - lastdvtime) > refreshint) {
    SendDistVector();
  }
  printf("==========  end of timer processing  ==========\n");
}
/*--------------------------------------------------------------------*/
