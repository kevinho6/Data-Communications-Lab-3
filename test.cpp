#include <iostream>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <time.h>
#include <fstream>
using namespace std;

int main()
{
  FILE *fp = fopen("topo1_a", "r");
  char line1[256];
  char line2[256];

  fgets(line1, sizeof(line1), fp);
  fgets(line2, sizeof(line2), fp);

  char *thisNodeSocket;
  char *remoteNodeSocket;
  char *thisInterfaceVIP;
  char *remoteInterfaceVIP;
  int cost;



  // thisNodeSocket = strtok(line1, "\n");
  // printf("[IP-address]:[port] %s\n", thisNodeSocket);

  // remoteNodeSocket = strtok(line2, " ");
  // printf("[IP-address-of-remote-node]:[port-of-remote-node] %s\n", remoteNodeSocket);

  // thisInterfaceVIP = strtok(NULL, " ");
  // printf("[VIP of my interface] %s\n", thisInterfaceVIP);

  // remoteInterfaceVIP = strtok(NULL, " ");
  // printf("[VIP of the remote node's interface] %s\n", remoteInterfaceVIP);

  // cost = atoi(strtok(NULL, " "));
  // printf("[Cost] %i\n", cost);

  //   char *myIP = strtok(thisNodeSocket, ":");

  //   char localhost[10] = "127.0.0.1";

  //   printf("%s\n", myIP);
  //   if (strcmp(myIP, "localhost") == 0) {
  //       myIP = localhost;
  //   }
  //   printf("%s\n", myIP);
  printf("%i\n", numeric_limits<int>::max());


  fclose(fp);
}
