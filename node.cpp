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
#include "ipsum.h"

using namespace std;

#define MAX_NUM_ROUTING_ENTRIES 64
#define LOCALHOST "127.0.0.1"
#define IP_ADDR_LEN 16
#define MAX_TTL 16
#define MAX_MTU_SIZE 1400
#define MAX_RECV_SIZE (1024 * 64) // 64 KB
#define TEST_PROTOCOL_VAL 0
#define RIP_PROTOCOL_VAL 200

struct iphdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl : 4;
    unsigned int version : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version : 4;
    unsigned int ihl : 4;
#else
#error "Please fix <bits/endian.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
};

typedef struct interface
{
    int interface_id;
    char my_ip[IP_ADDR_LEN];
    uint16_t my_port;
    //char other_ip[IP_ADDR_LEN];
    //uint16_t other_port;
    char my_vip[IP_ADDR_LEN];
    char other_vip[IP_ADDR_LEN];
    int mtu_size;
    bool is_up;
    int send_socket;
} interface_t;

typedef struct forwarding_entry
{
    char entry_src_addr[IP_ADDR_LEN];
    char dest_addr[IP_ADDR_LEN];
    int interface_id;
    int cost;
    time_t last_updated;
} forwarding_entry_t;

typedef struct forwarding_table
{
    int num_entries;
    forwarding_entry_t forwarding_entries[MAX_NUM_ROUTING_ENTRIES];
} forwarding_table_t;

typedef struct ifconfig_table
{
    int num_entries;
    interface_t ifconfig_entries[MAX_NUM_ROUTING_ENTRIES];
} ifconfig_table_t;

typedef struct rip_packet
{
    uint16_t command;
    uint16_t num_entries;

    struct
    {
        uint32_t cost;
        uint32_t address;
    } entries[MAX_NUM_ROUTING_ENTRIES];
} rip_packet_t;

typedef struct metadata
{
    uint32_t port;
    char my_ip[IP_ADDR_LEN];
} metadata_t;

forwarding_table_t FORWARDING_TABLE;
ifconfig_table_t IFCONFIG_TABLE;
metadata_t SELF;

void initialize_interface(interface_t *interface)
{
    if ((interface->send_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        perror("Failed to start send socket");
        exit(1);
    }
}

//Debugging utility
void print_mem(char const *vp, size_t n)
{
    char const *p = vp;
    for (size_t i = 0; i < n; i++)
        printf("%02x\n", p[i]);
    putchar('\n');
};

void send_packet_with_interface(interface_t *interface, char *data, int data_size, struct iphdr *ip_header)
{
    // TODO --- 1
    // contruct the socket and send it through socket
    // sendto function
    // https://linux.die.net/man/2/sendto

    if (!interface->is_up)
        return;

    struct sockaddr_in dest_addr;

    dest_addr.sin_addr.s_addr = inet_addr(interface->my_ip);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(interface->my_port);

    ip_header->tot_len = ip_header->ihl * 4 + data_size;
    ip_header->check = ip_sum((char *)ip_header, ip_header->ihl * 4);
    char full_packet[ip_header->tot_len];

    memcpy(full_packet, ip_header, ip_header->ihl * 4);
    memcpy(full_packet + ip_header->ihl * 4, data, data_size);

    if (sendto(interface->send_socket, full_packet, ip_header->tot_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
    {
        perror("Failed to send packet");
    }
}

interface_t *get_interface_by_id(int id)
{
    interface_t *temp = IFCONFIG_TABLE.ifconfig_entries;
    int i;
    for (i = 0; i < IFCONFIG_TABLE.num_entries; i++)
    {
        if (IFCONFIG_TABLE.ifconfig_entries[i].interface_id == id)
        {
            return (temp + i);
        }
    }
    return NULL;
}

interface_t *get_interface_by_dest_addr(char *dest_addr)
{
    interface_t *temp = IFCONFIG_TABLE.ifconfig_entries;
    int i;
    for (i = 0; i < IFCONFIG_TABLE.num_entries; i++)
    {
        if (strcmp(IFCONFIG_TABLE.ifconfig_entries[i].other_vip, dest_addr) == 0)
        {
            return (temp + i);
        }
    }
    return NULL;
}

forwarding_entry_t *get_forwarding_entry_by_dest_addr(char *dest_addr)
{
    // TODO --- 2
    // Search the forwarding table to find the next hop / best route

    for (int i = 0; i < FORWARDING_TABLE.num_entries; i++)
    {
        if (strcmp(FORWARDING_TABLE.forwarding_entries[i].dest_addr, dest_addr) == 0)
        {
            forwarding_entry_t *f_entry = &FORWARDING_TABLE.forwarding_entries[i];
            return f_entry;
        }
    }
    // IF WE DON'T FIND THE NEXT BEST HOP THEN DO SOMETHING
    //return NULL;
    forwarding_entry_t * test = &FORWARDING_TABLE.forwarding_entries[0];
    return test;
}

/**
* Creates an ifconfig entry and puts it into the ifconfig table
**/
void create_ifconfig_entry(int ID, uint16_t port, char *myIP, char *myVIP, char *otherVIP)
{
    interface_t entry;
    entry.interface_id = ID;
    entry.my_port = port;
    strcpy(entry.my_ip, myIP);
    strcpy(entry.my_vip, myVIP);
    strcpy(entry.other_vip, otherVIP);
    entry.is_up = true;
    entry.mtu_size = MAX_MTU_SIZE;

    initialize_interface(&entry);
    IFCONFIG_TABLE.ifconfig_entries[ID] = entry;
    IFCONFIG_TABLE.num_entries++;
}

void update_forwarding_entry(char *src_addr, char *next_addr, char *dest_addr, int cost)
{

    // TODO --- 3
    // Whenever needed (received an update from other nodes or link break), update the forwarding table

    // find the forwarding entry that matches the destination address and update the cost
    for (int i = 0; i < FORWARDING_TABLE.num_entries; i++)
    {
        if (strcmp(FORWARDING_TABLE.forwarding_entries[i].entry_src_addr, src_addr) == 0 && strcmp(FORWARDING_TABLE.forwarding_entries[i].dest_addr, dest_addr) == 0)
        {
            FORWARDING_TABLE.forwarding_entries[i].cost = cost;
            break;
        }
    }

    // NOW BROADCAST THOSE UPDATES TO THE NEIGHBORS
}

void build_tables(FILE *fp)
{
    // TODO --- 4
    // Build the forwarding table

    char line1[256];
    char line2[256];

    fgets(line1, sizeof(line1), fp);
    fgets(line2, sizeof(line2), fp);

    char *thisNodeSocket = strtok(line1, "\n");
    char *remoteNodeSocket = strtok(line2, " ");
    char *thisInterfaceVIP = strtok(NULL, " ");
    char *remoteInterfaceVIP = strtok(NULL, " ");
    int cost = atoi(strtok(NULL, " "));

    char *myIP = strtok(thisNodeSocket, ":");
    uint16_t myPort = atoi(strtok(NULL, ""));
    char *remoteIP = strtok(remoteNodeSocket, ":");
    uint16_t remotePort = atoi(strtok(NULL, ""));

    char localhost[10] = "127.0.0.1";
    if (strcmp(myIP, "localhost") == 0) {
        myIP = localhost;
    }
    if (strcmp(remoteIP, "localhost") == 0) {
        remoteIP = localhost;
    }

    forwarding_entry_t newForwardingEntry;
    strcpy(newForwardingEntry.entry_src_addr, myIP);
    strcpy(newForwardingEntry.dest_addr, remoteIP);
    newForwardingEntry.interface_id = IFCONFIG_TABLE.num_entries;
    newForwardingEntry.cost = cost;
    newForwardingEntry.last_updated = time(NULL);

    FORWARDING_TABLE.forwarding_entries[FORWARDING_TABLE.num_entries] = newForwardingEntry;
    FORWARDING_TABLE.num_entries++;

    // Build the interface table
    create_ifconfig_entry(IFCONFIG_TABLE.num_entries, myPort, myIP, thisInterfaceVIP, remoteInterfaceVIP);
}

// Modified the function header
void load_from_file(int numFiles, char **files)
{
    // TODO --- 5
    // Load the configuration files
    // Call build_tables(FILE *fp)

    for (int i = 1; i < numFiles; i++)
    {
        FILE *fp = fopen(files[i], "r");
        build_tables(fp);
        fclose(fp);
    }
}

bool is_dest_equal_to_me(char *dest_addr)
{
    interface_t *temp = IFCONFIG_TABLE.ifconfig_entries;
    int i;
    for (i = 0; i < IFCONFIG_TABLE.num_entries; i++)
    {
        if (strcmp(IFCONFIG_TABLE.ifconfig_entries[i].my_vip, dest_addr) == 0)
        {
            return true;
        }
    }
    return false;
}

void send_packet(char *dest_addr, char *msg, int msg_size, int TTL, int protocol)
{
    // TODO --- 6
    // Call the function to get the next check_for_expired_routes
    // Call the function to get the interface ID
    // Contruct the IP header (listed below)
    // Send the packet through a corresponding interface

    interface_t *interface = get_interface_by_dest_addr(dest_addr);
    struct iphdr ip_header;
    struct iphdr * ip_header_ptr = &ip_header;

    ip_header.id = rand();
    ip_header.saddr = inet_addr(interface->my_vip);
    // FORWARDING ENTRY DESTINATION ADDRESS
    // THIS MAY NOT WORK

    forwarding_entry_t *f_entry = get_forwarding_entry_by_dest_addr(dest_addr);
    ip_header.daddr = inet_addr(f_entry->dest_addr);

    ip_header.version = 4;
    ip_header.ttl = TTL;
    ip_header.protocol = protocol;
    ip_header.ihl = 5;

    // ???
    ip_header.check = 0;
    ip_header.tot_len = 0;
    ip_header.frag_off = 0;

    send_packet_with_interface(interface, msg, msg_size, ip_header_ptr);
}

void set_as_up(int ID)
{
    interface_t *interface = get_interface_by_id(ID);
    if (interface == NULL)
    {
        printf("\nInterface %d is not found.\n\n", ID);
        return;
    }
    interface->is_up = true;
    forwarding_entry_t *entry = get_forwarding_entry_by_dest_addr(IFCONFIG_TABLE.ifconfig_entries[ID].my_vip);
    entry->cost = 0;
    printf("\nInterface %d is up.\n\n", ID);
    return;
}

void set_as_down(int ID)
{
    interface_t *interface = get_interface_by_id(ID);
    if (interface == NULL)
    {
        printf("\nInterface %d is not found.\n\n", ID);
        return;
    }
    interface->is_up = false;
    forwarding_entry_t *entry = get_forwarding_entry_by_dest_addr(IFCONFIG_TABLE.ifconfig_entries[ID].my_vip);
    entry->cost = MAX_TTL;
    printf("\nInterface %d is down.\n\n", ID);
    return;
}

void print_routes()
{
    printf("\nStart finding routes....\n");
    int i;
    for (i = 0; i < FORWARDING_TABLE.num_entries; ++i)
    {
        forwarding_entry_t entry = FORWARDING_TABLE.forwarding_entries[i];
        printf("%s %d %d\n", entry.dest_addr, entry.interface_id, entry.cost);
    }
    printf("....end finding routes.\n\n");
}

void print_ifconfig()
{
    printf("\nStart ifconfig....\n");
    int i;
    for (i = 0; i < IFCONFIG_TABLE.num_entries; ++i)
    {
        interface_t entry = IFCONFIG_TABLE.ifconfig_entries[i];
        printf("%d %s %s\n", entry.interface_id, entry.my_vip, entry.is_up ? "up" : "down");
    }
    printf("....end ifconfig.\n\n");
}

void send_forwarding_update(char *dest_addr)
{
    // TODO --- 7
    // Sends an RIP update to a specified destination
    // Call a corresponding function
    // send_packet();
}

void activate_RIP_update()
{
    int i;
    for (i = 0; i < IFCONFIG_TABLE.num_entries; i++)
    {
        if (IFCONFIG_TABLE.ifconfig_entries[i].is_up)
        {
            send_forwarding_update(IFCONFIG_TABLE.ifconfig_entries[i].other_vip);
        }
    }
}

void request_routes()
{
    int i;
    for (i = 0; i < IFCONFIG_TABLE.num_entries; i++)
    {
        rip_packet_t *RIP_packet = (rip_packet_t *)malloc(sizeof(rip_packet_t *));
        RIP_packet->command = 1;
        RIP_packet->num_entries = 0;
        send_packet(IFCONFIG_TABLE.ifconfig_entries[i].other_vip, (char *)RIP_packet, sizeof(rip_packet_t), MAX_TTL, RIP_PROTOCOL_VAL);
    }
}

void check_for_expired_routes()
{

    // TODO --- 8
    // Periodically check the routes
    // forwarding_entries[i].interface_id != -1 & ((int) time(NULL) - (int) forwarding_entries[i].last_updated > 12)
    // You should do something to mark it invalid
}

void choose_command(char *command)
{

    // TODO --- 9
    // Get the command from the user
    // Process the commands

    if (strncmp(command, "ifconfig", 8) == 0)
    {
        print_ifconfig();
    }
    else if (strncmp(command, "routes", 6) == 0)
    {
        print_routes();
    }
    else if (strncmp(command, "down", 4) == 0)
    {
        strtok(command, " ");
        int interfaceID = atoi(strtok(NULL, ""));
        set_as_down(interfaceID);
    }
    else if (strncmp(command, "up", 2) == 0)
    {
        strtok(command, " ");
        int interfaceID = atoi(strtok(NULL, ""));
        set_as_up(interfaceID);
        activate_RIP_update();
    }
    else if (strncmp(command, "send", 4) == 0)
    {
        strtok(command, " ");
        char *dest_addr = strtok(NULL, " ");
        char *msg = strtok(NULL, "");
        int msg_size = strlen(msg);
        int TTL = MAX_TTL;
        int protocol = 0;
        send_packet(dest_addr, msg, msg_size, TTL, protocol);
    }
}

int init_listen_socket(int port, fd_set *running_fd_set)
{
    int listen_socket;
    struct sockaddr_in server_addr;

    bzero((char *)&server_addr, sizeof(server_addr));
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if ((listen_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    { //UDP socket listening for anything
        perror("Create socket error: ");
        exit(1);
    }

    if ((bind(listen_socket, (const struct sockaddr *)&server_addr, (socklen_t)sizeof(server_addr))) < 0)
    {
        perror("Bind error: ");
        exit(1);
    }

    FD_SET(listen_socket, running_fd_set);

    fcntl(listen_socket, F_SETFL, O_NONBLOCK, 1); // non-blocking interactions

    return listen_socket;
}

void handle_packet(int listen_socket)
{

    // TODO --- 10
    // The most important and comprehensive
    // Think carefully and completely
    // You should call multiple functions listed above
}

int main(int argc, char **argv)
{
    // Initialize based on input file
    FORWARDING_TABLE.num_entries = 0;
    IFCONFIG_TABLE.num_entries = 0;
    // passed in number of arguments and the array of file names
    load_from_file(argc, argv);

    // initialize routing information
    int listen_socket;
    fd_set full_fd_set;
    fd_set *running_ptr;
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 1000;

    time_t last_updated;
    time(&last_updated);

    running_ptr = &full_fd_set;
    listen_socket = init_listen_socket(SELF.port, running_ptr);

    char command_line[1500];

    // CODE ERRORS HERE
    request_routes();

    while (1)
    {
        FD_ZERO(running_ptr);
        FD_SET(STDIN_FILENO, running_ptr);
        FD_SET(listen_socket, running_ptr);

        // check for user input
        // handle
        // check for received packet
        // handle

        if (select(FD_SETSIZE, running_ptr, NULL, NULL, &timeout) < 0)
        {
            perror("Select error: ");
            exit(EXIT_FAILURE);
        }

        if (FD_ISSET(listen_socket, running_ptr))
        {
            // data ready on the read socket
            //TODO: receive data and pass directly to ALL interfaces
            // Only an up and directly attached interface (by source port) should act on this and call handle_packet
            handle_packet(listen_socket);
        }

        if (FD_ISSET(STDIN_FILENO, running_ptr))
        {
            scanf("%s", command_line);
            //fgets(command_line, 100, stdin);
            //printf( "\n%s", commandLine);
            choose_command(command_line);
            fflush(STDIN_FILENO);
        }

        if (((int)time(NULL) - (int)last_updated) >= 5)
        {
            request_routes();
            time(&last_updated);
            //printf("been 5 seconds\n");
        }
        check_for_expired_routes();
    }
}
