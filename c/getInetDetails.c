#include "stdio.h"
#include "stdlib.h"
#include "pcap.h"
#include "errno.h"
#include "sys/socket.h"
#include "netinet/in.h"
#include "arpa/inet.h"
int main()
{
    char *device_name, *netmask, *net_addr;
    char error[PCAP_ERRBUF_SIZE];
    int rcode;
    // Ip Address as UnSigned 32 bit Integer
    bpf_u_int32 net_addr_int, netmask_int;
    struct in_addr addr;

    // ASK PCAP To Find a Suitable Device To Capture Packets
    device_name = pcap_lookupdev(error);
    if (device_name == NULL)
    {
        printf("Error Thrown: %s\n", error);
        return -1;
    }
    printf("Network Device Name: %s\n", device_name);

    // ASK PCAP To Find the IP Address and SubNetMask of the Device
    rcode = pcap_lookupnet(device_name, &net_addr_int, &netmask_int, error);
    if (rcode == -1)
    {
        printf("Error Thrown: %s\n", error);
        return -1;
    }
    // Convert 32 bit Integer to IP Address and SubNetMask
    addr.s_addr = net_addr_int;
    net_addr = inet_ntoa(addr);
    if (net_addr == NULL)
    {
        perror("inet_ntoa");
        return -1;
    }
    printf("Network Address: %s\n", net_addr);

    addr.s_addr = netmask_int;
    netmask = inet_ntoa(addr);
    if (netmask == NULL)
    {
        perror("inet_ntoa");
        return -1;
    }
    printf("Subnet Mask: %s\n", netmask);
    return 0;
}