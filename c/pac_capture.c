#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

int main()
{
    char *device_name;
    pcap_t *pack_descr;
    char error[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct pcap_pkthdr header;
    struct ether_header *eptr; // net/ethernet.h defined by pcap.h
    u_char *hard_ptr;
    struct ip *iph;

    device_name = pcap_lookupdev(error);
    if (device_name == NULL)
    {
        printf("Error Thrown: %s\n", error);
        return -1;
    }

    printf("Network Device Name: %s\n", device_name);

    pack_descr = pcap_open_live(device_name, BUFSIZ, 0, 1, error);
    if (pack_descr == NULL)
    {
        printf("Error Thrown: %s\n", error);
        return -1;
    }

    while (1)
    {
        packet = pcap_next(pack_descr, &header);
        if (packet == NULL)
        {
            printf("No packet captured.\n");
            return -1;
        }
        printf("--------------------==[ Packet Captured ]==--------------------\n");
        printf("Packet Capture Length: %d\n", header.len);
        printf("Received at: %s", ctime((const time_t *)&header.ts.tv_sec));
        printf("Ether Header Length: %d\n", ETHER_HDR_LEN);
        eptr = (struct ether_header *)packet;
        if (ntohs(eptr->ether_type) == ETHERTYPE_IP)
        { // 0x0800
            printf("Ethernet Type Hex: 0x%x Dec: %d is an IP Packet\n",
                   ETHERTYPE_IP,
                   ETHERTYPE_IP);
            iph = (struct ip *)(packet + ETHER_HDR_LEN);
            printf("Source IP Address: %s\n", inet_ntoa(iph->ip_src));
            printf("Destination IP Address: %s\n", inet_ntoa(iph->ip_dst));
        }
        else if (ntohs(eptr->ether_type) == ETHERTYPE_ARP)
        { // 0x0806
            printf("Ethernet Type Hex: 0x%x Dec: %d is an ARP Packet\n",
                   ETHERTYPE_ARP,
                   ETHERTYPE_ARP);
        }
        else
        {
            printf("Ethernet Type Hex: 0x%x Dec: %d is an unknown Packet\n",
                   ETHERTYPE_ARP,
                   ETHERTYPE_ARP);
        }
        hard_ptr = eptr->ether_dhost;
        int i = ETHER_ADDR_LEN;
        printf("Destination Address: ");
        do
        {
            if (i == ETHER_ADDR_LEN)
                printf("%02x", *hard_ptr++);
            else
                printf(":%02x", *hard_ptr++);
        } while (--i > 0);
        printf("\n");
        hard_ptr = eptr->ether_shost;
        i = ETHER_ADDR_LEN;
        printf("Source Address: ");
        do
        {
            if (i == ETHER_ADDR_LEN)
                printf("%02x", *hard_ptr++);
            else
                printf(":%02x", *hard_ptr++);
        } while (--i > 0);
        printf("\n--------------------==[ End of Packet ]==--------------------\n");
    }
    return 0;
}
