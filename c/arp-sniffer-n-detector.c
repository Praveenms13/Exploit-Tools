#include "stdio.h"
#include "stdlib.h"
#include "pcap.h"
#include "string.h"
#include "time.h"
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>

#define ARP_REQUEST 1  // ARP RESPONSE
#define ARP_RESPONSE 2 // ARP REQUEST

typedef struct _arp_hdr arp_hdr;
struct _arp_hdr
{
    uint16_t htype;        // Hardware Type (Ethernet)
    uint16_t ptype;        // Protocol Type (IP)
    uint8_t hlen;          // Hardware Address Length (MAC)
    uint8_t plen;          // Protocol Address Length (IP)
    uint16_t opcode;       // Operation Code (ARP Request or ARP Response)
    uint8_t sender_mac[6]; // Sender MAC Address (Attacker)
    uint8_t sender_ip[4];  // Sender IP Address (Attacker)
    uint8_t target_mac[6]; // Target MAC Address (Victim)
    uint8_t target_ip[4];  // Target IP Address (Victim)
};

void print_available_interfaces()
{
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces, *temp;
    int i = 0;
    if (pcap_findalldevs(&interfaces, error) == -1)
    {
        printf("Cannot Acquire the devices: %s\n", error);
        exit(1);
    }
    printf("The Available Interfaces are:\n");
    for (temp = interfaces; temp; temp = temp->next)
    {
        printf("#%d => %s - %s\n", ++i, temp->name, temp->description);
    }
}
void print_help(char *bin)
{
    printf("\n\nARP Spoof Detector\n");
    printf("Version: %s and the Tool version is 1.0.0\n", pcap_lib_version());
    printf("Usage: arpSniffer [OPTION]...\n");
    printf("Eg. %s -i < interface>[You can look for the available interfaces using -l (or) --lokup]\n", bin);
    printf("ARP Sniffer\n");
    printf("\n");
    printf("  -h, --help\t\t\tPrint this help\n");
    printf("  -v, --version\t\t\tPrint version information\n");
    printf("  -i, --interface=INTERFACE\tSpecify the interface to sniff on\n");
    printf("\n\n___  ____________   ___________ _____  ___________ ___________  \n");
    printf("End of Program\n");
}
void print_version()
{
    printf("    ___   ___  ___                           \n");
    printf("   / _ | / _ \\/ _ \\                          \n");
    printf("  / __ |/ , _/ ___/                          \n");
    printf(" /_/_|_/_/|_/_/_________________             \n");
    printf("   / __/ |/ /  _/ __/ __/ __/ _ \\            \n");
    printf("  _\\ \\/    // // _// _// _// , _/            \n");
    printf(" /___/_/|_/___/_/_/_/ /___/_/|_|             \n");
    printf("   / _ | / |/ / _ \\                          \n");
    printf("  / __ |/    / // /                          \n");
    printf(" /_/_|_/_/|_/____/____________________  ___  \n");
    printf("   / _ \\/ __/_  __/ __/ ___/_  __/ __ \\/ _ \\ \n");
    printf("  / // / _/  / / / _// /__  / / / /_/ / , _/ \n");
    printf(" /____/___/ /_/ /___/\\___/ /_/  \\____/_/|_|  \n");
    printf("\nVersion: %s and the Tool version is 1.0.0\n", pcap_lib_version());
    printf("This tool is used to sniff the ARP packets and can possibly detect the ongoing ARP spoofing Attack in the interface, This tool is in beta stage. \n");
    printf("\n\nAuthor: M S Praveen Kumar\n");
    printf("Profile Link: https://www.praveenms.site\n");
    printf("Email: mspraveenkumar77@gmail.com\n");
    printf("Github Link: https://github.com/Praveenms13\n");
    printf("Tool link: https://github.com/Praveenms13/Exploit-Tools/blob/main/c/arp-sniffer-n-detector.c\n");
}
void printAlert()
{
}
char *get_mac_address(char *mac_addr, uint8_t mac[6])
{
    sprintf(mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return mac_addr;
}
char *get_ip_address(char *ip_addr, uint8_t ip[4])
{
    sprintf(ip_addr, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    return ip_addr;
}
void spoofAlert(char *ip, char *mac)
{
    char cmd[256];
    printf("Alert !!\n");
    sprintf(cmd, "/usr/bin/notify-send -t 5000 -i face-angry \"ARP Spoofing Detected. IP: %s and MAC: %s\"", ip, mac);
    system(cmd);
}
void spoofWelcome()
{
    char cmd[256];
    sprintf(cmd, "/usr/bin/notify-send -t 5000 -i face-angel \"I am Watching for ARP Spoofing. Sit Back and Relax.\"");
    printf("%s", cmd);
    system(cmd);
}
int sniffARP(char *interface)
{
    char *device_name = interface;
    pcap_t *pack_descr;
    char error[PCAP_ERRBUF_SIZE];
    const u_char *packet;
    struct pcap_pkthdr header;
    struct ether_header *eptr; // net/ethernet.h defined by pcap.h
    u_char *hard_ptr;
    arp_hdr *arpheader = NULL;
    char *sender_mac, *sender_ip, *target_mac, *target_ip;
    int counter = 0;
    time_t start, end;
    long int diff;

    pack_descr = pcap_open_live(device_name, BUFSIZ, 0, 1, error);
    if (pack_descr == NULL)
    {
        printf("Error Thrown: %s\n", error);
        print_available_interfaces();
        return -1;
    }
    printf("\nSniffing on %s..........\n\n", device_name);
    while (1)
    {
        packet = pcap_next(pack_descr, &header);
        if (packet == NULL)
        {
            printf("No packet captured.\n");
            return -1;
        }

        eptr = (struct ether_header *)packet;
        if (ntohs(eptr->ether_type) == ETHERTYPE_ARP)
        {
            start = time(NULL) / 3600; // will give epoch seconds
            diff = start - end;
            if (diff > 20)
            {
                counter = 0;
            }
            // 0x0806
            // Going 14 bytes ahead to get the ARP header which is 14 bytes ahead of the ethernet header(eptr = (struct ether_header *)packet;)
            arpheader = (arp_hdr *)(packet + 14);
            printf("--------------------==[ Packet Captured ]==--------------------\n");
            printf("Count: %d  Current-Time: %ld  Difference: %ld\n", counter, start, diff);
            printf("Recieved an ARP Packet of Length: %d\n", header.len);
            printf("Received at: %s", ctime((const time_t *)&header.ts.tv_sec));
            printf("Ether Header Length: %d\n", ETHER_HDR_LEN);
            printf("Operation Type: %s\n", (ntohs(arpheader->opcode) == ARP_REQUEST) ? "ARP Request" : "ARP Response");
            char mac_addr[20], ip_addr[20];
            sender_mac = get_mac_address(mac_addr, arpheader->sender_mac);
            sender_ip = get_ip_address(ip_addr, arpheader->sender_ip);
            target_mac = get_mac_address(mac_addr, arpheader->target_mac);
            target_ip = get_ip_address(ip_addr, arpheader->target_ip);
            printf("Sender MAC Address: %s\n", sender_mac);
            printf("Sender IP Address: %s\n", sender_ip);
            printf("Target MAC Address: %s\n", target_mac);
            printf("Target IP Address: %s\n", target_ip);
            printf("--------------------==[ End of Packet  ]==--------------------\n\n");
            counter++;
            end = time(NULL) / 3600; // will give epoch seconds
            if (counter > 10)
            {
                spoofAlert(sender_ip, sender_mac);
            }
        }
    }
}
int main(int argc, char *argv[])
{
    printf("___  ____________   ___________ _____  ___________ ___________  \n\n");
    spoofAlert("ip", "mac");
    if (access("/usr/bin/notify-send", F_OK) == -1)
    {
        print_version();
        printf("\n\nAlert: Can't send alerts\n");
        printf("Error: Please install notify-send to get the alerts\n");
        printf("Please Install the Dependencies by running: sudo apt install notify-send\n\n");
        exit(1);
    }
    if (argc < 2 || strcmp("-h", argv[1]) == 0 || strcmp("--help", argv[1]) == 0)
    {
        print_version();
        print_help(argv[0]);
        exit(1);
    }
    else if (strcmp("-v", argv[1]) == 0 || strcmp("--version", argv[1]) == 0)
    {
        print_version();
        exit(1);
    }
    else if (strcmp("-l", argv[1]) == 0 || strcmp("--lookup", argv[1]) == 0)
    {
        print_available_interfaces();
        exit(1);
    }
    else if (strcmp("-i", argv[1]) == 0 || strcmp("--interface", argv[1]) == 0)
    {
        if (argc < 3)
        {
            printf("--------------------------------------------------------------------------------\n");
            printf("Error: Please Specify the Interface to Sniff on. Select from the following.....\n");
            printf("--------------------------------------------------------------------------------\n\n");
            print_available_interfaces();
            printf("Usage: arpSniffer [OPTION]...\n");
            printf("Eg. %s -i < interface>[You can look for the available interfaces using -l (or) --lokup]\n", argv[0]);
        }
        else
        {
            sniffARP(argv[2]);
        }
    }
    else
    {
        printf("Invalid Arguement....\n");
        print_help(argv[0]);
    }
    printf("\n\n___  ____________   ___________ _____  ___________ ___________  \n");
    printf("End of Program\n");
    return 0;
}
