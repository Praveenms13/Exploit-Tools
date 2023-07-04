#include "stdio.h"
#include "stdlib.h"
#include "pcap.h"
int main()
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
        printf("#%d. %s - %s\n", ++i, temp->name, temp->description);
    }
    return 0;
}