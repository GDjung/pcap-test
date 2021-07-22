#include<libnet.h>
#include<stdio.h>
#include<pcap.h>
#include<stdbool.h>
#include<arpa/inet.h>

#define SIZE_ETHERNET 14
#define SIZE_IPV4 20
#define SIZE_TCP 20

void tcp_capDump(struct pcap_pkthdr* header,const unsigned char* packet);
void print_eth(u_int8_t* shost,u_int8_t* dhost);
void print_hex(unsigned char *data,int size);
void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}


int main(int argc, char** argv) {

	if(argc != 2){
		usage();
		return -1;
	}
	
    char errbuf[PCAP_ERRBUF_SIZE];
    char* device = argv[1]; 
    pcap_t* pcap = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);

    if(!pcap) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n",device, errbuf);
		return -1;
	}

    while (true) {
		struct pcap_pkthdr* header;
		const unsigned char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
	
        tcp_capDump(header, packet);
		
	}
}


void tcp_capDump(struct pcap_pkthdr* header,const unsigned char* packet){
	
    struct libnet_ethernet_hdr *eth = (struct libnet_ethernet_hdr*)packet;
	struct libnet_ipv4_hdr *ipv4 = (struct libnet_ipv4_hdr*)(packet+SIZE_ETHERNET);
	struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr*)(packet+SIZE_ETHERNET+SIZE_IPV4);

	// 1. ethernet 
	if(ntohs(eth->ether_type) != ETHERTYPE_IP) //  ETHERTYPE_IP = 0x800
		return;
	print_eth(eth->ether_shost ,eth->ether_dhost); //print mac addr 

	
	// 2. IP
	puts("=================IP=================");
	printf("Src IP : %s\n",inet_ntoa(ipv4->ip_src));	//print ip addr
	printf("Dst IP : %s\n",inet_ntoa(ipv4->ip_dst));


	// 3. TCP
	puts("================TCP=================");
	printf("Src Port : %d\n",tcp->th_sport);
	printf("Dst Port : %d\n",tcp->th_dport);


	// 4. Payload(data)
	puts("================Data================");
	print_hex((unsigned char*)(packet+SIZE_ETHERNET+SIZE_IPV4),header->caplen-(SIZE_ETHERNET+SIZE_IPV4));
}


void print_hex(unsigned char *data,int size){
	printf("[Size : %d]  ",size);
	for(int i = 0 ; i < size ; i++)
	{
		if(i > 7)
			break;
		printf("%02x ",*(data+i));
		
	}
		
}

void print_eth(u_int8_t* shost,u_int8_t* dhost)
{
	puts("\n\n==============Ethernet===============");
	//print s_host
	printf("Src MAC : ");
	for(int i = 0 ; i < ETHER_ADDR_LEN ; i++) // ETHER_ADDR_LEN = 0x6
	{
		printf("%02x",shost[i]);
		if(i<ETHER_ADDR_LEN-1)
			printf(":");
	}
	//printf d_host
	printf("\nDst MAC : ");
	for(int i = 0 ; i < ETHER_ADDR_LEN ; i++) // ETHER_ADDR_LEN = 0x6
	{
		printf("%02x",dhost[i]);
		if(i<ETHER_ADDR_LEN-1)
			printf(":");
	}
	printf("\n");
}
