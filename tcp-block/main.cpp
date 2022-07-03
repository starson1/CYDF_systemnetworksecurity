#include <pcap.h>
#include <iostream>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <stdlib.h>
#include <libnet.h>
#include <stdint.h>
#include <string.h>

using namespace std;

#define FD 0
#define BK 1
char* keyword;
uint8_t attk_mac[6];
const char* alert = "blocked!!!";
struct tmp_header{
    struct in_addr s_addr;
	struct in_addr d_addr;
	uint8_t padding=0;
	uint8_t ip_p;
	uint16_t tcp_len;
};


void usage(){
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}
int get_mac(uint8_t* attk_mac){
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1){
        return 0;
    };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
        close(sock);
        return 0;
    }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) {
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else {
            close(sock);
            return 0;
        }
    }

    if (success){
        memcpy(attk_mac, ifr.ifr_hwaddr.sa_data, 6);
        close(sock);
        return 1;
    }
    else{
        close(sock);
        return 0;
    }
}
void get_checksum(uint16_t sum, uint16_t* header, int size){
    sum = 0;
	while(size >1) { 
		sum += *header++;
		size -= sizeof(uint16_t);
	} 
	if(size) sum += *(uint16_t*)header;
	sum = (sum >> 16) + (sum & 0xffff); 
	sum += (sum >>16); 
	sum = ~sum;
}
void set_pkt(int flag,uint8_t* packet, uint32_t seq, uint32_t ack){
    struct libnet_ethernet_hdr* ether = (struct libnet_ethernet_hdr*)packet;
    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)(packet+sizeof(struct libnet_ethernet_hdr));
    struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)(packet+sizeof(struct libnet_ipv4_hdr));
    
    struct tmp_header* tmp_hdr;
    //set packet -> basic  : BK == FD
    tmp_hdr->s_addr = ip->ip_src;
    tmp_hdr->d_addr = ip->ip_dst;
    tmp_hdr->ip_p = ip->ip_p;
    tmp_hdr->tcp_len = tcp->th_off*4;
    int data_size = sizeof(struct tmp_header) + tcp->th_off*4;
    uint16_t* checksum = (uint16_t*)malloc(data_size);
    memcpy(checksum,tmp_hdr,sizeof(struct tmp_header));
    memcpy(checksum+sizeof(struct tmp_header),tcp,tcp->th_off*4);
    get_mac(attk_mac);
    if(flag == BK){
        //change addr
        for(int i=0;i<6;i++){
            ether->ether_dhost[i] = ether->ether_shost[i];
            ether->ether_shost[i] = attk_mac[i];
        }
        //change info
        uint32_t iptmp = ip->ip_dst.s_addr;
        ip->ip_dst.s_addr = ip->ip_src.s_addr;
        ip->ip_src.s_addr = iptmp;
        uint16_t ptmp = tcp->th_dport;
        tcp->th_dport = tcp->th_sport;
        tcp->th_sport = ptmp;
    }
    //set packet -> content RST
    //ip : BK == FD
    ip->ip_tos = 0x01;
    ip->ip_len = htons(ip->ip_hl*4 + tcp->th_off*4);
    ip->ip_ttl = 0xff;
    ip->ip_sum = 0;
    get_checksum(ip->ip_sum,(uint16_t*)ip,ip->ip_hl*4);
    //tcp
    tcp->th_seq = seq;
    tcp->th_ack = ack;
    tcp->th_flags = 0;
    if(flag ==FD)tcp->th_flags = TH_RST;
    else if(flag==BK)tcp->th_flags = TH_FIN;
    tcp->th_flags = TH_ACK;
    tcp->th_win = 0;
    tcp->th_sum = 0;
    tcp->th_urp = 0;
    if(flag == BK){
        // set message
        uint8_t* data = (uint8_t*)tcp + tcp->th_off*4;
        strncpy((char*)data,(char*)alert,8);
    }
    get_checksum(tcp->th_sum,checksum,data_size);
    free(checksum);  
}
void block(pcap_t* handle, uint8_t* packet, int pkt_size,uint32_t seq,uint32_t ack,uint32_t header_len,uint32_t data_len){
    uint8_t fd_packet[1500]={0,};
    uint8_t bk_packet[1500]={0,};

    memcpy(fd_packet,packet,pkt_size); //RST
    memcpy(bk_packet,packet,pkt_size); // FIN
    //FD == 0, BK == 1 FLAG
    set_pkt(FD,fd_packet,htonl(ntohl(seq)+data_len),ack);
    set_pkt(BK,fd_packet,ack,htonl(ntohl(seq)+data_len));

    pcap_inject(handle,fd_packet,header_len);
    pcap_inject(handle,bk_packet,header_len);

}
int filter_packet(uint8_t* packet, pcap_t* handle){
    //패킷 분석
    //1. 패킷 사이즈를 알아서 데이터 사이즈 분리 해야함.
    struct libnet_ethernet_hdr* ether = (struct libnet_ethernet_hdr*)packet;
    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)(ether+1);
    struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)((uint8_t*)ip+(ip->ip_hl*4));
    int pkt_size = 0;
    if(IPPROTO_TCP != ip->ip_p){ // protocol not match
        return 0;
    }
    
    int tcp_len = tcp->th_off*4;
    uint32_t data_len = ntohs(ip->ip_len)+(ip->ip_hl+tcp_len);
    uint32_t header_len = sizeof(struct libnet_ethernet_hdr)+(ip->ip_hl*4)+tcp_len;
    uint8_t* pdata = (uint8_t*)tcp + tcp->th_off*4; // data 영역
    pkt_size = (int)header_len+(int)data_len;
    if(data_len < 0){ // no data
        return 0;
    }
    else{
        for(int i=0;i<data_len;i++){
            if(strncmp((char*)pdata,keyword,strlen(keyword)) == 0){
                
                uint32_t header = sizeof(struct libnet_ethernet_hdr)+ip->ip_hl + tcp_len;
                uint32_t seq = tcp->th_seq;
                uint32_t ack = tcp->th_ack;

                printf("Filtering Target : %s",keyword);
                block(handle,packet,pkt_size,seq,ack,header_len,data_len);
                break;
            }
        }
    }
    return 0;
}


int main(int argc, char* argv[]){
    //if input error
    if(argc !=3){ 
        usage();
        return -1;
    }

    char *dev = argv[1];
    keyword = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev,BUFSIZ, 1,1000,errbuf);
    if(handle == NULL){
        fprintf(stderr,"Fail.. NULL POINTER \n-> %s: %s\n",dev,errbuf);
        return -1;
    }
    //packet caputure
    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
    
        filter_packet((uint8_t*)packet,handle);
        pcap_close(handle);
    }
}
