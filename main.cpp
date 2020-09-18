#include<pcap.h>
#include<stdio.h>
#include <arpa/inet.h>
#include<libnet.h>
#include<stdint.h>

struct eth_addr{
    u_char ether_addr[6];
};
struct ip_addr{
    u_char ip_addr[4];
};
struct eth_hdr{
    struct eth_addr src;
    struct eth_addr dst;
};
struct ip_hdr{
    u_char no_need[12];
    struct ip_addr src;
    struct ip_addr dst;
};
struct tcp_hdr{
    char src_port[2];
    char dst_port[2];
    u_char no_need[20];
    u_char data[16];
};
void print_tcp(const u_char *packet){
    struct tcp_hdr *tcp;
    tcp = (struct tcp_hdr *)packet;

    printf("src packet : %d\n",tcp->src_port);
    printf("dst packet : %d\n",tcp->dst_port);
    printf("data : %s\n",tcp->data);
}
void print_ip(const u_char *packet){
    struct ip_hdr *ip;
    ip = (struct ip_hdr *)packet;

    printf("src addr : ");
    for(int i=0;i<4;i++){
        printf("%d",ip->src.ip_addr[i]);
        if(i!=3)printf(".");
        else printf("\n");
    }
    printf("dst addr : ");
    for(int i=0;i<4;i++){
        printf("%d",ip->dst.ip_addr[i]);
        if(i!=3)printf(".");
        else printf("\n");
    }
    printf("\n");
}
void print_eth(const u_char *packet){
    struct eth_hdr *eth;
    eth = (struct eth_hdr *)packet;

    printf("src addr : ");
    for(int i =0;i<6;i++){
        printf("%02x",eth->src.ether_addr[i]);
        if(i!=5) printf(":");
        else printf("\n");
    }
    printf("dst addr : ");
    for(int i =0;i<6;i++){
        printf("%02x",eth->dst.ether_addr[i]);
        if(i!=5) printf(":");
        else printf("\n");
    }
    printf("\n");
}

int main(int argc, char* argv[]){
    //if input error
    if(argc !=2){ 
        printf("invalid input");
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev,BUFSIZ, 1,1000,errbuf);
    if(handle == nullptr){
        fprintf(stderr,"NO nullpointer");
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
        if(packet[23] == 6){
            printf("----------------------------\n");
        print_eth(packet);
        packet+=14;
        print_ip(packet);
        packet +=20;
        print_tcp(packet);
        printf("----------------------------\n\n");
        }
    }
    pcap_close(handle);
}
