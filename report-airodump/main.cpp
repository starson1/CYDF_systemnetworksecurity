#include "main.h"

using namespace std;
vector <pair<string,int>> beacon_list;
pcap_t* handle;

int print_frame(pcap_t* handle,uint8_t* packet){
    struct Radiotap_hdr* radio_hdr = (struct Radiotap_hdr*)packet;
    struct Beacon_Frame* beacon = (struct Beacon_Frame*)(packet+radio_hdr->hdr_len);
    struct Wireless_mgmt* w_mgmt = (struct Wireless_mgmt*)(packet+radio_hdr->hdr_len+sizeof(struct Beacon_Frame));
    
    if(beacon->FCF[0] != 0x80){
        printf("Not A Beacon Frame!\n\n");
        return 0;
    }
    //BSSID
    printf("BSSID : ");
    for(int i=0;i<MAC_SIZE-1;i++){
        printf("%02x:",beacon->BSSID[i]);
    }
    printf("%02x\n",beacon->BSSID[5]);

    //ESSID
    printf("SSID :");
    for(int i=0;i<w_mgmt->tag1_len;i++){
        printf("%c",w_mgmt->SSID[i]);
    }
    printf("\n");
    char* ssid = w_mgmt->SSID;
    //BEACON
    //calc Beacon_list
    
    int flag =1;
    for(int i=0;i<beacon_list.size();i++){
        
        if(!strncmp((char*)w_mgmt->SSID,beacon_list[i].first.c_str(),sizeof(beacon_list[i].first.c_str()))){
            beacon_list[i].second +=1;
            printf("BEACON : %d\n",beacon_list[i].second);
            flag =0;
            break;
        }
    }
    
    if(flag){
        pair<string,int> p = make_pair(ssid,0);
        beacon_list.push_back(p);
        printf("BEACON : 0\n");
    }
    
    //PWR
    printf("PWR : %d dBm\n",radio_hdr->ant_sig1);
    printf("\n");
    
    return 1;
}

void usage(){
    cout << "syntax : airodump <interface>"<<endl;
    cout << "sample : airodump mon0"<<endl;
}
int main(int argc, char* argv[]){
    //if input error
    if(argc !=2){ 
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }
    //packet caputure
     while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        print_frame(handle,(uint8_t*)packet);
    }
    
    pcap_close(handle);
}
