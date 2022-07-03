#include <stdint.h>
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
#include <utility>
#include <string>
#include <vector>

#define MAC_SIZE 6
struct Radiotap_hdr{
    uint8_t hdr_rev;
    uint8_t hdr_pad;
    uint16_t hdr_len;
    uint64_t present_flag;
    uint64_t MAC_timestamp;
    uint8_t flag;
    uint8_t data_rate;
    uint16_t chnl_freq;
    uint16_t chnl_flag;
    uint8_t ant_sig0;
    uint16_t RX_flag;
    uint8_t ant_sig1;
    uint8_t ant;
};

struct Beacon_Frame{
    uint8_t FCF[2];         //Frame Control Field : 2byte
    uint16_t Dur;         //Duration : 2byte
    uint8_t Brdcast[6];   // Destination Mac Address : 6byte
    uint8_t MAC[6];   //Source Mac Address : 6byte
    uint8_t BSSID[6];     // BSSID : 6byte
    uint16_t frag_num;    //fragment number
};

struct Wireless_mgmt{
    uint16_t fixed[6];
    uint8_t tag1_num;
    uint8_t tag1_len;
    char SSID[20];

};

