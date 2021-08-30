#include<cstdio>
#include<pcap.h>
#include"ethhdr.h"
#include"arphdr.h"
#include"plus.h"

#include<string>
#include<iostream>

void GetAddrs(char * _dev, std::string & _my_IP, std::string & _my_mac)
{

	int sock;
	struct ifreq ifr;
	
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	
	strncpy((char*)ifr.ifr_name, _dev, IFNAMSIZ - 1);

	
	//uint32_t ip;
	char ipstr[40];
	if(ioctl(sock,SIOCGIFADDR, &ifr) < 0)
	{
		printf("Socket Error, IP");
	}
	else
	{
		inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr, sizeof(struct sockaddr));
		//ip = ntohl(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr);
	}


	//std::cout << ip << std::endl;
	//_my_IP = std::string((char*)ip);
	_my_IP = std::string(ipstr);
	std::cout <<"my IP : " << _my_IP << std::endl;
	
	char macstr[40];
	uint8_t my_mac_func[6];
	
	//Mac mac;
	if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
	{
		printf("Socket Error, MAC");
	}
	else
	{
		//macstr = ether_ntoa(AF_INET, ifr.ifr_addr.sa_data);
		memcpy(my_mac_func, ifr.ifr_addr.sa_data, 6);
		sprintf(macstr, "%02X:%02X:%02X:%02X:%02X:%02X", my_mac_func[0], my_mac_func[1], my_mac_func[2], my_mac_func[3], my_mac_func[4], my_mac_func[5]);
		//my_mac_func = (uint8_t*)ifr.ifr_hwaddr.sa_data;
	}
	
	close(sock);
	
	//std::cout << mac << std::endl;
	

	
	_my_mac = std::string(macstr);
	std::cout <<"my mac : " << _my_mac << std::endl;

	
}
