#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include "Diffie_hellman.h"

#define MAXBYTES2CAPTURE 2048

typedef struct{
	unsigned char client_ip[16];
	unsigned char server_ip[16];
	pcap_t *p;
}ip_rule;
struct psd_header{ 
	unsigned int saddr;
	unsigned int daddr;
	char mbz;
	char ptcl;
	unsigned short tcpl;
};
uint16_t calc_cksm(void *pkt, int len) { 
	uint16_t *buf = (uint16_t*)pkt;
	uint32_t cksm = 0; 
	while (len > 1) { 
		cksm += *buf++; 
		cksm = (cksm >> 16) + (cksm & 0xffff); 
		len -= 2; 
	} if (len) { 
		cksm += *((uint8_t*)buf); 
		cksm = (cksm >> 16) + (cksm & 0xffff); 
	} 
	return (uint16_t)((~cksm) & 0xffff); 
}
void set_psdheader(struct psd_header* ph,struct iphdr *ip, uint16_t tl){
	ph->saddr=ip->saddr;
	ph->daddr=ip->daddr;
	ph->mbz=0;
	ph->ptcl=6;
	ph->tcpl=htons(tl);
}
Mim_key dh_key;
/* processPacket(): Callback function called by pcap_loop() everytime a packet */
/* arrives to the network card. This function prints the captured raw data in  */
/* hexadecimal.                                                                */
void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet){
	unsigned char server_mac[]={0x00,0x0c,0x29,0x9a,0xa4,0xba};
	unsigned char client_mac[]={0x00,0x0c,0x29,0x19,0xe5,0x73};
	unsigned char my_mac[]={0x00,0x0c,0x29,0x65,0x27,0xb3};
	
	struct ether_header *ethernet;
	struct iphdr *ip;
	struct tcphdr *tcp;
	
	char srcip_str[16];
	memset(srcip_str,0,16);
	ip_rule * ip_r=(ip_rule*)arg;

	ethernet = (struct ether_header*)(packet);  //ethernet header
	ip = (struct iphdr*)(packet + ETHER_HDR_LEN);   //ip head
	tcp = (struct tcphdr*)(packet + ETHER_HDR_LEN+ sizeof(struct iphdr));   //tcp head
	
	int hdr_len=ETHER_HDR_LEN+sizeof(struct iphdr)+sizeof(struct tcphdr)+12;
	int dl=pkthdr->len-hdr_len;
	
	inet_ntop(AF_INET,&(ip->saddr),srcip_str,16);
	//src mac
	memcpy(ethernet->ether_shost,my_mac,6);

	if(strncmp(srcip_str, ip_r->client_ip, strlen(srcip_str))==0){
		//client
		if(strncmp(packet+hdr_len,"pub",3)==0){
			//generate private key T
			generate_key(32,&dh_key);
			mpz_t key_from_c;
			mpz_init(key_from_c);
			mpz_set_str(key_from_c,packet+hdr_len+3,16);
			//g^(at)
			mpz_powm(dh_key.key_for_client, key_from_c, dh_key.private_key, dh_key.prime);
			//T=g^(t)
			mpz_powm(dh_key.public_key, dh_key.base, dh_key.private_key, dh_key.prime);			
			//send T to server
			memcpy(ethernet->ether_dhost,server_mac,6);
			//T->char*
			unsigned char pub[64];
			mpz_get_str(pub,16,dh_key.public_key);
			memcpy(packet+hdr_len+3,pub,sizeof(pub));
			//recalculate the checksum
			uint16_t tcp_len =pkthdr->len-ETHER_HDR_LEN-sizeof(struct iphdr);
			unsigned char * data_for_checksum=(unsigned char*)malloc(tcp_len+sizeof(struct psd_header));	
			struct psd_header ph;
			bzero(data_for_checksum, tcp_len+sizeof(ph));
			set_psdheader(&ph, ip, tcp_len);
			memcpy(data_for_checksum, (void*)(&ph), sizeof(ph));
			tcp->check=0;
			memcpy(data_for_checksum+sizeof(ph), tcp, tcp_len);
			uint16_t cs=calc_cksm(data_for_checksum, tcp_len+sizeof(ph));
			tcp->check=cs;

		}else if(strncmp(packet+hdr_len,"data",4)==0){
			//decrypt
			char *buff=packet+hdr_len;
			char *plain=(char*)malloc(dl-48);
			bzero(plain, sizeof(buff));
			char key_string[128],key_value[32];
			mpz_get_str(key_string, 16, dh_key.key_for_client);
			memcpy(key_value, str2hex(key_string), sizeof(key_value));
			//add(16)+iv(12)+tag(16)+data
			unsigned char iv[12],add[16],tag[16];
			memcpy(add,buff+4,16);
			memcpy(iv,buff+16+4,12);
			memset(tag,0,16);
			int tmp=aes_gcm_ad(key_value, 32,iv, 12,buff+44+4, dl-44-4,add, 16,tag, plain);
			
			//encrypt
			bzero(key_string, sizeof(key_string));
			mpz_get_str(key_string, 16, dh_key.key_for_server);
			memcpy(key_value, str2hex(key_string), sizeof(key_value));
			tmp=aes_gcm_ae(key_value, 32,iv,12,plain,dl-48,add, 16,buff+44+4, tag);
			//recalculate the checksum
			uint16_t tcp_len =pkthdr->len-ETHER_HDR_LEN-sizeof(struct iphdr);
			unsigned char * data_for_checksum=(unsigned char*)malloc(tcp_len+sizeof(struct psd_header));	
			struct psd_header ph;
			bzero(data_for_checksum, tcp_len+sizeof(ph));
			set_psdheader(&ph, ip, tcp_len);
			memcpy(data_for_checksum, (void*)(&ph), sizeof(ph));
			tcp->check=0;
			memcpy(data_for_checksum+sizeof(ph), tcp, tcp_len);
			uint16_t cs=calc_cksm(data_for_checksum, tcp_len+sizeof(ph));
			tcp->check=cs;
		}
		memcpy(ethernet->ether_dhost,server_mac,6);			
	}else{
		//server
		if(strncmp(packet+hdr_len,"pri",3)==0){
			mpz_set_str(dh_key.prime, packet+hdr_len+3, 16);
		}else if(strncmp(packet+hdr_len,"pub",3)==0){
			mpz_t key_from_s;
			mpz_init(key_from_s);
			mpz_set_str(key_from_s,packet+hdr_len+3,16);
			//g^(bt)
			mpz_powm(dh_key.key_for_server, key_from_s, dh_key.private_key, dh_key.prime);
			unsigned char pub[64];
			mpz_get_str(pub,16,dh_key.public_key);
			memcpy(packet+hdr_len+3,pub,sizeof(pub));
			//recalculate the checksum
			uint16_t tcp_len =pkthdr->len-ETHER_HDR_LEN-sizeof(struct iphdr);
			unsigned char * data_for_checksum=(unsigned char*)malloc(tcp_len+sizeof(struct psd_header));	
			struct psd_header ph;			
			bzero(data_for_checksum, tcp_len+sizeof(ph));
			set_psdheader(&ph, ip, tcp_len);			
			memcpy(data_for_checksum, (void*)(&ph), sizeof(ph));
			tcp->check=0;
			memcpy(data_for_checksum+sizeof(ph), tcp, tcp_len);
			unsigned short cs=calc_cksm(data_for_checksum, tcp_len+sizeof(ph));
			tcp->check=cs;
		}else if(strncmp(packet+hdr_len,"data",4)==0){
			//decrypt
			char *buff=packet+hdr_len;
			char *plain=(char*)malloc(dl-48);
			bzero(plain, sizeof(buff));
			char key_string[128],key_value[32];
			mpz_get_str(key_string, 16, dh_key.key_for_server);
			memcpy(key_value, str2hex(key_string), sizeof(key_value));
			//add(16)+iv(12)+tag(16)+data
			unsigned char iv[12],add[16],tag[16];
			memcpy(add,buff+4,16);
			memcpy(iv,buff+16+4,12);
			memset(tag,0,16);
			int tmp=aes_gcm_ad(key_value, 32,iv, 12,buff+44+4, dl-44-4,add, 16,tag, plain);
			printf("[server]%s",plain);
			//encrypt
			bzero(key_string, sizeof(key_string));
			mpz_get_str(key_string, 16, dh_key.key_for_client);
			memcpy(key_value, str2hex(key_string), sizeof(key_value));
			tmp=aes_gcm_ae(key_value, 32,iv,12,plain,dl-48,add, 16,buff+44+4, tag);
			//recalculate the checksum
			uint16_t tcp_len =pkthdr->len-ETHER_HDR_LEN-sizeof(struct iphdr);
			unsigned char * data_for_checksum=(unsigned char*)malloc(tcp_len+sizeof(struct psd_header));	
			struct psd_header ph;
			bzero(data_for_checksum, tcp_len+sizeof(ph));
			set_psdheader(&ph, ip, tcp_len);
			memcpy(data_for_checksum, (void*)(&ph), sizeof(ph));
			tcp->check=0;
			memcpy(data_for_checksum+sizeof(ph), tcp, tcp_len);
			uint16_t cs=calc_cksm(data_for_checksum, tcp_len+sizeof(ph));
			tcp->check=cs;
		}
		memcpy(ethernet->ether_dhost,client_mac,6);			
	}
	pcap_sendpacket(ip_r->p,packet,pkthdr->len);
	return;
}

/* main(): Main function. Opens network interface and calls pcap_loop() */
int main(int argc, char *argv[] ){
	if(argc!=3){
		puts("./main client_ip server_ip");
		return 0;
	}
	int i=0, count=0;
	pcap_t *descr = NULL;
	char errbuf[PCAP_ERRBUF_SIZE], *device=NULL;
	memset(errbuf,0,PCAP_ERRBUF_SIZE);
    struct bpf_program filter;  //packet filter
	init_numbers(&dh_key);
    mpz_set_ui(dh_key.base, (unsigned long)2);	
	dh_key.urand = fopen("/dev/urandom","r");
	// Get the name of the first device suitable for capture
	if ( (device = pcap_lookupdev(errbuf)) == NULL){
		fprintf(stderr, "ERROR: %s\n", errbuf);
		exit(1);
	}
	printf("Opening device %s\n", device);
	//Open device in promiscuous mode
	if ( (descr = pcap_open_live(device, MAXBYTES2CAPTURE, 1,  512, errbuf)) == NULL){
		fprintf(stderr, "ERROR: %s\n", errbuf);
		exit(1);
	}
    //set filter src dest host
	char rule[128];
	memset(rule,0,128);
	strncat(rule,"(src host ",10);
	strncat(rule,argv[1],strlen(argv[1]));
	strncat(rule," and dst host ",14);
	strncat(rule,argv[2],strlen(argv[2]));
	strncat(rule,") or (src host ",15);
	strncat(rule,argv[2],strlen(argv[2]));
	strncat(rule," and dst host ",14);
	strncat(rule,argv[1],strlen(argv[1]));
	strncat(rule, ")", 1);
    if(pcap_compile(descr,&filter,rule,1,0)<0){
        printf("error\n");
        return 0;
    }
    if(pcap_setfilter(descr,&filter)<0){
        printf("error\n");
        return 0;
    }
	ip_rule ip_r;
	ip_r.p=descr;
	memset(ip_r.client_ip,0,15);
	memcpy(ip_r.client_ip, argv[1],strlen(argv[1]));
	memset(ip_r.server_ip,0,15);
	memcpy(ip_r.server_ip, argv[2],strlen(argv[2]));
	//Loop forever & call processPacket() for every received packet
	if ( pcap_loop(descr, -1, processPacket, (u_char *)&ip_r) == -1){
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
		exit(1);
	}
	return 0;
}

