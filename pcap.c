#include "header.h"

void ex() 
{
  printf("./pcap [device name]\n");
  printf("ex) ./pcap ens37\n");
}

int main(int argc, char* argv[]) 
{

  if (argc != 2) 
  {
    ex();
    return -1;
  }

  char error[PCAP_ERRBUF_SIZE];
  char* dev = argv[1];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, error);

  if (handle == NULL) 
  {
    fprintf(stderr, "device isn't open %s: %s\n", dev, error);
    return -1;
  }

  while (true) 
  {

    struct pcap_pkthdr* header;
    // u == unsigned

    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);

    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    //Modify below codes
    //DO NOT CHEAT IT !!

    printf("\n%u bytes captured\n", header->caplen);
    //mac src, dst : 6bytes

    ETHER_HDR *ens;
    ens = (struct ethernet_header *)packet;
    int l3_protocol = ntohs(ens->type);

    printf("Source_MAC        - %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",ens->source[0] , ens->source[1] , ens->source[2] , ens->source[3] , ens->source[4] , ens->source[5]);

    printf("Destination_MAC   - %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",ens->dest[0] , ens->dest[1] , ens->dest[2] , ens->dest[3] , ens->dest[4] , ens->dest[5]);

    printf("L3 protocol       - 0x%.4x \n" , l3_protocol );

    //verify upper layer
    //ip src, dst : 4bytes  && hex to ip   
    if(l3_protocol==0x0800)
    {
        IPV4_HDR *iph;
        iph = (struct ip_hdr *)(packet+sizeof(struct ethernet_header));
        int l4_protocol = iph->protocol_id;
        char ip_length = iph->header_len;

        printf("Source_IP         - %s\n", inet_ntoa(iph->ip_srcaddr));
        printf("Destination_IP    - %s\n", inet_ntoa(iph->ip_dstaddr));
        printf("L4 Protocol       - 0x%x\n",l4_protocol);
    
        //verify upper layer
        //tcp src, dst : 2bytes && hex to decimal

        if(l4_protocol==0x06)
	{
            TCP_HDR *tcph;
            tcph = (struct tcp_hdr *)(packet+sizeof(struct ethernet_header)+ip_length*4);
            int tcph_size = tcph->header_len1*4;
            //printf("%u %lu",header->caplen,sizeof(struct ethernet_header)+sizeof(struct ip_hdr)+sizeof(struct tcp_hdr));
            
            printf("Source_Port       - %d\n", ntohs(tcph->tcp_srcport));
            printf("Destination_Port  - %d\n", ntohs(tcph->tcp_dstport));
            
            if(sizeof(struct ethernet_header)+ip_length*4+tcph_size < header->caplen)
	   {
                TCP_PAY *tcpp;
                tcpp = (struct tcp_payload *)(packet+sizeof(struct ethernet_header)+ip_length*4+tcph_size);
                printf("Data         - ");

                for(int i=0;i<16;i++)
                    printf("%.2X", tcpp->data[i]);
                printf("\n");
            }
        }

        else
            printf("It's not following TCP Protocol\n");
    }

    else
        printf("It's not following IP Protocol\n");

  }

  pcap_close(handle);
  return 0;
}

