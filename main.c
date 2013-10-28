/*
  
  whoisrunning

  whoisrunning is a minimal DNS-SD and mDNS client that takes a service type
  as its argument and returns the IPv4 and/or IPv6 addreses and port numbers
  running a service of the type.

  Usage: whoisrunning <service_type>
  
  License: GPLv3
  Author: juul@sudomesh.org
  Copyright Marc Juul Christoffersen 2013.

  References:

  DNS RFC: http://tools.ietf.org/html/rfc1035
    Section 4.1, 3.2.2 and 3.2.4

  DNS Security Extensions RFC: http://tools.ietf.org/html/rfc2535
    Section 6.1

  mDNS RFC: http://tools.ietf.org/html/rfc6762
    Section 18.

  DNS-SD RFC: http://tools.ietf.org/html/rfc6763
        
*/

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>

#define PROGRAM_NAME "mdnssd"
#define DNS_HEADER_SIZE (12)
#define DNS_MAX_HOSTNAME_LENGTH (253)
#define DNS_MAX_LABEL_LENGTH (63)
#define MDNS_MULTICAST_ADDRESS "224.0.0.251"
#define MDNS_PORT (5353)
#define DNS_BUFFER_SIZE (32768)

// TODO find the right number for this
#define DNS_MESSAGE_MAX_SIZE (4096)

struct mDNSPacketStruct{
  uint16_t id;
  uint16_t flags;
  uint16_t qd_count;
  uint16_t an_count;
  uint16_t ns_count;
  uint16_t ar_count;
  char* data;
  size_t data_size;
} __attribute__((__packed__)); // ensure that struct is packed
typedef struct mDNSPacketStruct mDNSPacket;

typedef struct {
  int qr;
  int opcode;
  int aa;
  int tc;
  int rd;
  int ra;
  int zero;
  int ad;
  int cd;
  int rcode;
} mDNSFlags;

typedef struct {
  char* qname;
  uint16_t qtype;
  uint16_t qclass;
  int prefer_unicast_response;
} mDNSQuestion;


void usage(char* argv0) {
  fprintf(stderr, "Usage: %s <hostname.local>\n", argv0);
}

void fail(char* msg) {
  //  fprintf(stderr, "Error: %s\n", msg);
  perror(msg);
  exit(1);
}

// parse and sanitize hostname
// TODO rewrite this based on notes in RFC6763 secion 4.1.1
char* parse_hostname(char* hostname) {
  // TODO ensure that hostnames have
  // at most 127 levels
  // labels with 1 to 63 octets
  char* result;
  int i;
  int hostname_length = strlen(hostname);
  if((hostname_length < 1) || (hostname_length > DNS_MAX_HOSTNAME_LENGTH)) {
    return NULL;
  }
  result = malloc(hostname_length);
  if(!result) {
    fail("failed to allocate memory for parsed hostname");
  }
  
  for(i=0; i < hostname_length; i++) {
    
    if(hostname[i] == '.') { // dot
      result[i] = 0x05;
    } else if((hostname[i] == 0x05) || // alternative to dot
            (hostname[i] == '-') || // dash
            ((hostname[i] >= 48) && (hostname[i] <= 57)) || // numeric 0-9
            ((hostname[i] >= 97) && (hostname[i] <= 122))) { // lower case letters a-z
      
      result[i] = hostname[i];
    } else {
      free(result);
      return NULL;
    }
  }
  return result;
}

mDNSPacket* mdns_make_packet() {
  mDNSPacket* packet = malloc(sizeof(mDNSPacket));
  if(!packet) {
    fail("failed to allocate memory for packet");
  }
  return packet;
}

// expects host byte_order
mDNSFlags* mdns_parse_header_flags(uint16_t data) {
  mDNSFlags* flags = malloc(sizeof(mDNSFlags));
  if(!flags) {
    fail("could not allocate memory for parsing header flags");
  }
  flags->rcode = data & 0xf;
  flags->cd = (data >> 4) & 1;
  flags->ad = (data >> 5) & 1;
  flags->zero = (data >> 6) & 1;
  flags->ra = (data >> 7) & 1;
  flags->rd = (data >> 8) & 1;
  flags->tc = (data >> 9) & 1;
  flags->aa = (data >> 10) & 1;
  flags->opcode = (data >> 14) & 0xf;
  flags->qr = (data >> 15) & 1;

  return flags;
}

// outputs host byte order
uint16_t mdns_pack_header_flags(mDNSFlags flags) {
  uint16_t packed = 0;
  
  packed |= (flags.rcode & 0xfff0);
  packed |= (flags.cd & 0xfffe) << 4; 
  packed |= (flags.ad & 0xfffe) << 5; 
  packed |= (flags.zero & 0xfffe) << 6; 
  packed |= (flags.ra & 0xfffe) << 7;
  packed |= (flags.rd & 0xfffe) << 8;
  packed |= (flags.tc & 0xfffe) << 9;
  packed |= (flags.aa & 0xfffe) << 10;
  packed |= (flags.opcode & 0xfff0) << 14;
  packed |= (flags.qr & 0xfffe) << 15;

  return packed;
}

char* mdns_pack_question(mDNSQuestion* q, size_t* size) {
  char* packed;
  size_t name_length;
  uint16_t qtype;
  uint16_t qclass;

  
  name_length = strlen(q->qname);
  if(name_length > DNS_MAX_HOSTNAME_LENGTH) {
    fail("domain name too long");
  }

  printf("name length: %u\n", name_length);

  *size = name_length + 1 + 2 + 2;

  // 1 char for terminating \0, 2 for qtype and 2 for qclass
  packed = malloc(*size);
  if(!packed) {
    fail("could not allocate memory for DNS question");
  }
  
  memcpy(packed, q->qname, name_length);
  packed[name_length] = '\0';

  // The top bit of the qclass field is repurposed by mDNS
  // to indicate that a unicast response is preferred
  // See RFC 6762 section 5.4
  if(q->prefer_unicast_response) {
    q->qclass |= 1 << 15;
  }

  qtype = htons(q->qtype);
  qclass = htons(q->qclass);

  memcpy(packed + name_length + 1, &qtype, 2);
  memcpy(packed + name_length + 3, &qclass, 2);

  return packed;
}


void mdns_packet_print(mDNSPacket* packet) {

  mDNSFlags* flags = mdns_parse_header_flags(packet->flags);

  printf("ID: %u\n", packet->id);
  printf("Flags: \n");
  printf("      QR: %u\n", flags->qr);
  printf("  OPCODE: %u\n", flags->opcode);
  printf("      AA: %u\n", flags->aa);
  printf("      TC: %u\n", flags->tc);
  printf("      RD: %u\n", flags->rd);
  printf("      RA: %u\n", flags->ra);
  printf("       Z: %u\n", flags->zero);
  printf("      AD: %u\n", flags->ad);
  printf("      CD: %u\n", flags->cd);
  printf("   RCODE: %u\n", flags->rcode);
  printf("\n");
  printf("QDCOUNT: %u\n", packet->qd_count);
  printf("ANCOUNT: %u\n", packet->an_count);
  printf("NSCOUNT: %u\n", packet->ns_count);
  printf("ARCOUNT: %u\n", packet->ar_count);
  printf("Data: %s\n",packet->data);

  free(flags);
}

// TODO this only parses the header so far
int mdns_parse_packet_net(char* data, mDNSPacket* packet) {

  memcpy(packet, data, DNS_HEADER_SIZE);
  packet->id = ntohs(packet->id);
  packet->flags = ntohs(packet->flags);
  packet->qd_count = ntohs(packet->qd_count);
  packet->an_count = ntohs(packet->an_count);
  packet->ns_count = ntohs(packet->ns_count);
  packet->ar_count = ntohs(packet->ar_count);

  // TODO use memcpy
  packet->data = data+DNS_HEADER_SIZE;

  // TODO actually parse the rest of message and find real parse size
  return 100;
}

mDNSPacket* mdns_build_query_packet(char* hostname) {
  mDNSPacket* packet = mdns_make_packet();
  mDNSQuestion question;
  mDNSFlags flags;

  flags.qr = 0; // this is a query
  flags.opcode = 0; // opcode must be 0 for multicast
  flags.aa = 0; // must be 0 for queries
  flags.tc = 0; // no (more) known-answer records coming
  flags.rd = 0; // must be 0 for multicast
  flags.ra = 0; // must be 0 for multicast
  flags.zero = 0; // must be zero
  flags.ad = 0; // must be zero for multicast
  flags.cd = 0; // must be zero for multicast
  flags.rcode = 0;

  packet->id = 0; // should be 0 for multicast query messages
  packet->flags = htons(mdns_pack_header_flags(flags));
  packet->qd_count = htons(1); // one question

  question.qname = parse_hostname(hostname); // TODO get this from ARGV
  //  question.qname = hostname; // TODO get this from ARGV
  if(!question.qname) {
    return NULL;
  }
  question.prefer_unicast_response = 0; 
  question.qtype = 1; // an A record (RFC 1035 section 3.2.2)
  question.qclass = 1; // class for the internet (RFC 1035 section 3.2.4)

  packet->data = mdns_pack_question(&question, &(packet->data_size));

  return packet;
}

char* mdns_pack_packet(mDNSPacket* packet, size_t* pack_length) {
  char* pack;

  *pack_length = DNS_HEADER_SIZE + packet->data_size;
  if(*pack_length > DNS_MESSAGE_MAX_SIZE) {
    fail("mDNS message too large");
  }

  pack = malloc(*pack_length);
  if(!pack) {
    fail("failed to allocate data for packed mDNS packet");
  }

  memcpy(pack, packet, DNS_HEADER_SIZE);
  memcpy(pack + DNS_HEADER_SIZE, packet->data, packet->data_size);

  return pack;
}

// data is the input data
// packet is where the parsed packet is written
// returns the number of bytes consumed if succesfully parsed a DNS message
// returns 0 if more bytes needed to parse another DNS message
// returns -1 on error
int parse_received(char* data, int* answer_counter) {
  int res;
  mDNSPacket packet;

  res = mdns_parse_packet_net(data, &packet);
  if(packet.an_count <= 0) {
    printf("received non-answer message. skipping.\n");
    return res;
  }
  if(res > 0) {
    // TODO check packet answers against query
    mdns_packet_print(&packet);
    // TODO free memory allocated for packet
  }

  return res;
}


int main(int argc, char* argv[]) {

  mDNSPacket* packet;
  char* data;
  size_t data_size;
  struct sockaddr_in addr;
  struct sockaddr_in last_addr;
  socklen_t addrlen;
  struct ip_mreq mreq;
  int sock;
  int res;
  int resp;
  int parsed;
  char* recvdata;
  int answer_counter = 0; // how many answers have been received

  recvdata = malloc(DNS_BUFFER_SIZE);
  if(!recvdata) {
    fail("could not allocate memory for temporary storage");
  }
  
  if(argc != 2) {
    if(argc > 0) {
      usage(argv[0]);
    } else {
      usage(PROGRAM_NAME);
    }
    exit(1);
  }

  // build the query message
  packet = mdns_build_query_packet(argv[1]);
  data = mdns_pack_packet(packet, &data_size);

  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if(sock < 0) {
    fail("error opening socket");
  }
  
  addr.sin_family = AF_INET;
  addr.sin_port = htons(MDNS_PORT);
  addr.sin_addr.s_addr = inet_addr(MDNS_MULTICAST_ADDRESS);
  addrlen = sizeof(addr);

  printf("binding\n");
  res = bind(sock, (struct sockaddr *) &addr, addrlen);
  if(res < 0) {
    fail("error binding socket");
  }

  mreq.imr_multiaddr.s_addr = inet_addr(MDNS_MULTICAST_ADDRESS);
  mreq.imr_interface.s_addr = htonl(INADDR_ANY); // TODO understand this  
  if(setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
    fail("setsockopt failed");
  } 

  printf("sending query with length: %u\n", data_size);
  // send query message
  res = sendto(sock, data, data_size, 0, (struct sockaddr *) &addr, addrlen);

  // keep receiving data indefinitely
  while(1) {
    printf("waiting for data\n");
    // note: DNS messages should arrive as single packets, so we don't need to worry
    //       about partially received messages
    res = recvfrom(sock, recvdata, DNS_BUFFER_SIZE, 0, (struct sockaddr *) &addr, &addrlen);
    if(res < 0) {
      fail("error receiving");
    } else if(res == 0) {
      fail("unknown error"); // TODO for TCP means connection closed, but for UDP?
    }
    printf("got data from %s\n", inet_ntoa(addr.sin_addr));

    parsed = 0;
    do {
      resp = parse_received(recvdata, &answer_counter);
      // if nothing else is parsable, stop parsing
      if(resp <= 0) {
        break;
      }
      parsed += resp;
    } while(parsed < res); // while there is still something to parse
  }

  free(recvdata);  
  return 0;
}
