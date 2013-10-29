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

// DNS Resource Record types
#define DNS_RR_TYPE_A (1)
#define DNS_RR_TYPE_CNAME (5)
#define DNS_RR_TYPE_PTR (12)
#define DNS_RR_TYPE_TXT (16)
#define DNS_RR_TYPE_SRV (33)

// The maximum number of answers allowed
#define MAX_ANSWERS (20)

struct mDNSMessageStruct{
  uint16_t id;
  uint16_t flags;
  uint16_t qd_count;
  uint16_t an_count;
  uint16_t ns_count;
  uint16_t ar_count;
  char* data;
  size_t data_size;
} __attribute__((__packed__)); // ensure that struct is packed
typedef struct mDNSMessageStruct mDNSMessage;

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

typedef struct {
  char* name;
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t rdata_length;
  void* rdata;
} mDNSResourceRecord;

typedef struct {
  char* str;
  struct in_addr addr;
  int type;
} FoundAnswer;

typedef struct {
  // TODO should use linked list?
  FoundAnswer* answers[MAX_ANSWERS]; 
  size_t length;
} FoundAnswerList;

// The name we're currently querying for;
char* query_for;


void usage(char* argv0) {
  fprintf(stderr, "Usage: %s <hostname.local>\n", argv0);
}

void fail(char* msg) {
  //  fprintf(stderr, "Error: %s\n", msg);
  perror(msg);
  exit(1);
}

FoundAnswer* add_answer(FoundAnswerList* alist) {
  FoundAnswer* a;
  if(alist->length >= MAX_ANSWERS) {
    return NULL;
  }
  a = malloc(sizeof(FoundAnswer));
  if(!a) {
    fail("Could not allocate memory for a found answer");
  }

  alist->answers[alist->length] = a;
  alist->length++;
  return a;
}


char* prepare_domain_name(char* name) {
  int i;
  int offset;
  int length = strlen(name);
  char* result;

  if(length < 1) {
    return NULL;
  }

  result = malloc(length + 2);
  if(!result) {
    fail("failed to allocate memory for parsed hostname");
  }

  if((name[0] != '.') && (name[0] != 0x05)) {
    // prepend with dot since it was missing
    result[0] = 0x05;
    offset = 1;
  } else {
    offset = 0;
  }


  for(i=0; i < length; i++) {
    if(name[i] == '.') { // dot
      result[i+offset] = 0x05;
    } else {
      result[i+offset] = name[i];
    }
  }
  result[length+offset] = '\0';

  return result;
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

mDNSMessage* mdns_make_message() {
  mDNSMessage* msg = malloc(sizeof(mDNSMessage));
  if(!msg) {
    fail("failed to allocate memory for mDNS message");
  }
  return msg;
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

  
  name_length = strlen(q->qname) + 1;
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

  packed[0] = 0x05;
  memcpy(packed+1, q->qname, name_length);
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


void mdns_message_print(mDNSMessage* msg) {

  mDNSFlags* flags = mdns_parse_header_flags(msg->flags);

  printf("ID: %u\n", msg->id);
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
  printf("QDCOUNT: %u\n", msg->qd_count);
  printf("ANCOUNT: %u\n", msg->an_count);
  printf("NSCOUNT: %u\n", msg->ns_count);
  printf("ARCOUNT: %u\n", msg->ar_count);
  printf("Resource records:\n");
  //  printf("Data: %s\n",msg->data);

  free(flags);
}

// parse question section
int mdns_parse_question(char* data, int size) {
  mDNSQuestion q;
  char* cur;
  int parsed;

  cur = data;
  // TODO check for invalid length
  parsed = strlen(data) + 1;
  q.qname = data;
  cur += parsed;
  if(parsed > size) {
    return 0;
  }

  memcpy(&(q.qtype), cur, 2);
  q.qtype = ntohs(q.qtype);
  cur += 2;
  parsed += 2;
  if(parsed > size) {
    return 0;
  }

  memcpy(&(q.qclass), cur, 2);
  q.qclass = ntohs(q.qclass);
  cur += 2;
  parsed += 2;
  if(parsed > size) {
    return 0;
  }
  
  return parsed;
}

// parse A resource record
int mdns_parse_rr_a(char* data, FoundAnswerList* alist) {
  FoundAnswer* a;

  a = add_answer(alist);
  memcpy(&(a->addr), data, 4);

  printf("%s\n", inet_ntoa(a->addr));

  return 4;
}

// parse CNAME resource record
int mdns_parse_rr_cname(char* data) {

  return 0;
}

// parse PTR resource record
int mdns_parse_rr_ptr(char* data) {

  return 0;
}

// parse TXT resource record
int mdns_parse_rr_txt(char* data) {

  return 0;
}

// parse SRV resource record
int mdns_parse_rr_srv(char* data) {

  return 0;
}

void mdns_parse_rdata_for_answers(mDNSResourceRecord* rr, FoundAnswerList* alist) {

  // if the resource record is not relevant
  // to the current query, then we don't care about it
  if(strcmp(rr->name, query_for) != 0) {
    return;
  }

  switch(rr->type) {
  case DNS_RR_TYPE_A:
    mdns_parse_rr_a(rr->rdata, alist);
    break;
  case DNS_RR_TYPE_CNAME:
  case DNS_RR_TYPE_PTR:
  case DNS_RR_TYPE_TXT:
  case DNS_RR_TYPE_SRV:
  default:
    printf("skipped irrelevant rr_data type %u\n", rr->type);
  }
}

// parse a resource record
// the answer, authority and additional sections all use the resource record format
int mdns_parse_rr(char* data, int size, FoundAnswerList* alist, int is_answer) {
  mDNSResourceRecord* rr;
  int parsed = 0;
  char* cur = data;
  rr = malloc(sizeof(mDNSResourceRecord));

  // TODO check for invalid length
  parsed = strlen(cur) + 1;
  cur += parsed;

  // +10 because type, class, ttl and rdata_lenth total 10 bytes
  if(parsed+10 > size) {
    free(rr);
    return 0;
  }

  rr->name = data;

  printf("  Resource Record for %s:\n", rr->name);

  memcpy(&(rr->type), cur, 2);
  rr->type = ntohs(rr->type);
  cur += 2;
  parsed += 2;

  memcpy(&(rr->class), cur, 2);
  rr->class = ntohs(rr->class);
  cur += 2;
  parsed += 2;

  memcpy(&(rr->ttl), cur, 4);
  rr->ttl = ntohl(rr->ttl);
  cur += 4;
  parsed += 4;

  memcpy(&(rr->rdata_length), cur, 2);
  rr->rdata_length = ntohs(rr->rdata_length);
  cur += 2;
  parsed += 2;

  if(parsed > size) {
    free(rr);
    return 0;
  }

  rr->rdata = cur;
  parsed += rr->rdata_length;
  
  if(is_answer) {
    mdns_parse_rdata_for_answers(rr, alist);
  }

  free(rr);
  return parsed;
}

// TODO this only parses the header so far
  int mdns_parse_message_net(char* data, int size, mDNSMessage* msg, FoundAnswerList* alist) {

  int parsed = 0;
  int i;

  if(size < DNS_HEADER_SIZE) {
    return 0;
  }

  memcpy(msg, data, DNS_HEADER_SIZE);
  msg->id = ntohs(msg->id);
  msg->flags = ntohs(msg->flags);
  msg->qd_count = ntohs(msg->qd_count);
  msg->an_count = ntohs(msg->an_count);
  msg->ns_count = ntohs(msg->ns_count);
  msg->ar_count = ntohs(msg->ar_count);
  parsed += DNS_HEADER_SIZE;

  mdns_message_print(msg);

  for(i=0; i < msg->qd_count; i++) {
    parsed += mdns_parse_question(data+parsed, size-parsed);
  }

  for(i=0; i < msg->an_count; i++) {
    parsed += mdns_parse_rr(data+parsed, size-parsed, alist, 1);
  }

  for(i=0; i < msg->ns_count; i++) {
    parsed += mdns_parse_rr(data+parsed, size-parsed, alist, 0);
  }

  for(i=0; i < msg->ar_count; i++) {
    parsed += mdns_parse_rr(data+parsed, size-parsed, alist, 0);
  }

  // TODO actually parse the rest of message and find real parse size
  return parsed;
}

mDNSMessage* mdns_build_query_message(char* hostname) {
  mDNSMessage* msg = mdns_make_message();
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

  msg->id = 0; // should be 0 for multicast query messages
  msg->flags = htons(mdns_pack_header_flags(flags));
  msg->qd_count = htons(1); // one question

  question.qname = parse_hostname(hostname); // TODO get this from ARGV
  //  question.qname = hostname; // TODO get this from ARGV
  if(!question.qname) {
    return NULL;
  }
  question.prefer_unicast_response = 0; 
  question.qtype = 1; // an A record (RFC 1035 section 3.2.2)
  question.qclass = 1; // class for the internet (RFC 1035 section 3.2.4)

  msg->data = mdns_pack_question(&question, &(msg->data_size));

  return msg;
}

char* mdns_pack_message(mDNSMessage* msg, size_t* pack_length) {
  char* pack;

  *pack_length = DNS_HEADER_SIZE + msg->data_size;
  if(*pack_length > DNS_MESSAGE_MAX_SIZE) {
    fail("mDNS message too large");
  }

  pack = malloc(*pack_length);
  if(!pack) {
    fail("failed to allocate data for packed mDNS message");
  }

  memcpy(pack, msg, DNS_HEADER_SIZE);
  memcpy(pack + DNS_HEADER_SIZE, msg->data, msg->data_size);

  return pack;
}

// data is the input data
// *answer_counter is incremented for each answer section
// returns the number of bytes consumed if succesfully parsed a DNS message
// returns 0 if no DNS message parsed
// returns -1 on error
int parse_received(char* data, int size, FoundAnswerList* alist) {
  int res;
  mDNSMessage msg;

  res = mdns_parse_message_net(data, size, &msg, alist);
  return res;
}


int query(char* query_str, int num_answers, FoundAnswerList* alist) {
  mDNSMessage* msg;
  char* data;
  size_t data_size;
  struct sockaddr_in addr;
  socklen_t addrlen;
  struct ip_mreq mreq;
  int sock;
  int res;
  int resp;
  int parsed;
  char* recvdata;

  recvdata = malloc(DNS_BUFFER_SIZE);
  if(!recvdata) {
    fail("could not allocate memory for temporary storage");
  }

  query_for = prepare_domain_name(query_str);

  // build the query message
  msg = mdns_build_query_message(query_str);
  data = mdns_pack_message(msg, &data_size);

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
    if(alist->length >= num_answers) {
      return alist->length;
    }
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
      resp = parse_received(recvdata+parsed, res, alist);
      // if nothing else is parsable, stop parsing
      if(resp <= 0) {
        break;
      }
      parsed += resp;
      printf("--- parsed %u vs. received %u\n", parsed, res);
    } while(parsed < res); // while there is still something to parse
  }

  free(query_for);
  query_for = NULL;

  free(recvdata);  
  
  return 0;
}

int main(int argc, char* argv[]) {

  int answers;
  FoundAnswerList alist;
  alist.length = 0;
  
  if(argc != 2) {
    if(argc > 0) {
      usage(argv[0]);
    } else {
      usage(PROGRAM_NAME);
    }
    exit(1);
  }

  // retrieve one answer for query
  answers = query(argv[1], 1, &alist);
  if(answers < 1) {
    fprintf(stderr, "Did not find 1 answer for query: %s\n", argv[1]);
    return 1;
  }


  return 0;
}
