/*
  
  mdnssd-min

  mdnssd-min is a minimal DNS-SD and mDNS client that takes a service type
  as its argument and returns the IPv4 and/or IPv6 addreses and port numbers
  running a service of the type.

  Usage: mdnssd-min <service_type>
  
  License: GPLv3
  Author: juul@sudomesh.org
  Copyright 2013-2014 Marc Juul Christoffersen.

  References:

  DNS RFC: http://tools.ietf.org/html/rfc1035
    Section 4.1, 3.2.2 and 3.2.4

  DNS RFC: http://tools.ietf.org/html/rfc1034
    Section 3.7.1

  DNS Security Extensions RFC: http://tools.ietf.org/html/rfc2535
    Section 6.1

  mDNS RFC: http://tools.ietf.org/html/rfc6762
    Section 18.

  DNS-SD RFC: http://tools.ietf.org/html/rfc6763

  DNS SRV RFC: http://tools.ietf.org/html/rfc2782
        
*/

#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <time.h>

#include "mdnssd-min.h"

// TODO grrr, global variables
// The name we're currently querying for;
char* query_for;
// is debug mode enabled?
int debug_mode;

int debug(const char* format, ...) {
  va_list args;
  int ret;

  if(!debug_mode) {
    return 0;
  }
  va_start(args, format);
  ret = vfprintf(stderr, format, args);

  va_end(args);
  return ret;
}

void usage(char* argv0) {
  fprintf(stderr, "Given a service type, return a set of hostnames, IPs and port numbers\n");
  fprintf(stderr, "for instances of services of the given type.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Usage: %s [-a <answers>] [-t <time>] [-d] <_service._type.local>\n", argv0);
  fprintf(stderr, "\n");
  fprintf(stderr, "  answers: Minimum number of answers wanted (default: 1) [optional]\n");
  fprintf(stderr, "  time: Maximum number of seconds to wait for answers (default: 3) [optional]\n");
  fprintf(stderr, "  -d: Enable very verbose debug output [optional]\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Example usage: %s -a 2 -t 10 _workstation._tcp.local\n", argv0);
  fprintf(stderr, "\n");
}

void fail(char* msg) {
  perror(msg);
  exit(1);
}

void init_answer_list(FoundAnswerList* alist) {
  int i;

  for(i=0; i < MAX_ANSWERS; i++) {
    alist->answers[i] = NULL;
  }
  alist->length = 0;
  alist->completed_length = 0;
}

FoundAnswer* add_new_answer(FoundAnswerList* alist) {
  FoundAnswer* a;
  if(alist->length >= MAX_ANSWERS) {
    return NULL;
  }
  a = malloc(sizeof(FoundAnswer));
  if(!a) {
    fail("Could not allocate memory for a found answer");
  }

  a->name = NULL;
  a->hostname = NULL;
  a->port = 0;
  a->srv_query_sent = 0;
  a->a_query_sent = 0;
  a->addr.s_addr = 0;
  alist->answers[alist->length] = a;
  alist->length++;
  return a;
}

FoundAnswer* add_answer(FoundAnswerList* alist, FoundAnswer* a) {
  if(alist->length >= MAX_ANSWERS) {
    return NULL;
  }

  alist->answers[alist->length] = a;
  alist->length++;
  return a;
}

void clear_answer_list(FoundAnswerList* alist) {
  int i;
  for(i=0; i < MAX_ANSWERS; i++) {
    if(alist->answers[i]) {
      if(alist->answers[i]->name) {
        // TODO there may be more that needs freeing
        free(alist->answers[i]->name);
      }
      free(alist->answers[i]);
    }
  }
  alist->length = 0;
}

char* prepare_query_string(char* name) {
  int i;
  int count;
  int lastdot = 0;
  int len = strlen(name);
  char* result;

  result = malloc(len + 2);
  if(!result) {
    fail("failed to allocate memory for parsed hostname");
  }

  count = 0;
  for(i=0; i < len+1; i++) {
    if((name[i] == '.') || (name[i] == '\0')) {
      result[lastdot] = (char) count;
      count = 0;
      lastdot = i+1;
      continue;
    }
    result[i+1] = name[i];
    count++;
  }
  result[len+1] = '\0';  

  return result;
}

// parse and sanitize hostname
// TODO go throught this and ensure that it conforms to RFC6763 secion 4.1.1
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

  debug("name length: %u\n", name_length);

  *size = name_length + 2 + 2;

  // 1 char for terminating \0, 2 for qtype and 2 for qclass
  packed = malloc(*size);
  if(!packed) {
    fail("could not allocate memory for DNS question");
  }

  memcpy(packed, q->qname, name_length);

  // The top bit of the qclass field is repurposed by mDNS
  // to indicate that a unicast response is preferred
  // See RFC 6762 section 5.4
  if(q->prefer_unicast_response) {
    q->qclass |= 1 << 15;
  }

  qtype = htons(q->qtype);
  qclass = htons(q->qclass);

  memcpy(packed + name_length, &qtype, 2);
  memcpy(packed + name_length + 2, &qclass, 2);

  return packed;
}


void mdns_message_print(mDNSMessage* msg) {

  mDNSFlags* flags = mdns_parse_header_flags(msg->flags);

  debug("ID: %u\n", msg->id);
  debug("Flags: \n");
  debug("      QR: %u\n", flags->qr);
  debug("  OPCODE: %u\n", flags->opcode);
  debug("      AA: %u\n", flags->aa);
  debug("      TC: %u\n", flags->tc);
  debug("      RD: %u\n", flags->rd);
  debug("      RA: %u\n", flags->ra);
  debug("       Z: %u\n", flags->zero);
  debug("      AD: %u\n", flags->ad);
  debug("      CD: %u\n", flags->cd);
  debug("   RCODE: %u\n", flags->rcode);
  debug("\n");
  debug("QDCOUNT: %u\n", msg->qd_count);
  debug("ANCOUNT: %u\n", msg->an_count);
  debug("NSCOUNT: %u\n", msg->ns_count);
  debug("ARCOUNT: %u\n", msg->ar_count);
  debug("Resource records:\n");

  free(flags);
}

// parse question section
int mdns_parse_question(char* message, char* data, int size) {
  mDNSQuestion q;
  char* cur;
  int parsed = 0;

  cur = data;
  // TODO check for invalid length
  q.qname = parse_rr_name(message, data, &parsed);
  cur += parsed;
  if(parsed > size) {
    fail("qname is too long");
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
int mdns_parse_rr_a(char* data, FoundAnswer* a) {

  memcpy(&(a->addr), data, 4);
  //  a->type = DNS_RR_TYPE_A;

  debug("        A: %s\n", inet_ntoa(a->addr));

  return 4;
}

// parse PTR resource record
int mdns_parse_rr_ptr(char* message, char* data, FoundAnswer* a) {
  int parsed = 0;

  a->name = parse_rr_name(message, data, &parsed);

  //  a->type = DNS_RR_TYPE_PTR;

  debug("        PTR: %s\n", a->name);

  return parsed;
}

// parse SRV resource record
int mdns_parse_rr_srv(char* message, char* data, FoundAnswer* a) {
  uint16_t priority;
  uint16_t weight;
  int parsed = 0;
  
  // TODO currently we do nothing with the priority and weight
  memcpy(&priority, data, 2);
  priority = ntohs(priority);
  data += 2;
  parsed += 2;

  memcpy(&weight, data, 2);
  weight = ntohs(weight);
  data += 2;
  parsed += 2;

  memcpy(&(a->port), data, 2);
  a->port = ntohs(a->port);
  data += 2;
  parsed += 2;

  //  a->type = DNS_RR_TYPE_SRV;

  a->hostname = parse_rr_name(message, data, &parsed);

  debug("        SRV target: %s\n", a->hostname);
  debug("        SRV port: %u\n", a->port);

  return parsed;
}

// get name compression offset
uint16_t get_offset(char* data) {
  uint16_t offset;

  memcpy(&offset, data, 2);
  offset = ntohs(offset);

  if((offset >> 14) & 3) {
    // this means that the name is a reference to 
    // a string instead of a string
    offset &= 0x3fff; // change two most significant bits to 0
    return offset;
  }
  return 0;

};


// parse a domain name 
// of the type included in resource records
char* parse_rr_name(char* message, char* name, int* parsed) {

  int dereference_count = 0;
  uint16_t offset;
  int label_len;
  char* out;
  int out_i = 0;
  int i = 0;
  int did_jump = 0;
  int pars = 0;

  out = malloc(MAX_RR_NAME_SIZE);
  if(!out) {
    fail("could not allocate memory for resource record name");
  }

  while(1) {
    offset = get_offset(name);
    if(offset) {
      if(!did_jump) {
        pars += 2; // parsed two bytes before jump
      }
      did_jump = 1;
      name = message + offset;
      dereference_count++;
      if(dereference_count >= MAX_DEREFERENCE_COUNT) {
        // don't allow messages to crash this app
        free(out);
        return NULL;
      }
      continue;
    }
    // insert a dot between labels
    if(out_i > 0) {
      out[out_i++] = '.';

      if(out_i+1 >= MAX_RR_NAME_SIZE) {
        free(out);
        return NULL;
      }
    }
    // it wasn't an offset, so it must be a string length
    label_len = (int) name[0];
    name++;
    if(!did_jump) {
      pars++;
    }
    for(i=0; i < label_len; i++) {
      out[out_i++] = name[i];
      if(out_i+1 >= MAX_RR_NAME_SIZE) {
        free(out);
        return NULL;
      }
      if(!did_jump) {
        pars++;
      }
    }
    name += label_len;
    if(name[0] == '\0') {
      out[out_i] = '\0';
      if(!did_jump) {
        pars++;
      }
      *parsed += pars;
      return out;
    }
  }
}


void mdns_parse_rdata_type(char* message, mDNSResourceRecord* rr, FoundAnswer* answer) {

  switch(rr->type) {
  case DNS_RR_TYPE_A:
    mdns_parse_rr_a(rr->rdata, answer);
    break;
  case DNS_RR_TYPE_PTR:
    mdns_parse_rr_ptr(message, rr->rdata, answer);
    break;
  case DNS_RR_TYPE_SRV:
    mdns_parse_rr_srv(message, rr->rdata, answer);
    break;
  case DNS_RR_TYPE_CNAME:
  case DNS_RR_TYPE_TXT:
  default:
    debug("      [skipped irrelevant record]\n");
  }
}

void free_resource_record(mDNSResourceRecord* rr) {
  if(!rr) {
    return;
  }
  if(rr->name) {
    free(rr->name);
  }
  free(rr);
}

// parse a resource record
// the answer, authority and additional sections all use the resource record format
int mdns_parse_rr(char* message, char* rrdata, int size, FoundAnswerList* alist, int is_answer) {
  mDNSResourceRecord* rr;
  int parsed = 0;
  char* cur = rrdata;
  FoundAnswer* answer;

  rr = malloc(sizeof(mDNSResourceRecord));
  rr->name = NULL;

  rr->name = parse_rr_name(message, rrdata, &parsed);
  if(!rr->name) {
    // TODO are calling functions dealing with this correctly?
    fprintf(stderr, "parsing resource record name failed\n");
    return 0;
  }

  cur += parsed;

  // +10 because type, class, ttl and rdata_lenth 
  // take up total 10 bytes
  if(parsed+10 > size) {
    free_resource_record(rr);
    return 0;
  }

  debug("      Resource Record Name: %s\n", rr->name);
  
  memcpy(&(rr->type), cur, 2);
  rr->type = ntohs(rr->type);
  cur += 2;
  parsed += 2;

  debug("      Resource Record Type: %u\n", rr->type);

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
    free_resource_record(rr);
    return 0;
  }

  rr->rdata = cur;
  parsed += rr->rdata_length;
  
  if(is_answer) {
    answer = add_new_answer(alist);
    answer->rr = rr;
    mdns_parse_rdata_type(message, rr, answer);
  }

  debug("    ------------------------------\n");

  //  free_resource_record(rr);
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

  debug("  Question records [%u] (not shown)\n", msg->qd_count);
  for(i=0; i < msg->qd_count; i++) {
    parsed += mdns_parse_question(data, data+parsed, size-parsed);
  }

  debug("  Answer records [%u]\n", msg->an_count);
  for(i=0; i < msg->an_count; i++) {
    debug("    Answer record %u of %u\n", i+1, msg->an_count);
    parsed += mdns_parse_rr(data, data+parsed, size-parsed, alist, 1);
  }

  debug("  Nameserver records [%u] (not shown)\n", msg->ns_count);
  for(i=0; i < msg->ns_count; i++) {
    parsed += mdns_parse_rr(data, data+parsed, size-parsed, alist, 0);
  }

  debug("  Additional records [%u] (not shown)\n", msg->ns_count);
  for(i=0; i < msg->ar_count; i++) {
    parsed += mdns_parse_rr(data, data+parsed, size-parsed, alist, 1);
  }

  return parsed;
}

mDNSMessage* mdns_build_query_message(char* query_str, uint16_t query_type) {
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

  question.qname = query_str;

  if(!question.qname) {
    return NULL;
  }

  question.prefer_unicast_response = 0; 
  question.qtype = query_type;
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

// search argv for either stand-along
// arguments like -d or arguments with a value
// like -t 5
int get_arg(int argc, char* argv[], char* key, char** val) {
  int i;
  for(i=1; i < argc; i++) {
    if(strcmp(argv[i], key) == 0) {
      if(val) { // expecting a value
        if(argc < i+2) {
          continue;
        }
        *val = argv[i+1];
        return 1;
      } else { // not expecting a value
        return 1;
      }

    }
  }
  return 0;
}

int out_of_time(struct timeval* t) {
  if((t->tv_sec <= 0) && (t->tv_usec <= 0)) {
    return 1;
  }
  return 0;
}

void print_answers(FoundAnswerList* alist) {

  int i;
  FoundAnswer* answer = NULL;

  for(i=0; i < alist->length; i++) {
    answer = alist->answers[i];
    if(!answer) {
        continue;
    }
    if(!is_answer_complete(answer)) {
      continue;
    }

    printf("%s\t%s\t%u\n", answer->hostname, inet_ntoa(answer->addr), answer->port);

  }
}

int send_query(int sock, char* query_arg, uint16_t query_type) {

  mDNSMessage* msg;
  char* data;
  size_t data_size;
  int res;
  struct sockaddr_in addr;
  socklen_t addrlen;
  char* query_str;

  query_str = prepare_query_string(query_arg);

  addr.sin_family = AF_INET;
  addr.sin_port = htons(MDNS_PORT);
  addr.sin_addr.s_addr = inet_addr(MDNS_MULTICAST_ADDRESS);
  addrlen = sizeof(addr);

  // build and pack the query message
  msg = mdns_build_query_message(query_str, query_type);
  data = mdns_pack_message(msg, &data_size);

  debug("Sending DNS message with length: %u\n", data_size);
  // send query message
  res = sendto(sock, data, data_size, 0, (struct sockaddr *) &addr, addrlen);
  
  return res;
}

int init_socket() {

  int sock;
  int res;
  struct ip_mreq mreq;
  struct sockaddr_in addr;
  socklen_t addrlen;

  debug("Opening socket\n");
  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if(sock < 0) {
    fail("error opening socket");
  }

  // TODO this is repeated a few times in this program
  addr.sin_family = AF_INET;
  addr.sin_port = htons(MDNS_PORT);
  addr.sin_addr.s_addr = inet_addr(MDNS_MULTICAST_ADDRESS);
  addrlen = sizeof(addr);
  
  debug("Binding socket\n");
  res = bind(sock, (struct sockaddr *) &addr, addrlen);
  if(res < 0) {
    fail("error binding socket");
  }

  mreq.imr_multiaddr.s_addr = inet_addr(MDNS_MULTICAST_ADDRESS);
  mreq.imr_interface.s_addr = htonl(INADDR_ANY); // TODO understand this  
  debug("Setting socket options for multicast\n");
  if(setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
    fail("setsockopt failed");
  } 

  return sock;
}

/*
  An answer is complete if it has all of:
    * A hostname (from a SRV record)
    * A port (from a SRV record)
    * An IP address (from an A record)
 */
int is_answer_complete(FoundAnswer* a) {
  if(!a->addr.s_addr || !a->hostname || !a->port) {
    return 0;
  }
  return 1;
}

/*
  Attempt to complete an answer
  by trying to find the necessary information
  in the answer list, and if that fails, 
  then send a query.
*/
void complete_answer(int sock, FoundAnswerList* alist, FoundAnswer* a) {
  FoundAnswer* b;  
  int i;

  // attempt to complete answer from existing answer list
  for(i=0; i < alist->length; i++) {
    b = alist->answers[i];

    // fill in hostname and port
    // if a SRV record exists for the service instance name
    if(!a->hostname || !a->port) {
      if(b->rr->type == DNS_RR_TYPE_SRV) {
        if(strcmp(a->name, b->rr->name) == 0) {
          a->hostname = b->hostname;
          a->port = b->port;
        }
      }
    } else {
      // fill in IP address
      // if an A record exists for the hostname
      if(!a->addr.s_addr) {
        if(b->rr->type == DNS_RR_TYPE_A) {
          if(strcmp(a->hostname, b->rr->name) == 0) {
            a->addr.s_addr = b->addr.s_addr;
            alist->completed_length++;
          }
        }
      }
    }
  }

  // if answer is still not complete
  // send additional query
  if(!a->hostname || !a->port) {
    if(!a->srv_query_sent) {
      send_query(sock, a->name, DNS_RR_TYPE_SRV);
      a->srv_query_sent = 1;
      // TODO handle return value
    }
  } else {
    if(!a->addr.s_addr) {
      if(a->a_query_sent) {
        send_query(sock, a->hostname, DNS_RR_TYPE_PTR);
        a->a_query_sent = 1;
        // TODO handle return value
      }
    }
  }
}

// attempt to complete the received answers
void complete_answers(int sock, char* query_arg, FoundAnswerList* alist) {
  int i;
  FoundAnswer* a;

  for(i=0; i < alist->length; i++) {
    a = alist->answers[i];
    // only look for answers to the initial service query
    if(a->rr->type != DNS_RR_TYPE_PTR) {
      continue;
    }
    // skip complete answers and imcomplete answers 
    // for which we have already sent a query
    if(is_answer_complete(a) || (a->srv_query_sent && a->a_query_sent)) {
      continue;
    }

    // skip if this is not a reply to the sent query
    if(strcmp(a->rr->name, query_arg) != 0) {
      continue;
    }

    complete_answer(sock, alist, a);
  }
}

void main_loop(int sock, char* query_arg, int min_answers, FoundAnswerList* alist, struct timeval* runtime) {
  struct sockaddr_in addr;
  socklen_t addrlen;
  int res;
  int resp;
  int parsed;
  char* recvdata;
  fd_set active_fd_set;
  fd_set read_fd_set;
  fd_set except_fd_set;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(MDNS_PORT);
  addr.sin_addr.s_addr = inet_addr(MDNS_MULTICAST_ADDRESS);
  addrlen = sizeof(addr);

  recvdata = malloc(DNS_BUFFER_SIZE);
  if(!recvdata) {
    fail("could not allocate memory for temporary storage");
  }

  FD_ZERO(&active_fd_set);
  FD_SET(sock, &active_fd_set);

  debug("Entering main loop\n");

  // keep receiving data indefinitely
  while(1) {
    if((min_answers > 0) && (alist->completed_length >= min_answers)) {
      debug("Gathered %u answers out of minimum %u required\n", alist->completed_length, min_answers);
      break;
    }

    read_fd_set = active_fd_set;
    except_fd_set = active_fd_set;
    res = select(FD_SETSIZE, &read_fd_set, NULL, &except_fd_set, runtime);
    if(res < 0) {
      fail("select() call failed");
    }

    if(res == 0) {
      if((runtime->tv_sec <= 0) && (runtime->tv_usec <= 0)) {
        debug("time is up!");
        break;
      }
      continue;
    }

    if(FD_ISSET(sock, &except_fd_set)) {
      fail("exception on socket");
    }

    if(!FD_ISSET(sock, &read_fd_set)) {
      // I don't even know how we'd ever get here...
      continue;
    }

    // DNS messages should arrive as single packets
    // so we don't need to worry about partial receives
    debug("Receiving data\n");
    res = recvfrom(sock, recvdata, DNS_BUFFER_SIZE, 0, (struct sockaddr *) &addr, &addrlen);
    if(res < 0) {
      fail("error receiving");
    } else if(res == 0) {
      fail("unknown error"); // TODO for TCP means connection closed, but for UDP?
    }
    debug("Received %u bytes from %s\n", res, inet_ntoa(addr.sin_addr));

    parsed = 0;
    debug("Attempting to parse received data\n");
    do {
      resp = parse_received(recvdata+parsed, res, alist);
      // if nothing else is parsable, stop parsing
      if(resp <= 0) {
        break;
      }
      parsed += resp;
      debug("--Parsed %u bytes of %u received bytes\n", parsed, res);
    } while(parsed < res); // while there is still something to parse
    debug("Finished parsing received data\n");

    // attempt to complete the received answers
    complete_answers(sock, query_arg, alist);

  }

  close(sock);
  free(recvdata);

  return;
}

int main(int argc, char* argv[]) {

  struct timeval runtime;
  FoundAnswerList alist;
  char* query_arg;
  int ret;
  char* arg_val;
  int sock;
  int min_answers = 1; // TODO get from cmd line args

  debug_mode = 0;

  // default runtime 3 seconds
  runtime.tv_sec = 3;
  runtime.tv_usec = 0;

  if(argc < 2) {
    usage(argv[0]);
    exit(1);
  }

  // get min answers argument
  ret = get_arg(argc, argv, "-a", &arg_val);
  if(ret) {
    ret = atoi(arg_val);
    if((ret < 0) || (ret > MAX_ANSWERS)) {
      fprintf(stderr, "Maximum number of answers supported is %u\n", MAX_ANSWERS);
      usage(argv[0]);
      exit(1);
    }
    min_answers = ret;    
  }

  // get timeout argument
  ret = get_arg(argc, argv, "-t", &arg_val);
  if(ret) {
    ret = atoi(arg_val);
    if((ret < 0) || (ret > MAX_RUNTIME)) {
      usage(argv[0]);
      exit(1);
    }
    runtime.tv_sec = ret;    
  }

  // get debug argument
  ret = get_arg(argc, argv, "-d", NULL);
  if(ret) {
    debug_mode = 1;
  }

  // last argument should be query
  query_arg = argv[argc-1];

  // TODO where do we free this?!
  init_answer_list(&alist);

  sock = init_socket();

  // if it start with an underscore, 
  // assume it's a query for a service type
  if(query_arg[0] == '_') {

    ret = send_query(sock, query_arg, DNS_RR_TYPE_PTR);
    
  } else { // this is a query for a host name

    fail("only service queries currently supported");

  }

  main_loop(sock, query_arg, min_answers, &alist, &runtime);
  print_answers(&alist);

  return 0;
}
