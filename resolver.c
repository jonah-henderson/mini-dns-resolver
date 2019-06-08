#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>

//----------------------------------------------------------------------------------------------------------------------
// Auxiliary constants and program constraints
//----------------------------------------------------------------------------------------------------------------------

const int FALSE = 0;
const int TRUE = 1;

const int ASCII_UPPER_TO_LOWER_OFFSET = 32;

const int MAX_REQUEST_LEN = 256;
const int MAX_RESPONSE_LEN = 256;

const int MAX_DOMAIN_NAME_LEN = 256;

//----------------------------------------------------------------------------------------------------------------------
// DNS format constants and helper structs
//----------------------------------------------------------------------------------------------------------------------

// DNS resource record types
const int RR_CLASS_INET = 1;
const int RR_TYPE_IPV4 = 1;
const int RR_TYPE_CNAME = 5;

const int DNS_HEADER_LEN = 12;

// Size of the fixed length data in a CNAME record, which consists of
// type, class, ttl, and the rdata_len
const int CNAME_RDATA_FIXED_LEN = 2 + 2 + 4 + 2;

// "XXX.XXX.XXX.XXX\0"
const int MAX_IP_ADDR_ASCII_LEN = 16;

// When the pointer flags are set, the byte examined will have at least this value
const int DNS_POINTER_FLAG_VALUE = 192;

// But to get the actual offset value, we need to subtract the pointer flag bits
const int DNS_POINTER_FLAG_MASK = 0b11 << 14;

typedef unsigned int dns_rr_ttl;
typedef unsigned short dns_rr_type;
typedef unsigned short dns_rr_class;
typedef unsigned short dns_rdata_len;

// DNS resource record struct to make interacting with the data a little nicer
typedef struct
{
  char *name;
  dns_rr_type type;
  dns_rr_class class;
  dns_rr_ttl ttl;
  dns_rdata_len rdata_len;
  unsigned char *rdata;
} dns_rr;

// DNS header structure
typedef struct
{
  unsigned short id;

  unsigned char rd
      :1; // recursion desired
  unsigned char tc
      :1; // truncated message
  unsigned char aa
      :1; // authoritative answer
  unsigned char opcode
      :4; // purpose of message
  unsigned char qr
      :1; // query/response flag

  unsigned char rcode
      :4; // response code
  unsigned char cd
      :1; // checking disabled
  unsigned char ad
      :1; // authenticated data
  unsigned char z
      :1; // reserved
  unsigned char ra
      :1; // recursion available

  unsigned short q_count; // number of question entries
  unsigned short ans_count; // number of answer entries
  unsigned short auth_count; // number of authority entries
  unsigned short add_count; // number of resource entries
} dns_header;

// DNS question fixed-size elements
typedef struct
{
  unsigned short class;
  unsigned short type;
} dns_query;

//----------------------------------------------------------------------------------------------------------------------
// Program typedefs and structs
//----------------------------------------------------------------------------------------------------------------------

struct dns_answer_entry;
struct dns_answer_entry
{
  char *value;
  struct dns_answer_entry *next;
};
typedef struct dns_answer_entry dns_answer_entry;

//----------------------------------------------------------------------------------------------------------------------
// Program functions
//----------------------------------------------------------------------------------------------------------------------

/**
 * Canonicalize a domain name in place.  Change all upper-case characters to
 * lower case and remove the trailing dot if there is any.  If the name
 * passed is a single dot, "." (representing the root zone), then it
 * should stay the same.
 */
void canonicalize_name(char *domainName)
{

  int nameLen, i;

  // leave the root zone alone
  if (strcmp(domainName, ".") == 0)
  {
    return;
  }

  nameLen = (int) strlen(domainName);

  // remove the trailing dot, if any
  if (domainName[nameLen - 1] == '.')
  {
    domainName[nameLen - 1] = '\0';
  }

  // make all upper-case letters lower case
  for (i = 0; i < nameLen; i++)
  {
    if (domainName[i] >= 'A' && domainName[i] <= 'Z')
    {
      domainName[i] += ASCII_UPPER_TO_LOWER_OFFSET;
    }
  }
}

/**
 * Converts a DNS name from string representation (dot-separated labels)
 * to DNS wire format, using the provided byte array (wireBuf).  Returns
 * the number of bytes used by the name in wire format.
 */
int name_ascii_to_wire(char *domainName, unsigned char *wireBuf)
{
  char *namePtr = domainName;
  unsigned char *wirePtr = wireBuf;
  int totalLength = 0;

  // end condition checked below
  while (1)
  {
    unsigned char labelLen = 0;
    char *labelPtr = namePtr;

    // loop through the next label segment to find its length
    while (*labelPtr != '.' && *labelPtr != '\0')
    {
      labelLen++;
      labelPtr++;
    }

    // put the label length on the buffer
    *wirePtr++ = labelLen;
    totalLength++;

    // then copy the label to the buffer
    while (namePtr != labelPtr)
    {
      *wirePtr++ = (unsigned char) *namePtr;
      namePtr++;
      totalLength++;
    }

    // if we're at the end of the name, break
    if (*namePtr == '\0')
      break;

    namePtr++;
  }

  // put the null terminator on the buffer
  *wirePtr = 0;
  totalLength++;

  return totalLength;
}

/**
 * Extracts the wire-formatted DNS name at the offset specified by
 * *indexPtr in the array of bytes provided (wire) and return its string
 * representation (dot-separated labels) in a char array allocated for
 * that purpose.  Updates the value pointed to by indexp to the next
 * value beyond the name.
 */
char *name_ascii_from_wire(unsigned char *wire, int *indexPtr)
{
  unsigned char *wirePtr = wire + *indexPtr;
  int updateIndex = 0;
  int jumped = FALSE;

  char *ascii = malloc(MAX_DOMAIN_NAME_LEN);
  char *asciiPtr = ascii;
  memset(ascii, 0, MAX_DOMAIN_NAME_LEN);

  // First, copy the DNS formatted/compressed address to the ascii array
  while (*wirePtr != 0)
  {
    // If the pointer flags are set
    if (*wirePtr >= DNS_POINTER_FLAG_VALUE)
    {
      // then the next 14 bits are an offset into the wire buffer where the relevant characters are
      unsigned int firstByte = *wirePtr << 8;
      unsigned int nextByte = *(wirePtr + 1);

      // Remove the pointer flags bits from the value
      unsigned int offset = (firstByte + nextByte) - DNS_POINTER_FLAG_MASK;
      wirePtr = wire + offset;

      jumped = TRUE;
    }
    else
    {
      *asciiPtr++ = *wirePtr++;

      // If we've jumped back to an earlier part of the message, then the new index doesn't need to be incremented
      // any more
      if (!jumped)
        updateIndex++;
    }
  }

  // If we did end up jumping, we just need to skip the two pointer bytes to get the offset to the next record
  if (jumped)
    updateIndex += 2;

  // Now convert the DNS formatted address to plain ASCII

  int nameLen = (int) strlen(ascii);

  for (int i = 0; i < nameLen; i++)
  {
    // Work label by label
    unsigned int labelLen = (unsigned int) ascii[i];

    // Shift everything in this label up one character to overwrite what was previously the label length
    for (int j = 0; j < labelLen; j++)
    {
      ascii[i] = ascii[i + 1];
      i++;
    }

    // Place a '.' after this label, where the last character in the label was previously
    ascii[i] = '.';
  }

  // Terminate string and update record offset index
  ascii[nameLen - 1] = '\0';

  *indexPtr += updateIndex;

  return ascii;
}

/**
 * Extracts the wire-formatted resource record at the offset specified by
 * *indexPtr in the array of bytes provided (wire) and returns a
 * dns_rr (struct) populated with its contents. Updates the value
 * pointed to by indexp to the next value beyond the resource record.
 */
dns_rr rr_from_wire(unsigned char *wire, int *indexPtr)
{
  dns_rr record;

  memset(&record, 0, sizeof(dns_rr));

  // Get the name from the wire. This updates the index to point to right after the name
  record.name = name_ascii_from_wire(wire, indexPtr);

  // Then, get each field, updating the index as we go

  // the funky-looking pointer arithmetic here just means
  //   - dereference the index pointer, add its value to the base wire buffer pointer
  //   - cast that to an unsigned <type> pointer (where type corresponds to the record field)
  //   - dereference that value to get the actual field value from the wire

  record.type = ntohs(*((unsigned short *) (wire + *indexPtr)));
  *indexPtr += sizeof(unsigned short);

  record.class = ntohs(*((unsigned short *) (wire + *indexPtr)));
  *indexPtr += sizeof(unsigned short);

  record.ttl = ntohl(*((unsigned int *) (wire + *indexPtr)));
  *indexPtr += sizeof(unsigned int);

  record.rdata_len = ntohs(*((unsigned short *) (wire + *indexPtr)));
  *indexPtr += sizeof(unsigned short);

  record.rdata = (unsigned char *) malloc(record.rdata_len);
  memcpy(record.rdata, (wire + *indexPtr), record.rdata_len);

  *indexPtr += record.rdata_len;

  return record;
}

/**
 * Given a domain name, a query type, and a buffer to work with, constructs a DNS query in the buffer
 */
unsigned short create_dns_query(char *qname, dns_rr_type qtype, unsigned char *wire)
{
  // First create the header

  unsigned short totalLen = 0;
  unsigned char *wirePtr = wire;

  // This lets us work with a nice struct instead of loads of offsets
  dns_header *hdr = (dns_header *) wire;

  // A random ID is sufficient for our purposes
  srand((unsigned int) time(NULL));

  hdr->id = (unsigned short) rand();

  hdr->qr = 0;
  hdr->opcode = 0;
  hdr->aa = 0;
  hdr->tc = 0;
  hdr->rd = 1;
  hdr->ra = 0;
  hdr->ad = 0;
  hdr->z = 0;
  hdr->cd = 0;
  hdr->rcode = 0;

  // We only ever permit one question
  hdr->q_count = htons(1);

  hdr->ans_count = 0;
  hdr->add_count = 0;
  hdr->auth_count = 0;

  totalLen += sizeof(dns_header);
  wirePtr += sizeof(dns_header);

  // Convert the name to DNS format

  int nameLen = name_ascii_to_wire(qname, wirePtr);

  totalLen += nameLen;
  wirePtr += nameLen;

  // Add the type and the class to the RR

  dns_query *query = (dns_query *) wirePtr;

  query->class = htons(RR_CLASS_INET);
  query->type = htons(qtype);

  totalLen += 4;

  return totalLen;
}

/**
 * Extracts the IPv4 address from the answer section, following any
 * aliases that might be found, and return the string representation of
 * the IP address.  If no address is found, then return NULL.
 */
dns_answer_entry *get_answer_address(char *qname, unsigned char *wire)
{
  // Set up our linked list. For ease of coding, we start with one entry.
  // Then, after all RRs have been processed, the last unused entry is freed.

  dns_answer_entry *entry = malloc(sizeof(dns_answer_entry));
  dns_answer_entry *head = entry;
  dns_answer_entry *last = NULL; // Predecessor, not last entry in the list

  // These are really the only parts of the headers that concern us
  // We need to know how many questions to skip over and, of course, how many answers to process
  unsigned short totalQuestions = ntohs(*((unsigned short *) (wire + 4)));
  unsigned short totalAnswerRRs = ntohs(*((unsigned short *) (wire + 6)));

  // Save us some time and processing
  if (totalAnswerRRs == 0)
    return NULL;

  // Initialise the offset to after the header, effectively skipping it
  int offset = DNS_HEADER_LEN;

  // skip each question
  for (int i = 0; i < totalQuestions; i++)
  {
    // skip question names by label lengths
    while (*(wire + offset) != 0x00)
      offset += *(wire + offset) + 1;

    // move from null terminator to type byte
    offset++;

    // skip type and class bytes
    offset += 4;
  }

  // Process each answer
  for (int i = 0; i < totalAnswerRRs; i++)
  {
    // We need to keep track of the beginning of this record in case we need to parse rdata,
    // since name_ascii_from_wire only takes the wire and an offset, not any bytes
    int thisRRoffset = offset;
    dns_rr record = rr_from_wire(wire, &offset);

    if (strcmp(qname, record.name) == 0 && record.type == RR_TYPE_IPV4)
    {
      // If we're here, it's an IP address
      entry->value = malloc(MAX_IP_ADDR_ASCII_LEN);

      inet_ntop(AF_INET, record.rdata, entry->value, MAX_IP_ADDR_ASCII_LEN);
    }
    else if (strcmp(qname, record.name) == 0 && record.type == RR_TYPE_CNAME)
    {
      // If we're here, it's a CNAME entry

      // skip the rr name
      // a little inefficient, but I didn't want to copy what is essentially the same functionality just to
      // skip the name
      name_ascii_from_wire(wire, &thisRRoffset);

      // skip type, class, ttl, and rdata_len
      thisRRoffset += CNAME_RDATA_FIXED_LEN;

      // get the canonical name from the rdata
      char *cname = name_ascii_from_wire(wire, &thisRRoffset);

      // this is what we're looking for in future records now
      qname = cname;

      entry->value = cname;
    }

    if (last != NULL)
      last->next = entry;

    last = entry;

    entry = malloc(sizeof(dns_answer_entry));
  }

  // Free the unused final entry
  free(entry);

  return head;
}

/**
 * Handles the networking bit of sending out a request and reading a response from the server
 * Returns the number of bytes received from the server
 */
int send_recv_message(unsigned char *request, int requestLen, unsigned char *response, char *server, unsigned short port)
{
  // Set up the address
  struct sockaddr_in addr;

  memset(&addr, 0, sizeof(addr));

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);

  inet_pton(AF_INET, server, &(addr.sin_addr.s_addr));

  // Create the socket
  int socketFd = socket(AF_INET, SOCK_DGRAM, 0);

  if (socketFd == -1)
  {
    perror("Couldn't open socket:");
    exit(1);
  }

  // Connect to the server
  if (connect(socketFd, (struct sockaddr *) &addr, sizeof(addr)) != 0)
  {
    perror("Couldn't connect:");
    exit(1);
  }

  // Send the data
  send(socketFd, request, (size_t) requestLen, 0);

  // Read the response
  int totalBytesRead = 0;
  totalBytesRead = (int) read(socketFd, response, 256);

  return totalBytesRead;
}

/**
 * Given a domain name query and a DNS server, constructs a DNS query, sends it, and parses the response out
 * into a linked list of IPv4 addresses
 * @param queryDomainName
 * @param dnsServer
 * @return
 */
dns_answer_entry *resolve(char *queryDomainName, char *dnsServer)
{
  canonicalize_name(queryDomainName);

  unsigned char req[MAX_REQUEST_LEN];
  unsigned char res[MAX_RESPONSE_LEN];

  memset(req, 0, MAX_REQUEST_LEN);
  memset(res, 0, MAX_RESPONSE_LEN);

  int reqLen = create_dns_query(queryDomainName, RR_TYPE_IPV4, req);

  send_recv_message(req, reqLen, res, dnsServer, 53);

  return get_answer_address(queryDomainName, res);
}

/**
 * Resolves a domain name by sending a DNS query to the specified server.
 * All associated IPv4 addresses are printed to stdout
 */
int main(int argc, char *argv[])
{
  dns_answer_entry *ans;

  if (argc < 3)
  {
    fprintf(stderr, "Usage: %s <domain name> <server>\n", argv[0]);
    exit(1);
  }

  ans = resolve(argv[1], argv[2]);

  while (ans != NULL)
  {
    printf("%s\n", ans->value);
    ans = ans->next;
  }
}
