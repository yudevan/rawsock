/*  Copyright (C) 2011-2013  P.D. Buchan (pdbuchan@yahoo.com)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// Send an IPv6 ICMP router solicitation packet.
// Change hoplimit and specify interface using ancillary
// data method.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netinet/icmp6.h>    // struct nd_router_solicit, which contains icmp6_hdr, ND_ROUTER_SOLICIT
#include <netinet/in.h>       // IPPROTO_IPV6, IPPROTO_ICMPV6, INET6_ADDRSTRLEN
#include <netinet/ip.h>       // IP_MAXPACKET (65535)
#include <arpa/inet.h>        // inet_ntop()
#include <netdb.h>            // struct addrinfo
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl. Here, we need SIOCGIFHWADDR
#include <bits/socket.h>      // structs msghdr and cmsghdr
#include <net/if.h>           // struct ifreq

#include <errno.h>            // errno, perror()

// Taken from <linux/ipv6.h>, also in <netinet/in.h>
struct in6_pktinfo {
        struct in6_addr ipi6_addr;
        int             ipi6_ifindex;
};

// Function prototypes
uint16_t checksum (uint16_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);

int
main (int argc, char **argv)
{
  int RS_HDRLEN = sizeof (struct nd_router_solicit);  // Length of RS message header
  int optlen = 8; // Option Type (1 byte) + Length (1 byte) + Length of MAC address (6 bytes)

  int i, sd, status, ifindex, cmsglen, hoplimit, psdhdrlen;
  struct addrinfo hints;
  struct addrinfo *res;
  struct sockaddr_in6 *ipv6, src, dst;
  struct nd_router_solicit *rs;
  socklen_t srclen;
  uint8_t *outpack, *options, *psdhdr;
  struct msghdr msghdr;
  struct ifreq ifr;
  struct cmsghdr *cmsghdr1, *cmsghdr2;
  struct in6_pktinfo *pktinfo;
  struct iovec iov[2];
  char *target, *source, *interface;
  void *tmp;

  // Allocate memory for various arrays.
  interface = allocate_strmem (40);
  target = allocate_strmem (INET6_ADDRSTRLEN);
  source = allocate_strmem (INET6_ADDRSTRLEN);
  outpack = allocate_ustrmem (IP_MAXPACKET);
  options = allocate_ustrmem (optlen);
  psdhdr = allocate_ustrmem (IP_MAXPACKET);

  // Interface to send packet through.
  strcpy (interface, "eth0");

  // Source (node sending solicitation) IPv6 link-local address or the IPv6 unspecified address (::).
  // You need to fill this out.
  strcpy (source, "fe80::");

  // Destination IPv6 address ("all routers" router solicitation multicast address)
  strcpy (target, "ff02::2");

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Resolve source using getaddrinfo().
  if ((status = getaddrinfo (source, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
    return (EXIT_FAILURE);
  }
  memcpy (&src, res->ai_addr, res->ai_addrlen);
  srclen = res->ai_addrlen;
  memcpy (psdhdr, src.sin6_addr.s6_addr, 16 * sizeof (uint8_t));  // Copy to checksum pseudo-header
  freeaddrinfo (res);

  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
    return (EXIT_FAILURE);
  }
  memcpy (&dst, res->ai_addr, res->ai_addrlen);
  memcpy (psdhdr + 16, dst.sin6_addr.s6_addr, 16 * sizeof (uint8_t));  // Copy to checksum pseudo-header

  // Report IPv6 "all routers" multicast address.
  ipv6 = (struct sockaddr_in6 *) res->ai_addr;
  tmp = &(ipv6->sin6_addr);
  memset (target, 0, INET6_ADDRSTRLEN * sizeof (char));
  if (inet_ntop (AF_INET6, tmp, target, INET6_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }
  printf ("Sending to IPv6 \"all routers\" multicast address: %s\n", target);
  freeaddrinfo (res);

  // Request a socket descriptor sd.
  if ((sd = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
    perror ("Failed to get socket descriptor ");
    exit (EXIT_FAILURE);
  }

  // Use ioctl() to look up soliciting node's (i.e., source's) interface name and get its MAC address.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
    perror ("ioctl() failed to get source MAC address ");
    return (EXIT_FAILURE);
  }

  // Copy source MAC address into options buffer.
  options[0] = 1;           // Option Type - "source link layer address" (Section 4.6 of RFC 4861)
  options[1] = optlen / 8;  // Option Length - units of 8 octets (RFC 4861)
  for (i=0; i<6; i++) {
    options[i+2] = (uint8_t) ifr.ifr_addr.sa_data[i];
  }

  // Report soliciting node MAC address to stdout.
  printf ("MAC address for interface %s is ", interface);
  for (i=0; i<5; i++) {
    printf ("%02x:", options[i+2]);
  }
  printf ("%02x\n", options[5+2]);

  // Bind the socket descriptor to the source address if not site-local or link-local.
  if (!(psdhdr[0] == 0xfe)) {
    if (bind (sd, (struct sockaddr *) &src, srclen) < 0) {
      perror ("Failed to bind the socket descriptor to the source address ");
      exit (EXIT_FAILURE);
    }
  }

  // Find interface index from interface name.
  // This will be put in cmsghdr data in order to specify the interface we want to use.
  if ((ifindex = if_nametoindex (interface)) == 0) {
    perror ("if_nametoindex() failed to obtain interface index ");
    exit (EXIT_FAILURE);
  }
  printf ("Soliciting node's index for interface %s is %i\n", interface, ifindex);

  // Define first part of buffer outpack to be a router solicit struct.
  rs = (struct nd_router_solicit *) outpack;
  memset (rs, 0, sizeof (*rs));

  // Populate icmp6_hdr portion of router solicit struct.
  rs->nd_rs_hdr.icmp6_type = ND_ROUTER_SOLICIT;  // 133 (RFC 4861)
  rs->nd_rs_hdr.icmp6_code = 0;              // zero for router solicitation (RFC 4861)
  rs->nd_rs_hdr.icmp6_cksum = htons(0);      // zero when calculating checksum
  rs->nd_rs_reserved = htonl (0);            // Reserved - must be set to zero (RFC 4861)

  // Append options to end of router solicit struct.
  memcpy (outpack + RS_HDRLEN, options, optlen * sizeof (uint8_t));

  // Need a pseudo-header for checksum calculation. Define length. (RFC 2460)
  // Length = source IP (16 bytes) + destination IP (16 bytes)
  //        + upper layer packet length (4 bytes) + zero (3 bytes)
  //        + next header (1 byte)
  psdhdrlen = 16 + 16 + 4 + 3 + 1 + RS_HDRLEN + optlen;

  // Prepare msghdr for sendmsg().
  memset (&msghdr, 0, sizeof (msghdr));
  msghdr.msg_name = &dst;  // Destination IPv6 address (as struct sockaddr_in6)
  msghdr.msg_namelen = sizeof (dst);
  memset (&iov, 0, sizeof (iov));
  iov[0].iov_base = (uint8_t *) outpack;  // Point msghdr to buffer outpack
  iov[0].iov_len = RS_HDRLEN + optlen;
  msghdr.msg_iov = iov;                 // scatter/gather array
  msghdr.msg_iovlen = 1;                // number of elements in scatter/gather array

  // Tell msghdr we're adding cmsghdr data to change hop limit and specify interface.
  // Allocate some memory for our cmsghdr data.
  cmsglen = CMSG_SPACE (sizeof (int)) + CMSG_SPACE (sizeof (struct in6_pktinfo));
  msghdr.msg_control = allocate_ustrmem (cmsglen);
  msghdr.msg_controllen = cmsglen;

  // Change hop limit to 255 as required for router solicitation (RFC 4861).
  hoplimit = 255;
  cmsghdr1 = CMSG_FIRSTHDR (&msghdr);
  cmsghdr1->cmsg_level = IPPROTO_IPV6;
  cmsghdr1->cmsg_type = IPV6_HOPLIMIT;  // We want to change hop limit
  cmsghdr1->cmsg_len = CMSG_LEN (sizeof (int));
  *((int *) CMSG_DATA (cmsghdr1)) = hoplimit;

  // Specify source interface index for this packet via cmsghdr data.
  cmsghdr2 = CMSG_NXTHDR (&msghdr, cmsghdr1);
  cmsghdr2->cmsg_level = IPPROTO_IPV6;
  cmsghdr2->cmsg_type = IPV6_PKTINFO;  // We want to specify interface here
  cmsghdr2->cmsg_len = CMSG_LEN (sizeof (struct in6_pktinfo));
  pktinfo = (struct in6_pktinfo *) CMSG_DATA (cmsghdr2);
  pktinfo->ipi6_ifindex = ifindex;

  // Compute ICMPv6 checksum (RFC 2460).
  // psdhdr[0 to 15] = source IPv6 address, set earlier.
  // psdhdr[16 to 31] = destination IPv6 address, set earlier.
  psdhdr[32] = 0;  // Length should not be greater than 65535 (i.e., 2 bytes)
  psdhdr[33] = 0;  // Length should not be greater than 65535 (i.e., 2 bytes)
  psdhdr[34] = (RS_HDRLEN + optlen)  / 256;  // Upper layer packet length
  psdhdr[35] = (RS_HDRLEN + optlen)  % 256;  // Upper layer packet length
  psdhdr[36] = 0;  // Must be zero
  psdhdr[37] = 0;  // Must be zero
  psdhdr[38] = 0;  // Must be zero
  psdhdr[39] = IPPROTO_ICMPV6;
  memcpy (psdhdr + 40, outpack, (RS_HDRLEN + optlen) * sizeof (uint8_t));
  rs->nd_rs_hdr.icmp6_cksum = checksum ((uint16_t *) psdhdr, psdhdrlen);

  printf ("Checksum: %x\n", ntohs (rs->nd_rs_hdr.icmp6_cksum));

  // Send packet.
  if (sendmsg (sd, &msghdr, 0) < 0) {
    perror ("sendmsg() failed ");
    exit (EXIT_FAILURE);
  }
  close (sd);

  // Free allocated memory.
  free (interface);
  free (target);
  free (source);
  free (outpack);
  free (options);
  free (psdhdr);
  free (msghdr.msg_control);

  return (EXIT_SUCCESS);
}

// Checksum function
uint16_t
checksum (uint16_t *addr, int len)
{
  int nleft = len;
  int sum = 0;
  uint16_t *w = addr;
  uint16_t answer = 0;

  while (nleft > 1) {
    sum += *w++;
    nleft -= sizeof (uint16_t);
  }

  if (nleft == 1) {
    *(uint8_t *) (&answer) = *(uint8_t *) w;
    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  answer = ~sum;

  return (answer);
}

// Allocate memory for an array of chars.
char *
allocate_strmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of unsigned chars.
uint8_t *
allocate_ustrmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}
