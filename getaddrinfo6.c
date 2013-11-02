#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

// Function prototype
void *get_in_addr (struct sockaddr *);

int
main (int argc, char **argv)
{
  int i, status;
  char *target, *dst_ip, *text;
  unsigned char *bin;
  struct addrinfo hints, *res, *p;
  struct sockaddr_in6 *ipv6, dst;
  void *tmp;

  text = (char *) malloc (40 * sizeof (char));
  memset (text, 0, 40 * sizeof (char));

  target = (char *) malloc (40 * sizeof (char));
  memset (target, 0, 40 * sizeof (char));
  strcpy (target, "ipv6.google.com");

  bin = (unsigned char *) malloc (16 * sizeof (unsigned char));
  memset (bin, 0, 16 * sizeof (unsigned char));

  dst_ip = (char *) malloc (INET6_ADDRSTRLEN);
  memset (dst_ip, 0, INET6_ADDRSTRLEN);

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }

  // Loop through results and demonstrate various uses of them.
  for (p = res; p != NULL; p = p->ai_next) {

    memcpy (&dst, p->ai_addr, p->ai_addrlen);  // Struct needed for msghdr

    // Presentation form
    ipv6 = (struct sockaddr_in6 *) p->ai_addr;
    tmp = &(ipv6->sin6_addr);
    inet_ntop (AF_INET6, tmp, dst_ip, 40);
    printf ("From string: %s\n", dst_ip);

    // ... or ...

    // Also presentation form
    memset (dst_ip, 0, INET6_ADDRSTRLEN);
    inet_ntop (p->ai_family, get_in_addr ((struct sockaddr *)p->ai_addr), dst_ip, INET6_ADDRSTRLEN);
    printf ("Also from string: %s\n", dst_ip);

    memcpy (bin, ipv6->sin6_addr.s6_addr, 16 * sizeof (unsigned char));  // Binary from ipv6 if you have it, or
    memcpy (bin, dst.sin6_addr.s6_addr, 16 * sizeof (unsigned char));    // Binary from dst if you have that.

    printf ("From binary: ");
    i = 0;
    while (i<14) {
      printf ("%02x%02x:", bin[i], bin[i+1]);
      i += 2;
    }
    printf ("%02x%02x\n", bin[14], bin[15]);

    memset (text, 0, INET6_ADDRSTRLEN);
    inet_ntop (AF_INET6, bin, text, INET6_ADDRSTRLEN);
    printf ("Also from binary: %s\n", text);
  }

  freeaddrinfo (res);

  return (EXIT_SUCCESS);
}

// Get sockaddr (IPv4 or IPv6).
void *get_in_addr (struct sockaddr *sa)
{
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }

  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}
