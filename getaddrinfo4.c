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
  int status;
  char *target, *dst_ip, *text;
  unsigned char *bin;
  struct addrinfo hints, *res, *p;
  struct sockaddr_in *ipv4, dst;
  void *tmp;

  text = (char *) malloc (16 * sizeof (char));
  memset (text, 0, 16 * sizeof (char));

  target = (char *) malloc (40 * sizeof (char));
  memset (target, 0, 40 * sizeof (char));
  strcpy (target, "www.google.com");

  bin = (unsigned char *) malloc (4 * sizeof (unsigned char));
  memset (bin, 0, 4 * sizeof (unsigned char));

  dst_ip = (char *) malloc (16 * sizeof (char));
  memset (dst_ip, 0, 16 * sizeof (char));

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_INET;
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
    ipv4 = (struct sockaddr_in *) p->ai_addr;
    tmp = &(ipv4->sin_addr);
    inet_ntop (AF_INET, tmp, dst_ip, 16);
    printf ("From string: %s\n", dst_ip);

    // ... or ...

    // Also presentation form
    memset (dst_ip, 0, 16 * sizeof (char));
    inet_ntop (p->ai_family, get_in_addr ((struct sockaddr *)p->ai_addr), dst_ip, 16);
    printf ("Also from string: %s\n", dst_ip);

    memcpy (bin, &ipv4->sin_addr, 4 * sizeof (unsigned char));  // Binary from ipv4 if you have it, or
    memcpy (bin, &dst.sin_addr, 4 * sizeof (unsigned char));    // Binary from dst if you have that.

    printf ("From binary: %u.%u.%u.%u\n", bin[0], bin[1], bin[2], bin[3]);

    memset (text, 0, 16 * sizeof (char));
    inet_ntop (AF_INET, bin, text, 16);
    printf ("Also from binary: %s\n\n", text);
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
