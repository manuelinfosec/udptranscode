/* Wait for an incoming TCP connection.  Once it arrives, listen for UDP on
 * the specified port, then send the UDP packets (with a length header) over
 * the TCP connection */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "host2ip.h"

// Define the size of the buffer for UDP packets
#define UDPBUFFERSIZE 65536

// Define the size of the buffer for TCP packets, including the UDP packet size and additional space for the length field
#define TCPBUFFERSIZE (UDPBUFFERSIZE + 2) /* UDP packet + 2 (length field) */

// Macro to set the maximum file descriptor value for select() function
#define SET_MAX(fd) do { if (max < (fd) + 1) { max = (fd) + 1; } } while (0)

#if (SIZEOF_SHORT == 2)
// Typedef for a 16-bit unsigned integer when the size of a short integer is 2 bytes
typedef unsigned short u_int16;
#else
// Error message when the size of a short integer is not 2 bytes
#error Need a typedef for a 16-bit type
#endif


// Define an alias for an 8-bit unsigned integer
typedef unsigned char u_int8;

// Structure for an outgoing packet
struct out_packet {
  u_int16 length;     // Length of the packet data
  char buf[UDPBUFFERSIZE]; // Buffer to hold the packet data
};

// Structure for a relay connection
struct relay {
  struct sockaddr_in udpaddr; // UDP socket address
  struct sockaddr_in tcpaddr; // TCP socket address
  u_int8 udp_ttl;             // Time-to-live for UDP packets
  int multicast_udp;          // Flag indicating whether UDP multicast is used

  int udp_send_sock;   // UDP sending socket
  int udp_recv_sock;   // UDP receiving socket
  int tcp_listen_sock; // TCP listening socket
  int tcp_sock;        // TCP socket

  char buf[TCPBUFFERSIZE]; // Buffer to hold TCP packet data
  char *buf_ptr, *packet_start; // Pointers to buffer and packet start
  int packet_length;            // Length of the current packet in buffer
  enum {uninitialized = 0, reading_length, reading_packet} state; // State of the relay (e.g., uninitialized, reading length, reading packet)
};

static int debug = 0;

/*
 * usage()
 * Print the program usage info, and exit.
 */
static void usage(char *progname) {
  fprintf(stderr, "Usage: %s -s TCP-port [-r] [-v] UDP-addr/UDP-port[/ttl]\n",
          progname);
  fprintf(stderr, "    or %s -c TCP-addr[/TCP-port] [-r] [-v] UDP-addr/UDP-port[/ttl]\n",
          progname);
  fprintf(stderr, "     -s: Server mode.  Wait for TCP connections on the port.\n");
  fprintf(stderr, "     -c: Client mode.  Connect to the given address.\n");
  fprintf(stderr, "     -r: RTP mode.  Connect/listen on ports N and N+1 for both UDP and TCP.\n");
  fprintf(stderr, "         Port numbers must be even.\n");
  fprintf(stderr, "     -v: Verbose mode.  Specify -v multiple times for increased verbosity.\n");
  exit(2);
} /* usage */

/*
 * Function: parse_args
 * --------------------
 * Parses command line arguments to initialize relay parameters.
 *
 * argc: Number of command line arguments
 * argv: Array of command line argument strings
 * relays: Pointer to an array of relay structures
 * relay_count: Pointer to integer storing the count of relays
 * is_server: Pointer to integer indicating whether the program is acting as a server or client
 */
static void parse_args(int argc, char *argv[], struct relay **relays,
                       int *relay_count, int *is_server)
{
  int c;
  char *tcphostname, *tcpportstr, *udphostname, *udpportstr, *udpttlstr;
  struct in_addr tcpaddr, udpaddr;
  int tcpport, udpport, udpttl;
  int i;

  *is_server = -1;
  *relay_count = 1;
  debug = 0;
  tcphostname = NULL;
  tcpportstr = NULL;

  // Parse command line options
  while ((c = getopt(argc, argv, "s:c:rvh")) != EOF) {
    switch (c) {
    case 's':
      // Set server mode and parse TCP port
      if (*is_server != -1) {
        fprintf(stderr, "%s: Only one of -s and -c may be specified.\n",
                argv[0]);
        exit(2);
      }
      *is_server = 1;
      tcpportstr = optarg;
      break;
    case 'c':
      // Set client mode and parse TCP hostname
      if (*is_server != -1) {
        fprintf(stderr, "%s: Only one of -s and -c may be specified.\n",
                argv[0]);
        exit(2);
      }
      *is_server = 0;
      tcphostname = optarg;
      break;
    case 'r':
      // Enable relay mode
      *relay_count = 2;
      break;
    case 'v':
      // Increase debug verbosity
      debug++;
      break;
    case 'h':
    case '?':
    default:
      // Display usage information for invalid options
      usage(argv[0]);
      break;
    }
  }

  // Check if server or client mode is specified
  if (*is_server == -1) {
    fprintf(stderr, "%s: You must specify one of -s and -c.\n",
            argv[0]);
    exit(2);
  }

  // Check for correct number of command line arguments
  if (argc <= optind) {
    usage(argv[0]);
  }

  // Parse UDP host, port, and TTL
  udphostname = strtok(argv[optind], ":/ ");
  udpportstr = strtok(NULL, ":/ ");
  if (udpportstr == NULL) {
    usage(argv[0]);
  }
  udpttlstr = strtok(NULL, ":/ ");

  // Parse TCP host and port (for client mode)
  if (!*is_server) {
    tcphostname = strtok(tcphostname, ":/ ");
    tcpportstr = strtok(NULL, ":/ ");
  }
  else {
    tcphostname = NULL;
  }

  // Convert port strings to integers
  errno = 0;
  udpport = strtol(udpportstr, NULL, 0);
  if (errno || udpport <= 0 || udpport >= 65536) {
    fprintf(stderr, "%s: invalid port number\n", udpportstr);
    exit(2);
  }

  // Convert TTL string to integer
  if (udpttlstr != NULL) {
    errno = 0;
    udpttl = strtol(udpttlstr, NULL, 0);
    if (errno || udpttl < 0 || udpttl >= 256) {
      fprintf(stderr, "%s: invalid TTL\n", udpttlstr);
      exit(2);
    }
  }
  else {
    udpttl = 1;
  }

  // Parse TCP port (for client mode)
  if (tcpportstr != NULL) {
    errno = 0;
    tcpport = strtol(tcpportstr, NULL, 0);
    if (errno || tcpport <= 0 || tcpport >= 65536) {
      fprintf(stderr, "%s: invalid port number\n", tcpportstr);
      exit(2);
    }
  }
  else {
    tcpport = udpport;
  }

  // Check for even port numbers in relay mode
  if (*relay_count == 2 && (tcpport % 2 != 0 || udpport % 2 != 0)) {
    fprintf(stderr, "Port numbers must be even when using relay mode.\n");
    exit(2);
  }

  // Resolve UDP host
  udpaddr = host2ip(udphostname);
  if (udpaddr.s_addr == INADDR_ANY) {
    fprintf(stderr, "%s: UDP host unknown\n", udphostname);
    exit(2);
  }

  // Resolve TCP host (for client mode)
  if (*is_server) {
    tcpaddr.s_addr = INADDR_ANY;
  }
  else {
    tcpaddr = host2ip(tcphostname);
    if (tcpaddr.s_addr == INADDR_ANY) {
      fprintf(stderr, "%s: TCP host unknown\n", tcphostname);
      exit(2);
    }
  }
   
  // Allocate memory for relay structures
  *relays = (struct relay *) calloc(*relay_count, sizeof(struct relay));
  if (relays == NULL) {
    perror("Error allocating relay structure");
    exit(1);
  }

  // Initialize relay parameters
  for (i = 0; i < *relay_count; i++) {
    (*relays)[i].udpaddr.sin_addr = udpaddr;
    (*relays)[i].udpaddr.sin_port = htons(udpport + i);
    (*relays)[i].udpaddr.sin_family = AF_INET;
    (*relays)[i].udp_ttl = udpttl;
    (*relays)[i].multicast_udp = IN_MULTICAST(htons(udpaddr.s_addr));

    (*relays)[i].tcpaddr.sin_addr = tcpaddr;
    (*relays)[i].tcpaddr.sin_port = htons(tcpport + i);
    (*relays)[i].tcpaddr.sin_family = AF_INET;
  }
}

/*
 * Function: setup_udp_recv
 * ------------------------
 * Set up the UDP receiving socket for the specified relay.
 * Exit the program if any error occurs during setup.
 *
 * relay: Pointer to the relay structure containing UDP setup information
 */
static void setup_udp_recv(struct relay *relay)
{
  int opt;
  struct sockaddr_in udp_recv_addr;

  // Create UDP receiving socket
  if ((relay->udp_recv_sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("setup_udp_recv: socket");
    exit(1);
  }

  // Set "reuseaddr" option for the socket
  opt = 1;
  if (setsockopt(relay->udp_recv_sock, SOL_SOCKET, SO_REUSEADDR,
                 (void *)&opt, sizeof(opt)) < 0) {
    perror("setup_udp_recv: setsockopt(SO_REUSEADDR)");
    exit(1);
  }

  // Set "reuseport" option if available
#ifdef SO_REUSEPORT
  opt = 1;
  if (setsockopt(relay->udp_recv_sock, SOL_SOCKET, SO_REUSEPORT,
                 (void *)&opt, sizeof(opt)) < 0) {
    perror("setup_udp_recv: setsockopt(SO_REUSEPORT)");
    exit(1);
  }
#endif

  // Set up multicast group membership if multicast UDP is enabled
  if (relay->multicast_udp) {
#ifdef IP_ADD_MEMBERSHIP
    struct ip_mreq mreq;  // Multicast group membership structure

    mreq.imr_multiaddr = relay->udpaddr.sin_addr;
    mreq.imr_interface.s_addr = INADDR_ANY;

    if (setsockopt(relay->udp_recv_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   (void *)&mreq, sizeof(mreq)) < 0) {
      perror("setup_udp_recv: setsockopt(IP_ADD_MEMBERSHIP)");
      exit(1);
    }
#else
    fprintf(stderr, "Multicast addresses not supported\n");
    exit(1);
#endif
  }

  // Copy UDP address information and bind the socket
  memcpy(&udp_recv_addr, &(relay->udpaddr), sizeof(struct sockaddr_in));
  
  // Adjust the UDP address if multicast UDP is disabled
  if (!(relay->multicast_udp)) {
    udp_recv_addr.sin_addr.s_addr = INADDR_ANY;
  }

  // Bind the socket to the UDP address
  if (bind(relay->udp_recv_sock, (struct sockaddr *)&udp_recv_addr,
           sizeof(udp_recv_addr)) < 0) {
    perror("setup_udp_recv: bind");
    exit(1);
  }

  return;
} /* setup_udp_recv */

/*
 * Function: setup_udp_send
 * -------------------------
 * Set up the UDP sending socket for the specified relay.
 * Exit the program if any error occurs during setup.
 *
 * relay: Pointer to the relay structure containing UDP setup information
 */
static void setup_udp_send(struct relay *relay)
{
  // Create UDP socket
  if ((relay->udp_send_sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("setup_udp_send: socket");
    exit(1);
  }

  // Connect UDP socket to specified address
  if (connect(relay->udp_send_sock, (struct sockaddr *) &(relay->udpaddr),
              sizeof(relay->udpaddr)) < 0) { 
    perror("setup_udp_send: connect");
    exit(1);
  }

  // Configure multicast options if applicable
  if (IN_MULTICAST(htonl(relay->udpaddr.sin_addr.s_addr))) {
#ifdef IP_MULTICAST_LOOP
    u_int8 loop = 0;

    if (setsockopt(relay->udp_send_sock, IPPROTO_IP, IP_MULTICAST_LOOP,
                   (void *)&loop, sizeof(loop)) < 0) {
      perror("setup_udp_send: setsockopt(IP_MULTICAST_LOOP)");
      exit(1);
    }
#endif

#ifdef IP_MULTICAST_TTL
    if (setsockopt(relay->udp_send_sock, IPPROTO_IP, IP_MULTICAST_TTL,
                   (void *)&(relay->udp_ttl), sizeof(relay->udp_ttl)) < 0) {
      perror("setup_udp_send: setsockopt(IP_MULTICAST_TTL)");
      exit(1);
    }
#endif
  }
} /* setup_udp_send */


/*
 * Function: setup_server_listen
 * -----------------------------
 * Set up a TCP listening socket, and wait for an incoming connection to
 * it. Fill in the socket in the relay structure.
 * Exit the program if any error occurs during setup.
 *
 * relay: Pointer to the relay structure containing TCP setup information
 */
static void setup_server_listen(struct relay *relay)
{
  int opt;

  // Create TCP listening socket
  if ((relay->tcp_listen_sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
    perror("setup_server_listen: socket");
    exit(1);
  }
    
  // Set "reuseaddr" option for the socket
  opt = 1;
  if (setsockopt(relay->tcp_listen_sock, SOL_SOCKET, SO_REUSEADDR,
                 (void *)&opt, sizeof(opt)) < 0) {
    perror("setup_server_listen: setsockopt(SO_REUSEADDR)");
    exit(1);
  }
  
#ifdef SO_REUSEPORT
  opt = 1;
  if (setsockopt(relay->tcp_listen_sock, SOL_SOCKET, SO_REUSEPORT,
                 (void *)&opt, sizeof(opt)) < 0) { 
    perror("setup_server_listen: setsockopt(SO_REUSEPORT)");
    exit(1);
  }
#endif

  // Bind TCP listening socket
  if (bind(relay->tcp_listen_sock, (struct sockaddr *)&(relay->tcpaddr),
           sizeof(relay->tcpaddr)) < 0) {
    perror("setup_server_listen: bind");
    exit(1);
  }
    
  // Listen for incoming connections
  if (listen(relay->tcp_listen_sock, 1) < 0) {
    perror("setup_server_listen: listen");
    exit(1);
  }

  // Initialize relay's TCP socket
  relay->tcp_sock = -1;

  if (debug) fprintf(stderr, "Listening for TCP connections on port %hu\n",
                     ntohs(relay->tcpaddr.sin_port));
} /* setup_server_listen */


/*
 * Function: await_incoming_connections
 * -------------------------------------
 * Wait for connections to be established to all the TCP listeners.
 * Fill in the tcp_sock element of each relay.
 * Exit the program if any error occurs during setup.
 *
 * relays: Array of relay structures
 * relay_count: Number of relays
 */
static void await_incoming_connections(struct relay *relays, int relay_count) 
{
  int i;
  fd_set readfds;
  int max = 0;
  int all_connected;

  do {
    FD_ZERO(&readfds);
    all_connected = 1;
    for (i = 0; i < relay_count; i++) {
      if (relays[i].tcp_sock == -1) {
        // Only count relays we haven't had connections on yet
        all_connected = 0;
        FD_SET(relays[i].tcp_listen_sock, &readfds);
        SET_MAX(relays[i].tcp_listen_sock);
      }
    }
    
    if (all_connected) break;
    
    if (select(max, &readfds, NULL, NULL, NULL) < 0) {
      if (errno != EINTR) {
        perror("await_incoming_connection: select");
        exit(1);
      }
    }
    
    for (i = 0; i < relay_count; i++) {
      if (FD_ISSET(relays[i].tcp_listen_sock, &readfds)) {
        struct sockaddr_in client_addr;
        int addrlen = sizeof(client_addr);
        
        if ((relays[i].tcp_sock =
             accept(relays[i].tcp_listen_sock,
                    (struct sockaddr *) &client_addr, &addrlen)) < 0) {
          perror("await_incoming_connections: accept");
          exit(1);
        }
        
        if (debug) {
          fprintf(stderr, "TCP connection from %s/%hu\n",
                  inet_ntoa(client_addr.sin_addr),
                  ntohs(client_addr.sin_port));
        }
      }
    }
  } while (!all_connected);
} /* await_incoming_connections */


/*
 * Function: setup_tcp_client
 * ---------------------------
 * Connect the given relay to the desired address.
 * Fill in the tcp_sock element of the relay structure.
 * Exit the program if any error occurs during setup.
 *
 * relay: Pointer to the relay structure containing TCP setup information
 */
static void setup_tcp_client(struct relay *relay)
{
  // Create TCP socket
  if ((relay->tcp_sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
    perror("setup_tcp_client: socket");
    exit(1);
  }

  // Connect TCP socket to specified address
  if (connect(relay->tcp_sock, (struct sockaddr *) &(relay->tcpaddr),
              sizeof(relay->tcpaddr)) < 0) {
    perror("setup_tcp_client: connect");
    exit(1);
  }

  if (debug) fprintf(stderr, "Connected TCP to %s/%hu\n",
                     inet_ntoa(relay->tcpaddr.sin_addr),
                     ntohs(relay->tcpaddr.sin_port));
} /* setup_tcp_client */


/*
 * Function: udp_to_tcp
 * ---------------------
 * Forward a UDP packet received on the relay's UDP port to the TCP port.
 * If an error occurs during transmission or reception, return non-zero.
 *
 * relay: Pointer to the relay structure containing UDP and TCP socket information
 */
static int udp_to_tcp(struct relay *relay)
{
  struct out_packet p;
  int buflen;
  struct sockaddr_in remote_udpaddr;
  int addrlen = sizeof(remote_udpaddr);

  // Receive UDP packet
  if ((buflen = recvfrom(relay->udp_recv_sock, p.buf, UDPBUFFERSIZE, 0,
                         (struct sockaddr *) &remote_udpaddr,
                         &addrlen)) <= 0) {
    if (buflen < 0) {
      perror("udp_to_tcp: recv");
    }
    return 1;
  }

  // Log debug information if enabled
  if (debug > 1) {
    fprintf(stderr, "Received %d byte UDP packet from %s/%hu\n", buflen,
            inet_ntoa(remote_udpaddr.sin_addr),
            ntohs(remote_udpaddr.sin_port));
  }

  // Prepare packet length and send it to TCP port
  p.length = htons(buflen);
  if (send(relay->tcp_sock, (void *) &p, buflen+sizeof(p.length), 0) < 0) {
    perror("udp_to_tcp: send");
    return 1;
  }

  return 0;
} /* udp_to_tcp */


/*
 * Function: tcp_to_udp
 * ---------------------
 * Read data from the relay's TCP socket and send complete packets to the UDP port.
 * If an error occurs during transmission or reception, return non-zero.
 *
 * relay: Pointer to the relay structure containing UDP and TCP socket information
 */
static int tcp_to_udp(struct relay *relay)
{
  int read_len;

  // Initialize relay's state if uninitialized
  if (relay->state == uninitialized) {
    relay->state = reading_length;
    relay->buf_ptr = relay->buf;
    relay->packet_start = relay->buf;
    relay->packet_length = 0;
  }

  // Read data from TCP socket
  if ((read_len = read(relay->tcp_sock, relay->buf_ptr,
                       (relay->buf + TCPBUFFERSIZE - relay->buf_ptr))) <= 0) {
    if (read_len < 0) {
      perror("tcp_to_udp: read");
    }
    return 1;
  }
    
  relay->buf_ptr += read_len;

  // Process received data
  if (relay->state == reading_length) {
    if (relay->buf_ptr - relay->packet_start < sizeof(u_int16)) {
      return 0;
    }
    relay->packet_length = ntohs(*(u_int16 *)relay->packet_start);
    relay->packet_start += sizeof(u_int16);
    relay->state = reading_packet;
  }
  if (relay->buf_ptr - relay->packet_start < relay->packet_length) {
    return 0;
  }

  // Send complete UDP packet
  if (debug > 1) {
    fprintf(stderr, "Received packet on TCP, length %u; sending as UDP\n",
            relay->packet_length);
  }
  if (send(relay->udp_send_sock, relay->packet_start,
           relay->packet_length, 0) < 0) {
    if (errno != ECONNREFUSED) {
      perror("tcp_to_udp: send");
      return 1;
    }
    else {
      // Handle connection refusal gracefully
      int err, len = sizeof(err);

      if (debug > 1) {
        fprintf(stderr, "ECONNREFUSED on udp_send_sock; clearing.\n");
      }
      if (getsockopt(relay->udp_send_sock, SOL_SOCKET, SO_ERROR,
                     (void *)&err, &len) < 0) {
        perror("tcp_to_udp: getsockopt(SO_ERROR)");
        return 1;
      }
    }
  }

  // Adjust buffer pointers and relay state
  memmove(relay->buf, relay->packet_start + relay->packet_length,
          relay->buf_ptr - (relay->packet_start + relay->packet_length));
  relay->buf_ptr -= relay->packet_length + (relay->packet_start - relay->buf);
  relay->packet_start = relay->buf;
  relay->state = reading_length;

  return 0;
} /* tcp_to_udp */


/* main */
int main(int argc, char *argv[])
{
  struct relay *relays; // Array of relay structures to manage UDP-TCP conversion
  int relay_count, is_server; // Number of relays and server/client mode indicator
  int i; // Loop counter
  fd_set readfds; // File descriptor set for select() monitoring
  int max = 0; // Maximum file descriptor value for select()
  int ok; // Flag indicating if data forwarding operations are successful

  // Parse command-line arguments and initialize relays
  parse_args(argc, argv, &relays, &relay_count, &is_server);

  // Set up relay connections
  for (i = 0; i < relay_count; i++) {
    if (is_server) {
      setup_server_listen(&relays[i]);
    }
    else {
      setup_tcp_client(&relays[i]);
    }
    setup_udp_recv(&relays[i]);
    setup_udp_send(&relays[i]);
  }

  // If in server mode, wait for incoming TCP connections
  if (is_server) {
    await_incoming_connections(relays, relay_count);
  }

  // Main loop for data forwarding between UDP and TCP ports
  do {
    FD_ZERO(&readfds); // Clear file descriptor set
    for (i = 0; i < relay_count; i++) {
      // Add TCP and UDP sockets to the file descriptor set
      FD_SET(relays[i].tcp_sock, &readfds);
      SET_MAX(relays[i].tcp_sock);
      FD_SET(relays[i].udp_recv_sock, &readfds);
      SET_MAX(relays[i].udp_recv_sock);
    }

    // Monitor file descriptors for readability
    if (select(max, &readfds, NULL, NULL, NULL) < 0) {
      if (errno != EINTR) {
        perror("main loop: select");
        exit(1);
      }
    }

    ok = 0; // Initialize success flag
    for (i = 0; i < relay_count; i++) {
      // Forward TCP data to UDP and vice versa
      if (FD_ISSET(relays[i].tcp_sock, &readfds)) {
        ok += tcp_to_udp(&relays[i]);
      }
      if (FD_ISSET(relays[i].udp_recv_sock, &readfds)) {
        ok += udp_to_tcp(&relays[i]);
      }
    }
  } while (ok == 0); // Continue loop until there's an error in data forwarding

  exit(0); // Exit the program with success status
} /* main */
