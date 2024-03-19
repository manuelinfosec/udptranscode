# UDP Transcoder

UDPTranscoder is a lightweight application designed to facilitate the transmission 
of User Datagram Protocol (UDP) packets across network boundaries restricted to 
outgoing Transmission Control Protocol (TCP) connections. This functionality is 
particularly applicable to multimedia conferencing applications, which often rely
on UDP for real-time data exchange.

Imagine you're setting up a video call, but there's a  firewall in the way. 
That firewall only lets outgoing regular traffic (TCP connections) through, 
but your video call needs a different type of traffic (UDP packets) to function. 
UDPTranscoder comes to the rescue!

This program acts like a tunnel, sending those UDP packets back and forth within 
a standard TCP connection. So the firewall doesn't even know the difference, and 
your video call can flow smoothly.

**Security Note:** While this may a handy tool, it's important to remember that firewalls 
exist for security reasons. Only use this on trusted networks.

<h2>Installation</h2>

<p>To build, unpack the tar file or clone from Github, then type:</p>
<blockquote>
<p><samp>./configure</samp><br />
<samp>make</samp><br />
(optionally) <samp>make install</samp></p>
</blockquote>

<p>The <samp>configure</samp> script is a standard GNU autoconf-generated
configure script; the usual options for it apply.  The only option which 
should be necessary for normal use is
<samp>--prefix=<i>/path/to/install</i></samp>, which allows you to specify
where <samp>make install</samp> will put the installed binary.  Type
<samp>./configure --help</samp> for a full list of supported options.</p>


<h2>Usage</h2>
<p>UDPTranscoder can be run in two modes: a client mode and a server mode.  The
client mode initiates the TCP connection before relaying UDP; the server
waits for an incoming connection before doing so.  After the TCP connection
is established, the behavior of the two modes is identical.  If you are
using UDPTranscoder to traverse a firewall as discussed above, the client would
be run inside the firewall, and the server would be run outside it.</p>

<h3>Options</h3>
<blockquote>
<dl>
<dt><samp>-s</samp> <i>TCP-port</i></dt>
<dd><b>Server mode</b><br />
If udptranscode is invoked with the -s option, it runs in server mode: the
server will wait for an incoming connection on the specified TCP port, and
then relay UDP to and from it.</dd>
<dt><samp>-c</samp> <i>TCP-addr[/TCP-port]</i></dt>
<dd><b>Client mode</b><br />
If udptranscode is invoked with the -c option, it runs in client mode: it
will open a TCP connection to the specified TCP host and port, and then
relay UDP on it.
<p>The TCP port may be omitted in this case; it will default to the same
port number as the UDP port.</p></dd>
<dt><samp>-r</samp></dt>
<dd><b>RTP mode</b><br />
In order to facilitate tunneling both RTP and RTCP traffic for a
multi-media conference, this sets up relays on two consecutive TCP and UDP
ports.  All specified port numbers in this case must be even.  Note that
both the client and the server must use the <samp>-r</samp> flag for this to
work; the server will not begin relaying packets until both its connections
have been established.</dd>
<dt><samp>-v</samp></dt>
<dd><b>Verbose output</b><br />
<p>This flag turns on verbose debugging output about UDPTranscoder's actions.
It may be given multiple times.  With a single <samp>-v</samp>,
information about connection establishment is printed on UDPTranscoder's
standard error stream; with a second one, per-packet information is also
shown.  Note that this latter case can produce a prodigious amount of
information.</p>
<p>If this flag is not given, UDPTranscoder will remain silent unless an
error occurs.</p></dd>
</dl>
</blockquote>

<p>One of the two options <samp>-c</samp> and <samp>-s</samp> must be
given; if not, it is an error.</p>

<p>In all cases, the UDP address and port to tunnel is given after all
options.  UDPTranscoder will listen to this adddress for packets, and will send
received packets on this address.  The address may be a multicast address;
in this case, a multicast TTL should be specified, and tunneled packets will
be sent with this TTL.  All addresses, TCP and UDP, may be specified either
as an IPv4 dotted-quad address (e.g. 224.2.0.1) or as a host name
(e.g. <samp>google.com</samp>).  Port numbers must be in the
range of 1 to 65535; TTLs must be in the range 0 to 255.</p>

<h2>Packet Format</h2>
<p>The packets are sent on TCP using the obvious, simple format: a sixteen-bit
length field, in network byte order, precedes each data packet.  This
format was proposed in early drafts of RTP for RTP-over-TCP, but was dropped
from the final specification.</p>

<h2>Known Bugs/Issues</h2>
<p>UDPTranscoder does not check incoming UDP packets to verify that they are
indeed coming from the address which the user specified; it binds to
INADDR_ANY, and accepts any UDP packet arriving on the specified port.  This
could potentially allow denial-of-service or spoofing attacks.  If two or
more <samp>-v</samp> options are given, per-packet identification will be
printed of each packet's source address as it is received, allowing such a
situation to be diagnosed.</p>

<p>For multicast, UDPTranscoder turns off packet loopback, as it has no way to
distinguish its own packets it sent out from packets genuinely arriving on
the multicast group.  This means that if you are tunneling traffic from or
to a multicast group, both ends of UDPTranscoder must be run on different hosts
than any member of the group.  (In general, the only way to distinguish
looped packets from packets genuinely received from other applications on
the local host is with application-layer labeling, as RTP does.)</p>

<p>UDPTranscoder is designed to tunnel RTP-style traffic, in which applications
send and receive UDP packets to and from the same port (or pair of ports).
It does not support request/response-style traffic, in which a client
request is sent from a transient port X to a well-known port Y, and the
server's response is returned from port Y to port X.</p>

<p>UDPTranscoder deliberately ignores "Connection Refused" errors on the UDP
port, clearing the socket error state, so that a tunnel may be set up before
conferencing tools are started on both ends.  This may mean that a mis-typed
UDP address or port is not recognized, as no error is printed.  If two or
more <samp>-v</samp> options are given, a diagnostic will be printed
whenever the error state is cleared from the socket.</p>

<p>Once one endpoint of a tunnel is taken down, closing the socket, the
other one exits as well; to re-establish the tunnel, UDPTranscoder must be
restarted on both sides.</p>

<p>IP version 6 is not supported.</p>