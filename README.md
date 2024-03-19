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
