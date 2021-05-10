# apip
p4 implementation of Accountable and Private Internet Protocol


We choose 0x87DD to indicate the apip protocol.

The first four bits of an apip packet, otherwise known as the "apip_flag" are 4 bits  that indicate what type of message a packet using the apip protocol is. 

0 is reserved to possibly indicate that the field is not set for internal usage in switches.

1 indicates a non hashed packet
2 indicates a brief from a sender to an accountability delegate
3 indicates a verification request
4 indicates a verification response
5 indicates a shutoff message from a receiver to an accountability delegate


