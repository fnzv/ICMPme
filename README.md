# ICMPme
Instant messagging via encrypted ICMP Packets.
<br><br>

 Your Pc  -----> ICMP PACKET(with encapsulated message)----->Router\Firewall\Proxy--------------->Destination Pc <br>
<br>

**Features**:<br>
* Uses ICMP Protocol payload to transport data\msgs
* Bypass Firewalls,Proxies and Routers that uses standard firewalling rules to block traffic
* Avoid censorship
* Anonimity with 256 bit AES CTR Symmetric Encryption


## Usage:<br>
I like to keep my stuff simple stupid(KISS):
<br>
`./ICMPme.py -ip DestinationIP`<br>
The other end point must execute ICMPme to Send\Recieve messages.<br>
Once both Clients started ICMPme they can start exchanging encrypted ICMPme messages over (W)LAN\WAN<br>
The exchange of keys isn't managed via ICMPme script(in the todo list) :<br>
1) **private_auth_code**: is being used to verify that the message is send only to the endpoint<br>
2) **key**: is the 256 Bit key used by the AES CTR Encryption algorithm<br>
<br><br>

### Why Ping packets?
Well that's easy... no one will be able to know if these ICMP packets are Pings from one host to another or messages because everything is encrypted


### Installation and Dependencies
**Scapy**:<br>
* Automatically installed via [install.sh](https://github.com/fnzv/ICMPme/blob/master/install.sh)<br>
* [Official site](http://www.secdev.org/projects/scapy/doc/installation.html)<br>
* use `pip install scapy`<br>

***


**pyaes**:<br>
* Automatically installed via [install.sh](https://github.com/fnzv/ICMPme/blob/master/install.sh)<br>
* [Official site](https://github.com/ricmoo/pyaes)<br>
* use `pip install pyaes`



