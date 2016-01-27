#!/usr/bin/python
###  Author: Yessou Sami 
###
###  Instant Messagging via Encrypted ICMP packets(Ping) to bypass censorship(proxy,firewalls,gateways..)
###  Features: Anonimity( Message is encrypted with AES CTR)
###            Can't be Detect by firewall,proxy (Because is running on ICMP packets)
###            Connection less
###            
###  Dependencies: scapy,pyaes 
###
###  TODO: Encrypted Tunnelling of IP traffic, Proxying over ICMP, (En\De)capsulate TCP\UDP packets into ICMP
### 
###  PoC\Tutorial and wiki coming soon

from scapy.all import *
import hashlib,argparse,os
import pyaes,threading,logging
import sys,StringIO


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


parser = argparse.ArgumentParser()

parser.add_argument('-ip', action='store', default="none",
                    dest='ipdest',
                    help='Destination IP Address thats running ICMPme endpoint')



results = parser.parse_args()

ipdest=results.ipdest


# A 32 Byte key for encryption (32 Characters long)
key = "This_key_for_demo_purposes_only!"


iv =os.urandom(32) #generate random 256 IV



#Secret for authentication

private_auth_code=hashlib.sha224("Secret").hexdigest()

def ICMPre(pkt):
        #print "Received ICMP packet checking if ICMPme format"
        try:
                if private_auth_code in pkt[Raw].load:  #parse msg
                        msg=pkt[Raw].load
                        msg=msg.replace(private_auth_code,"")
                        msg=decrypt_icmp(msg)
                        print pkt[IP].src+"  : "+msg
        except:
                print "ICMPme auth_code wrong"

def encrypt_icmp(plaintext):
        aes = pyaes.AESModeOfOperationCTR(key)
        ciphertext = aes.encrypt(plaintext)
        return ciphertext


def decrypt_icmp(crypted_text):
        aes = pyaes.AESModeOfOperationCTR(key)
        decrypted = aes.decrypt(crypted_text)
        return decrypted


def Receive_pkts():

        sniff(count=100,prn=ICMPre,filter="icmp")


sniff_thread=threading.Thread(target=Receive_pkts)
sniff_thread.start()

msg=""
while msg!="quit":
        msg=raw_input("You : ")
        # send message to other host FORMAT private_auth_code and msg encrypted AES CTR
        msg_enc=encrypt_icmp(msg)
        msg_out=private_auth_code+msg_enc
        ###### Capturing stdout
        stdout = sys.stdout
        capturer = StringIO.StringIO()
        sys.stdout=capturer
        send(IP(dst=ipdest, ttl=128)/ICMP(id=1,seq=56,type=8)/msg_out)
        sys.stdout = stdout
        ###### Finished capturing stdout
