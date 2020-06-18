import scapy.all as scapy
import optparse

def get_arguments():
	parser = optparse.OptionParser()
	parser.add_option("-t", "--target", dest="target", help="Target IP / IP Range")
	(options, arguments) = parser.parse_args()  
	return options

def scan(ip):
	arp_request = scapy.ARP(pdst=ip)    #creating object
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast/arp_request  #combine both ip and mac
	answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False ) [0]	
#to hidden some info
	print("IP\t\t\tMac Address\n---------------------------------------")
	for element in answered_list:
		print(element[1].psrc + "\t\t" + element[1].hwsrc)      
		
options = get_arguments()
scan_result = scan(options.target)
