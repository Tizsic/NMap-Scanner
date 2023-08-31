import nmap

scanner = nmap.PortScanner()

print("Welcome, this is a simple nmap automation tool")
print("<-------------------------------------------------->")

# Get user input for IP address to scan
ip_addr = input("Please enter the IP address you want to scan: ")
print("The IP you entered is: ", ip_addr)
type(ip_addr)

# user response for type of scan

response = input("""\nPlease enter the type of scan you want to run
                 1) SYN ACK Scan
                 2)UPD Scan
                 3)Comprehensive Scan\n""")

#Syn ACK Scan (Syncronized Acknowledgement)
#A SYN/ACK Scan is used to determine which ports on a host are listening, open or closed.
#It can also be used to determine the OS of the host.
#it can be performed quickly, scanning thousands of ports per second on a fast network not hampered by restrictive firewalls.
#It is also relatively unobtrusive and stealthy since it never completes TCP connections. 
# SYN scan works against any compliant TCP stack rather than depending on idiosyncrasies of specific platforms as Nmap's FIN/NULL/Xmas, Maimon and idle scans do. 
# It also allows clear, reliable differentiation between the open, closed, and filtered states.

#UDP Scan
#A UDP scan is used to determine which UDP (User Datagram Protocol) ports are listening.
#UDP scans are significantly slower than TCP scans, because UDP is a connectionless protocol and more probes are required to determine whether a port is open or closed.
#UDP scans are also more prone to showing false positives, since UDP scanning does not involve a three-way handshake.
#UDP scans show open UDP ports, as well as closed ports that respond with an ICMP port unreachable message, and open|filtered ports that do not respond at all.

#Comprehensive Scan
#A comprehensive scan is a combination of SYN and UDP scans, along with a version detection scan.
#This scan is slower than the other scans, but is the most comprehensive.
#It is also the default scan type if none is selected.
#This scan is useful for determining the version of the services running on the target host, as well as the operating system.
#It is also useful for determining which ports are open on a firewall.
#This scan is also the most likely to be detected by intrusion detection systems.

print("You have selected option: ", response)

if response == '1':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS')

    #-v =   verbose mode
    #-sS =  SYN Scan
    #verbose mode will print out the details of the scan.

    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state()) #prints the state of the IP address
    print("Protocols: ", scanner[ip_addr].all_protocols()) #prints the protocols that are running on the IP address
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys()) #prints the open ports on the IP address

elif response == '2':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sU')

    #-v =   verbose mode
    #-sU =  UDP Scan
    #verbose mode will print out the details of the scan.

    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state()) #prints the state of the IP address
    print("Protocols: ", scanner[ip_addr].all_protocols()) #prints the protocols that are running on the IP address
    print("Open Ports: ", scanner[ip_addr]['udp'].keys()) #prints the open ports on the IP address

elif response == '3':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')

    #-v =   verbose mode
    #sV =   Version Detection
    #sC =   Script Scan using the default set of scripts
    #A =    Aggressive Scan
    #O =    OS Detection
    #verbose mode will print out the details of the scan.

    print(scanner.scaninfo())
    print("IP Status: ", scanner[ip_addr].state()) #prints the state of the IP address
    print("Protocols: ", scanner[ip_addr].all_protocols()) #prints the protocols that are running on the IP address
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys()) #prints the open ports on the IP address

elif response >= '4':
    print("Please enter a valid option")