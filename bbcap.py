import os
import re
import json
import argparse
from colorama import Fore
from datetime import datetime
from sys import platform

class PcapAnalyzer:

    def __init__(self, pcap_file):
        self.global_header_length=24
        self.packet_header_length=16
        self.pcap_file=pcap_file
        self.packet_indexes=[]
        self.file_size=os.stat(pcap_file).st_size
        self.dumped_packets={}
        self.packet_types={
            "L3":{"IPv4":[0, "0800"],"IPv6": [0, "86dd"], "ARP":[0, "0806"], 
            "RIP":[0, "unknown"], "DVMRP":[0, "unknown"], "IGMP":[0, "unknown"], "IPSEC":[0, "unknown"]}, 
            "L4":{"ICMPv4":[0, "unknown"],"ICMPv6":[0, "3a"],"TCP":[0, "06"],"UDP":[0, "11"]}}

    def ipv4_formatter(ipv4):
        return str(f"{int(ipv4[0:2],16)}.{int(ipv4[2:4],16)}.{int(ipv4[4:6],16)}.{int(ipv4[6:8],16)}")

    def mac_formatter(mac):
            return f"{mac[0:2].upper()}:{mac[2:4].upper()}:{mac[4:6].upper()}:{mac[6:8].upper()}:{mac[8:10].upper()}:{mac[10:12].upper()}"
    def ipv6_formatter(ipv6):
        pass

    def searchstring(self, string):
        
        with open(self.pcap_file, "rb") as f:
            content=f.read()
            if re.search(bytes(string, 'UTF-8'), content):

                for match in re.finditer(bytes(string, 'UTF-8'), content):
                    index=match.start()
                    value=match.group()
                    print(f"Value '{value.decode('utf-8')}' found at {index}th byte.", end= " ")

                    for enum, index in enumerate(self.packet_indexes):
                        if match.start()<index:
                            print(f"Analyze packet {enum} for details.")
                            break
            else:
                print(f"No match for value '{string}'")

    def dump_pcap(self):

        print("\nFollowing bytes are arranged regards to little endian byte order.")
        print(Fore.BLUE+"\n[Global Header - 24 Bytes]"+Fore.RESET)
        print(Fore.RED+f"Magic Number - 4 Bytes{Fore.RESET}: [", end=" ")
        with open(self.pcap_file, 'rb') as f:
            round=0
            global_header=[]
            while round < self.global_header_length:
                byte=f.read(1)
                global_header.append(byte.hex())
                print(f"{byte.hex()}", end = " ")
                if round==3:
                    print(f"]\n{Fore.RED}Major Version - 2 bytes{Fore.RESET}:  [", end=" ")
                if round==5:
                    print(f"]\n{Fore.RED}Major Version - 2 bytes{Fore.RESET}: [", end=" ")
                if round==7:
                    print(f"]\n{Fore.RED}Thiszone - 4 bytes{Fore.RESET}: [", end=" ")
                    #GMT to local correction
                if round==11:
                    print(f"]\n{Fore.RED}Sigfigs - 4 bytes{Fore.RESET}: [", end=" ")
                    #accuracy of timestamps
                if round==15:
                    print(f"]\n{Fore.RED}Snaplen - 4 bytes{Fore.RESET}: [", end=" ")
                    #max length of captured packets, in octests
                if round==19:
                    print(f"]\n{Fore.RED}Network - 4 bytes{Fore.RESET}:  [", end=" ")
                    #data link type
                    #https://www.tcpdump.org/linktypes.html
                round+=1
            print("]\n")
            print(Fore.BLUE+"[Global Header Readable Format]"+Fore.RESET)
            print("-------------------------------")
            magic_num=""
            for byte in global_header[0:4][::-1]:
                magic_num+=byte
            print(Fore.RED+f"Magic Number{Fore.RESET}: 0x{magic_num.upper()}")

            version=""
            for byte in global_header[4:8:2]:
                version+=str(int(byte))
            version=version[0]+"."+version[1]
            print(Fore.RED+f"Version{Fore.RESET}: {version}")

            thiszone=""
            for byte in global_header[8:12][::-1]:
                thiszone+=byte
            thiszone=int(thiszone, 16)
            print(Fore.RED+f"GMT to local correction{Fore.RESET}: {thiszone}")

            sigfigs=""
            for byte in global_header[12:16][::-1]:
                sigfigs+=byte
            sigfigs=int(sigfigs, 16)
            print(Fore.RED+f"Accuracy of timestamp{Fore.RESET}: {sigfigs}")

            max_len=""
            for byte in global_header[16:20][::-1]:
                max_len+=byte
            max_len=int(max_len, 16)
            print(Fore.RED+f"Max length of captured packets{Fore.RESET}: {max_len}")

            link_type=""
            for byte in global_header[20:24][::-1]:
                link_type+=byte
            link_type=int(link_type)
            print(Fore.RED+f"Data link type{Fore.RESET}: {link_type}", end="-")
            
            link_types_file=open("link_types.txt", "r")
            content=link_types_file.read()
            match=re.search(f"(.*)\n{str(link_type)}", content)
            type=match.group()
            type=type.split()[0]
            print(type)
            link_types_file.close()


    def packet_header_parser(packet_header):

        reverse=[]
        for byte in range(0, len(packet_header), 2):
            reverse.insert(0,packet_header[byte:][:2])
        reverse=reverse[::-1]
        packet_header="".join(byte for byte in reverse[::-1])

        return {"original_packet_length":int(packet_header[0:8], 16),
            "captured_packet_length":int(packet_header[8:16], 16),
            "packet_timestamp_mili_seconds":int(packet_header[16:24], 16),
            "packet_timestamp_seconds":int(packet_header[24:32], 16)}


    def find_tl_proto(sport, dport):
        with open("app_layer_protocols.txt", "r") as f:
            content=f.readlines()
            for proto in content:
                ports=proto.split(":")[1]
                if str(int(dport)) in ports:
                    if ports.split()[0] in str(int(dport)):
                        return proto.split(":")[0].upper()
                if str(int(sport)) in ports:
                    if ports.split()[0] in str(int(sport)):
                        return proto.split(":")[0].upper()

    def dump_packets(self):

        self.packet_indexes=[]
        self.dumped_packets={}
        self.packet_types={
            "L3":{"IPv4":[0, "0800"],"IPv6": [0, "86dd"], "ARP":[0, "0806"], 
            "RIP":[0, "unknown"], "DVMRP":[0, "unknown"], "IGMP":[0, "unknown"], "IPSEC":[0, "unknown"]}, 
            "L4":{"ICMPv4":[0, "unknown"],"ICMPv6":[0, "3a"],"TCP":[0, "06"],"UDP":[0, "11"]}}

        total_length=0
        with open(self.pcap_file, "rb") as f:
            f.seek(24)
            for packet in range(self.file_size):
                packet_length=""
                packet_length_temp=[]
                packet_raw=""

                for packet_header_byte in range(self.packet_header_length):
                    header_byte=f.read(1)
                    packet_raw+=header_byte.hex()
                    if header_byte==b'': 
                        self.packet_indexes.insert(0,40)
                        tcp_packets=self.packet_types["L4"]["TCP"][0]
                        udp_packets=self.packet_types["L4"]["UDP"][0]
                        # self.packet_indexes.pop() 
                        print(f"\n<{Fore.RED}{self.pcap_file}{Fore.RESET}: {Fore.BLUE}Total:{Fore.RESET}{len(self.packet_indexes)-1} " \
                        f"{Fore.BLUE}TCP:{Fore.RESET}{tcp_packets}{Fore.BLUE} UDP:{Fore.RESET}{udp_packets}{Fore.BLUE} Other:{Fore.RESET}" \
                        f"{len(self.packet_indexes)-1-(tcp_packets+udp_packets)}{Fore.RESET}>")
                        return
                    if 7<packet_header_byte<12:
                        packet_length+=header_byte.hex()
                for index in range(0, len(packet_length), 2):
                    packet_length_temp.append(packet_length[index:index+2])
                packet_length=""
                packet_length_temp=packet_length_temp[::-1]
                packet_length=int("".join(hexbyte for hexbyte in packet_length_temp), 16)
                total_length+=packet_length
                packet_raw+=f.read(packet_length).hex()
                self.dumped_packets[packet+1]={"Header":"","L2":{},"L3":{},"L4":{}}

                self.dumped_packets[packet+1]["Header"]=packet_raw[:32]

                layer2_data=packet_raw[32:][:28]
                self.dumped_packets[packet+1]["L2"]=Layer2.EthernetFrame(layer2_data,self.packet_types)
                layer3_protocol=layer2_data[-4:]

                if layer3_protocol==tuple(self.packet_types["L3"].values())[0][1]: #IPv4
                    layer3_data=packet_raw[60:][:40]
                    self.dumped_packets[packet+1]["L3"]=Layer3.IPv4(layer3_data, self.packet_types)

                    self.packet_types["L3"]["IPv4"][0]+=1
                    layer4_protocol=layer3_data[18:][:2]
                    ipv4_packet=self.dumped_packets[packet+1]["L3"]
                    from_addr=ipv4_packet["Source Address"]
                    to_addr=ipv4_packet["Destination Address"]

                    if layer4_protocol==self.packet_types["L4"]["TCP"][1] or layer4_protocol==self.packet_types["L4"]["UDP"][1]:
                        if layer4_protocol==self.packet_types["L4"]["TCP"][1]:
                            self.packet_types["L4"]["TCP"][0]+=1
                            layer4_tcp_data=Layer4.TCP(packet_raw[100:][:40])
                            self.dumped_packets[packet+1]["L4"]=layer4_tcp_data
                            from_port=layer4_tcp_data["Source Port"]
                            to_port=layer4_tcp_data["Destination Port"]
                            tcp_payload=packet_raw[32+len(layer2_data)+len(layer3_data)+len(packet_raw[100:][:40]):]
                            self.dumped_packets[packet+1]["L4"]["Raw Data"]=tcp_payload
                            # self.dumped_packets[packet+1]["L4"]["PROTO"]="TCP"

                            print(f"{Fore.RED}{packet+1:04d}{Fore.RESET} Ether / IP / TCP {from_addr}:{from_port} > {to_addr}:{to_port} / {packet_length} bytes.")

                        if layer4_protocol==self.packet_types["L4"]["UDP"][1]:
                            self.packet_types["L4"]["UDP"][0]+=1
                            layer4_udp_data=Layer4.UDP(packet_raw[100:][:16])
                            self.dumped_packets[packet+1]["L4"]=layer4_udp_data
                            from_port=layer4_udp_data["Source Port"]
                            to_port=layer4_udp_data["Destination Port"]
                            udp_payload=packet_raw[32+len(layer2_data)+len(layer3_data)+len(packet_raw[100:][:16]):]
                            self.dumped_packets[packet+1]["L4"]["Raw Data"]=udp_payload
                            # self.dumped_packets[packet+1]["L4"]["PROTO"]="UDP"

                            print(f"{Fore.RED}{packet+1:04d}{Fore.RESET} Ether / IP / UDP {from_addr}:{from_port} > {to_addr}:{to_port} / {packet_length} bytes.")

                    if layer4_protocol==self.packet_types["L4"]["ICMPv4"][1]:
                        self.packet_types["L4"]["ICMPv4"][0]+=1

                if layer3_protocol==tuple(self.packet_types["L3"].values())[1][1]: #IPv6
                    self.packet_types["L3"]["IPv6"][0]+=1
                    print(f"{Fore.RED}{packet+1:04d}{Fore.RESET} IPv6 Packet. Not supported yet! / {packet_length} bytes.")

                if layer3_protocol==tuple(self.packet_types["L3"].values())[2][1]: #ARP
                    self.packet_types["L3"]["ARP"][0]+=1
                    arp_packet=Layer3.ARP(packet_raw[-56:],self.packet_types)
                    self.dumped_packets[packet+1]["L3"]=arp_packet

                    arp_operation=arp_packet["Operation code"]
                    sender_addr=arp_packet["Sender IP address"]
                    target_addr=arp_packet["Target IP address"]
                    sender_mac=arp_packet["Sender MAC address"]
                    target_mac=arp_packet["Target MAC address"]

                    if arp_operation=="1 Request":
                        if target_mac=="00:00:00:00:00:00":
                            print(f"{Fore.RED}{packet+1:04d}{Fore.RESET} Ether / ARP Announcement for {sender_addr} Broadcast. At {sender_mac} / {packet_length} bytes.")
                        else:
                            print(f"{Fore.RED}{packet+1:04d}{Fore.RESET} Ether / ARP Who has {target_addr}? Tell {sender_addr} / {packet_length} bytes.")
                    if arp_operation=="2 Reply":
                        print(f"{Fore.RED}{packet+1:04d}{Fore.RESET} Ether / ARP {sender_addr} at {sender_mac} / {packet_length} bytes.")


                next_index=40+total_length+(packet*16)
                self.packet_indexes.append(next_index)
                f.seek(next_index)

    def dump_json(self):
        filename=f"bbcap-dump-{datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}-{self.pcap_file.split('.')[0]}.json"
        with open(filename, "w") as outfile:
            json.dump(self.dumped_packets, outfile, indent=4)
        print(Fore.LIGHTGREEN_EX+f"All the packet data successfully extracted to {filename}."+Fore.RESET)


    def dump_packet(self, index):

        print("")
        print(Fore.BLUE+"Packet Header"+Fore.RESET)
        packet_header=PcapAnalyzer.packet_header_parser(self.dumped_packets[index]["Header"])
        print(f"{Fore.RED}Timestamp Seconds{Fore.RESET}: {packet_header['packet_timestamp_seconds']}")
        print(f"{Fore.RED}Timestamp Miliseconds {Fore.RESET}: {packet_header['packet_timestamp_mili_seconds']}")
        print(f"{Fore.RED}Epoch Date from Timestamp{Fore.RESET}: {datetime.fromtimestamp(packet_header['packet_timestamp_seconds'])}")
        print(f"{Fore.RED}Captured Packet Length{Fore.RESET}: {packet_header['captured_packet_length']}")
        print(f"{Fore.RED}Original Packet Length{Fore.RESET}: {packet_header['original_packet_length']}")
        input(f"\n{Fore.CYAN}:: Press <ENTER> to continue reading.{Fore.RESET}")

        print(Fore.BLUE+"\nLayer 2 - Ethernet"+Fore.RESET)
        for key,value in self.dumped_packets[index]["L2"].items():
            print(f"{Fore.RED}{key}{Fore.RESET}: {value}")
        input(f"\n{Fore.CYAN}:: Press <ENTER> to continue reading.{Fore.RESET}")

        print(Fore.BLUE+f"\nLayer 3 - {self.dumped_packets[index]['L2']['Type']}"+Fore.RESET)
        for key,value in self.dumped_packets[index]["L3"].items():
            print(f"{Fore.RED}{key}{Fore.RESET}: {value}")
        input(f"\n{Fore.CYAN}:: Press <ENTER> to continue reading.{Fore.RESET}")

        if self.dumped_packets[index]["L4"]!={}:
            application_protocol=PcapAnalyzer.find_tl_proto(self.dumped_packets[index]["L4"]["Source Port"],
                                                            self.dumped_packets[index]["L4"]["Destination Port"])
            print(f"\n{Fore.BLUE}Layer 4 {self.dumped_packets[index]['L3']['Protocol']}{Fore.RESET}")
            print(f"{Fore.RED}Communication{Fore.RESET}: {application_protocol}")
            for key,value in self.dumped_packets[index]["L4"].items():
                print(f"{Fore.RED}{key}{Fore.RESET}: {value}")
            ApplicationLayer(self.dumped_packets[index]["L4"]["Raw Data"], application_protocol).format_payload()

class Layer2:

    def EthernetFrame(packet_data, packet_types):
        type=""
        for key, value in packet_types["L3"].items():
            if value[1] == packet_data[24:28]:
                type=key
        return {"Destination MAC":PcapAnalyzer.mac_formatter(packet_data[0:12]),
                "Source MAC":PcapAnalyzer.mac_formatter(packet_data[12:24]),"Type":type}

class Layer3():

    def ARP(packet_data, packet_types):
        if packet_data[4:8]==packet_types["L3"]["IPv4"][1]:
            protocol_type="IPv4"
        elif packet_data[4:8]==packet_types["L3"]["IPv6"][1]:
            protocol_type="IPv6"
        if int(packet_data[12:16], 16) == 1:
            operation="1 Request"
        elif int(packet_data[12:16], 16) == 2:
            operation="2 Reply"

        return {"Hardware type":int(packet_data[0:4], 16),
            "Protocol type":protocol_type,
            "Hardware size":int(packet_data[8:10], 16),
            "Protocol size":int(packet_data[10:12]),
            "Operation code":operation,
            "Sender MAC address":PcapAnalyzer.mac_formatter(packet_data[16:28]),
            "Sender IP address":PcapAnalyzer.ipv4_formatter(packet_data[28:36]),
            "Target MAC address":PcapAnalyzer.mac_formatter(packet_data[36:48]),
            "Target IP address":PcapAnalyzer.ipv4_formatter(packet_data[48:56])}

    def IPv4(packet_data, packet_types):

        if packet_data[18:20] == packet_types["L4"]["TCP"][1]:
            protocol="TCP"
        if packet_data[18:20] == packet_types["L4"]["UDP"][1]:
            protocol="UDP"
        return {"Version":int(packet_data[0:1], 16),
            "Header Length":int(packet_data[1:2], 16),
            "Service Type":f"0x{packet_data[2:4]}",
            #https://linuxreviews.org/Type_of_Service_(ToS)_and_DSCP_Values
            "Total Length":int(packet_data[4:8], 16),
            "Identification":int(packet_data[8:12], 16),
            "Flags":f"0x{packet_data[12:15]}",
            "Fragment Offset":int(packet_data[15:16], 16),
            "Time to Live":int(packet_data[16:18], 16),
            "Protocol":protocol,
            "Header Checksum":f"0x{packet_data[20:24].upper()}",
            "Source Address":PcapAnalyzer.ipv4_formatter(packet_data[24:32]),
            "Destination Address":PcapAnalyzer.ipv4_formatter(packet_data[32:40])}

class Layer4:

    def flags(flag):
        if flag=="002":
            return "[SYN]"
        if flag=="010":
            return "[ACK]"
        if flag=="012":
            return "[SYN, ACK]"
        if flag=="011":
            return "[FIN, ACK]"
        if flag=="014":
            return "[RST, ACK]"
        if flag=="018":
            return "[PSH, ACK]"

    def UDP(packet_data):
        return {"Source Port":int(packet_data[0:4], 16),
            "Destination Port":int(packet_data[4:8], 16),
            "Length":int(packet_data[8:12], 16),
            "Checksum":f"0x{packet_data[12:16].upper()}"}

    def TCP(packet_data):
        return {"Source Port":int(packet_data[0:4], 16),
        "Destination Port":int(packet_data[4:8], 16),
        "Sequence Number":int(packet_data[8:16], 16),
        "Acknowledgement Number":int(packet_data[16:24], 16),
        "Header Length":int(packet_data[24:25], 16),
        "Flags":Layer4.flags(packet_data[25:28]),
        "Window Size":int(packet_data[28:32],16),
        "Checksum":f"0x{packet_data[32:36].upper()}",
        "Urgent Pointer":packet_data[36:40]}

class ApplicationLayer:

    def __init__(self, data, protocol):
        self.data=data
        self.protocol=protocol

    def format_payload(self):

        def other(data):
            print(Fore.RED+f"Bytasdsaes{Fore.RESET}: {bytes.fromhex(data)}")
        def http(data):
            print(Fore.RED+f"Bytes{Fore.RESET}:")
            response=bytes.fromhex(data).split(b'\r\n')
            
            for element in response:
                print(element)
            
        def dhcp(data):

            def dhcp_options(raw_options):

                print("DHCP Options: ")
                option_base_file=open("bootp-dhcp-parameters.txt", "r")
                option_base=option_base_file.readlines()
                option_base_list=[]
                for option in option_base:
                    option_base_list.append(option.replace(" ","").split(":"))

                for key,value in raw_options.items():
                    option_code=int(raw_options.get(key)[0].get("Code: "),16)
                    option_data=raw_options.get(key)[2].get("Data: ")

                    byte_len=0
                    byte=''
                    string_data=[]
                    letters_cap="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    letters_low=letters_cap.lower()
                    symbols="!'^+%&/()=?_£#$½¾{[]}\|é,.;´><@€~"
                    numbers="0123456789"
                    charset=letters_cap+letters_low+symbols+numbers

                    for char in option_data:
                        byte+=char
                        byte_len+=1
                        if byte_len==2:
                            byte_len=0
                            try:
                                string_d=bytes.fromhex(byte).decode('utf-8')
                                if string_d in charset:
                                    string_data.append(string_d)
                            except:
                                pass
                            byte=''
                    for option in option_base_list:
                        if option[0]==str(option_code):
                            print(f"Option Code: {option_code} -> ({option[2]} {option[3].split()[0]})")
                            print(f"Hex: {option_data.upper()}, String: {''.join(letter for letter in string_data)}")
                    print("")
                option_base_file.close()

            message_type=data[0:2]
            hardware_type=data[2:4]
            hardware_address_length=data[4:6]
            hops=data[6:8]
            transaction_id=data[8:16]
            seconds_elapsed=data[16:20]
            bootp_flags=data[20:24]
            client_ip=data[24:32]
            your_client=data[32:40]
            next_server_ip_addr=data[40:48]
            relay_agent_ip_addr=data[48:56]
            client_mac_addr=data[56:68]
            client_hardware_address_padding=data[68:86]
            server_host_name=data[86:214]
            boot_file=data[214:470]
            magic_cookie="63825363"

            print(Fore.RED+"Formatted DHCP Data:"+Fore.RESET)
            print(f"Message Type: {int(message_type,16)}")
            print(f"Hardware Type: 0x{hardware_type.upper()}")
            print(f"Hardware Address Length: {int(hardware_address_length, 16)}")
            print(f"Hops: {int(hops, 16)}")
            print(f"Transaction ID: 0x{transaction_id}")
            print(f"Seconds Elapsed: 0x{(seconds_elapsed)}")
            print(f"Bootp Flags: 0x{bootp_flags}")
            print(f"Client IP: {client_ip[0:2]}.{client_ip[2:4]}.{client_ip[4:6]}.{client_ip[6:8]}")
            print(f"Your Client: {int(your_client[0:2],16)}.{int(your_client[2:4],16)}.{int(your_client[4:6],16)}.{int(your_client[6:8],16)}")
            print(f"Next Server IP Address: {int(next_server_ip_addr[0:2],16)}.{int(next_server_ip_addr[2:4],16)}.{int(next_server_ip_addr[4:6],16)}.{int(next_server_ip_addr[6:8],16)}")
            print(f"Relay Agent IP Address: {int(relay_agent_ip_addr[0:2],16)}.{int(relay_agent_ip_addr[2:4],16)}.{int(relay_agent_ip_addr[4:6],16)}.{int(relay_agent_ip_addr[6:8],16)}")
            print(f"Client MAC Address: {client_mac_addr[0:2].upper()}:{client_mac_addr[2:4].upper()}:{client_mac_addr[4:6].upper()}:{client_mac_addr[6:8].upper()}:{client_mac_addr[8:10].upper()}:{client_mac_addr[10:12].upper()}")
            print(f"Client Hardware Address Padding: {client_hardware_address_padding}")
            print(f"Server Hostname: {server_host_name}")
            print(f"Boot File: {boot_file}")
            print(f"DHCP Magic Cookie: {magic_cookie}")

            data=data[486:]

            options=[]
            
            counter=0
            while data[:2] != "ff":
                length=(int(data[2:][:2], 16)*2)
                jumps=length+2
                options.append(data[:jumps+2])
                next_data=data[jumps+2:]
                data=next_data
                counter+=1

            raw_options=dict()
            for index,option in enumerate(options):
                raw_options[f"{index}.Option"]=[{"Code: ":option[:2]},{"Length: ":option[2:4]},{"Data: ":option[4:]}]
            dhcp_options(raw_options)

        if self.protocol=="HTTPS" or self.protocol=="HTTP":
            http(self.data)
        elif self.protocol=="DHCP":
            dhcp(self.data)
        else:
            other(self.data)

if __name__=="__main__":

    print(f"")
    print(f"# ===================================================#")
    print(f"{Fore.BLUE} /$$$$$$$  /$$$$$$$   /$$$$$$   /$$$$$$  /$$$$$$$ {Fore.RESET}")
    print(f"{Fore.BLUE}| $$__  $$| $$__  $$ /$$__  $$ /$$__  $$| $$__  $${Fore.RESET}")
    print(f"{Fore.BLUE}| $$  \ $$| $$  \ $$| $$  \__/| $$  \ $$| $$  \ $${Fore.RESET}")
    print(f"{Fore.BLUE}| $$$$$$$ | $$$$$$$ | $$      | $$$$$$$$| $$$$$$$/{Fore.RESET}")
    print(f"{Fore.BLUE}| $$__  $$| $$__  $$| $$      | $$__  $$| $$____/ {Fore.RESET}")
    print(f"{Fore.BLUE}| $$  \ $$| $$  \ $$| $$    $$| $$  | $$| $$      {Fore.RESET}")
    print(f"{Fore.BLUE}| $$$$$$$/| $$$$$$$/|  $$$$$$/| $$  | $$| $$      {Fore.RESET}")
    print(f"{Fore.BLUE}|_______/ |_______/  \______/ |__/  |__/|__/      {Fore.RESET}")
    print(f"# ===================================================#")
    print(f"#|{Fore.RED}Author{Fore.RESET} > Burak Baris                               |")
    print(f"#|{Fore.RED}Website{Fore.RESET} > https://www.bbsec.net                    |")
    print(f"#|{Fore.RED}LinkedIn{Fore.RESET} > https://www.linkedin.com/in/burak-baris/|")
    print(f"#|{Fore.RED}Mail{Fore.RESET} > imbarisburak_buisiness@protonmail.com       |")
    print(f"#|{Fore.RED}Github{Fore.RESET} > https://github.com/krygeNNN               |")
    print(f"#|{Fore.RED}Instagram{Fore.RESET} > https://www.instagram.com/burak_baris_ |")
    print(f"#====================================================#")
    parser=argparse.ArgumentParser(description="PCAP Reader")
    parser.add_argument('--pcap', metavar='<pcap file name>',help="pcap file to analyze", required=True)
    args=parser.parse_args()

    if not os.path.isfile(args.pcap):
        print(f"{args.pcap} is missing in the directory.")
    if args.pcap.split('.')[1]!='pcap':
        if args.pcap.split('.')[1]=="pcapng":
            print(Fore.RED+"\nError!! pcapng file format is not supported, please convert it to pcap format.")
            os._exit(0)
        print(Fore.RED+"\nError!! Please use a pcap file.")
        os._exit(0)

    commands=["help","analyze pcap","exit", "search", "dump packets","dump packet", "summary", "clear", "dump json"]
    analyzer=PcapAnalyzer(args.pcap)
    dumped=False

    print(Fore.CYAN+"\nUse 'help' for commands."+Fore.RESET)

    while True:
        try:
            query=input("\n::"+Fore.LIGHTGREEN_EX+" BBCap "+Fore.RESET+"> ")
        except KeyboardInterrupt:
            print("Thank you for using me, bye!")
            os._exit(0)
        if query==commands[0]:
            print("")
            print("\tUse 'analyze pcap' to analyze pcap header informations.")
            print("\tUse 'dump packets' enumerate all the packets and see summary information.")
            print("\tUse 'dump packet' {packet} to get detailed analyze of a packet.")
            print("\tUse 'dump json' save json formatted details of the packets.")
            print("\tUse 'summary' to get the summary of the pcap.")
            print("\tUse 'search' to search a string.")
            print("\tUse 'clear' clear the screen.")
            print("\tUse 'exit' to end to program.")
            continue
        if query==commands[7]:
            if platform == "linux" or platform == "linux2":
                os.system("clear")
            elif platform == "darwin":
                os.system("clear")
            elif platform == "win32":
                os.system("cls")
            continue
        if query==commands[1]:
            analyzer.dump_pcap()
            continue
        if query==commands[2]:
            print("Thank you for using me, bye!")
            os._exit(0)
        if query==commands[3]:
            if dumped==False:
                print(Fore.CYAN+"Please create the packet list first to search a string in those packets."+Fore.RESET)
                print("Use 'help' for commands.")
                continue
            print("\tSearchs are case sensitive.")
            search=str(input("\t:: Input a string to search in the raw file.\n\t> "))
            analyzer.searchstring(search)
            continue
        if query==commands[4]:
            analyzer.dump_packets()
            dumped=True
            continue
        if query==commands[8]:
            if dumped==False:
                print(Fore.CYAN+"Please create the packet list first to extract them as a json file."+Fore.RESET)
                print("Use 'help' for commands.")
                continue
            analyzer.dump_json()
            continue
        if query.startswith(commands[5]):
            if dumped==False:
                print(Fore.CYAN+"Please create the packet list first to analyze a packet."+Fore.RESET)
                print("Use 'help' for commands.")
                continue
            query_index=int(query.split()[2])
            if query_index>len(analyzer.packet_indexes)-1:
                print(Fore.RED+"Please do not exceed the available range!"+Fore.RESET)
                continue
            elif query_index==0:
                print(Fore.RED+"Index starts from one rather than zero!"+Fore.RESET)
                continue
            elif query_index<0:
                print(Fore.RED+"You can not input a negative number!"+Fore.RESET)
                continue
            analyzer.dump_packet(query_index)
        if query==commands[6]:
            if dumped==False:
                print(Fore.CYAN+"Please create the packet list first to get summary of the pcap."+Fore.RESET)
                print("Use 'help' for commands.")
                continue
            tcp_packets=analyzer.packet_types["L4"]["TCP"][0]
            udp_packets=analyzer.packet_types["L4"]["UDP"][0]
            print(f"\n<{Fore.RED}{analyzer.pcap_file}{Fore.RESET}: {Fore.BLUE}Total:{Fore.RESET}{len(analyzer.packet_indexes)-1} " \
            f"{Fore.BLUE}TCP:{Fore.RESET}{tcp_packets}{Fore.BLUE} UDP:{Fore.RESET}{udp_packets}{Fore.BLUE} Other:{Fore.RESET}" \
            f"{len(analyzer.packet_indexes)-1-(tcp_packets+udp_packets)}{Fore.RESET}>")
