import argparse
import scapy.all as scapy


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='Target IP / IP range.')
    option = parser.parse_args()
    if not option.target:
        parser.error('[-] Adj meg egy IP címet. Használd a --help parancsot több infóért.')
    return option


def scan(ip):
    # készít egy packetet a Broadcast MAC address felé, amit az adott networkon lévő összes gép megkap és IP-t kér.
    arp_request = scapy.ARP(pdst=ip)                                                                                    # kiküld a cél-hálózatnak egy jelet, ami az IP címet tartalmazza
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")                                                                    # itt állítjuk be a broadcast MAC addresst /scapy.ls(scapy.Ether())
    arp_request_broadcast = broadcast/arp_request                                                                       # ezzel állítjuk a cél MAC addresst a broadcast MAC addressre
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]                                       # ezzel a paranccsal küldjük el a packetet, és ez kapja meg a választ /timeout=>1secet vár a válaszra
    clients_list = list()

    for i in answered_list:
        # print(i[1].show())                                                                                            # packet objektumnál .show() metódussal tudjuk a csomag mezőit megnézni
        client_dict = {'ip': i[1].psrc, 'mac': i[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


def print_result(results_list):
    print('IP\t\t\tMAC Address\n------------------------------------------')
    for client in results_list:
        print(client['ip'] + '\t\t' + client['mac'])


argument = get_arguments()
scan_result = scan(argument.target)  # 192.168.181.1/24
print_result(scan_result)