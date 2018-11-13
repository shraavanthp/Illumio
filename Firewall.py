import csv

class Firewall:    

    def __init__(self, path):
        self.index={}

        def fillIplist(start, end):
            ip_list=[]
            start = list(map(int, start))
            end = list(map(int, end))            
            while start < end:                
                for i in range(len(start)-1,-1,-1):
                    if start[i]<255:
                        start[i]+=1
                        break
                    else:
                        start[i]=0
                ip_list.append('.'.join(map(str,start)))
                
            return ip_list

        with open(path, 'r') as f:
            reader = csv.reader(f, delimiter=',')            
            for row in reader:
                
                temp_index=self.index                
                
                port_list=[]
                if '-' not in row[2]:
                    port_list.append(row[2])
                else:
                    split = row[2].split('-')
                    for x in range(int(split[0]), int(split[1])+1):
                        port_list.append(x)

                ip_list=[]
                if '-' not in row[3]:
                    ip_list.append(row[3])
                else:
                    split = row[3].split('-')
                    ip_list=fillIplist(split[0].split('.'), split[1].split('.'))
                
                for port in port_list:
                    for ip in ip_list:
                        con_string = row[0]+row[1]+str(port)+ip
                        temp_index[con_string]=1

    
    def accept_packet(self, direction, protocol, port, ip_address):        
        con_string = direction + protocol + str(port) + ip_address
        return con_string in self.index

fw = Firewall('rules.csv')
print(fw.accept_packet("inbound","tcp",80,"192.168.1.2"))
print(fw.accept_packet("inbound","tcp",80,"192.168.2.2"))
print(fw.accept_packet("outbound","tcp",25,"192.168.1.1"))
print(fw.accept_packet("outbound", "udp", 4400, "192.168.2.5"))
print(fw.accept_packet("outbound", "tcp", 110, "192.168.10.11"))