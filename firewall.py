import csv

class FireWall:
    def __init__(self,filePath):
        with open(filePath) as csvFile:
            #form a rule map
            self.inTcp = {"port":[], "ip_address":{}}
            self.inUdp = {"port":[], "ip_address":{}}
            self.outTcp = {"port":[], "ip_address":{}}
            self.outUdp = {"port":[], "ip_address":{}}
            self.ruleMap = {"inbound": {"tcp": self.inTcp, "udp": self.inUdp},"outbound": {"tcp": self.outTcp, "udp": self.outUdp}}

            readCSV = csv.reader(csvFile)
            for index, line in enumerate(readCSV):
                direction = line[0]
                protocol = line[1]
                port = line[2]
                ip_address = line[3]
                self.add_entry(direction, protocol, port, ip_address, index)
        sorted(self.inTcp["port"], key = lambda k:k[0][1])
        sorted(self.inUdp["port"], key = lambda k:k[0][1])
        sorted(self.outTcp["port"], key = lambda k:k[0][1])
        sorted(self.outUdp["port"], key = lambda k:k[0][1])
        return
        
    def add_entry(self, direction, protocol, port, ip_address, index):
        portRange = port.split("-")
        if len(portRange) == 1:
            portRange = portRange*2
        #change list item type from string into integer
        portRange = [int(item) for item in portRange]
        self.ruleMap[direction][protocol]["port"].append((portRange, index))

        ipRange = ip_address.split("-")
        if len(ipRange) == 1:
            ipRange = ipRange*2
        ipRange = [tuple(int(n) for n in ipRange[0].split('.')), tuple(int(n) for n in ipRange[1].split('.'))]
        self.ruleMap[direction][protocol]["ip_address"][index] = ipRange
        return
        

    def accept_packet(self, direction, protocol, port, ip_address):
        #search all ports that includes port passed in
        keys = self.search(direction, protocol, port)
        ipAddresses = [self.ruleMap[direction][protocol]["ip_address"][key] for key in keys]
        ip_address = tuple(int(n) for n in ip_address.split('.'))
        #data structure for ipAddresses is [[(0,0,0,0),(0,0,0,0)],[(194,0,0,5),(194,0,1,6)]]
        for addresses in ipAddresses:
            if addresses[0] <= ip_address and ip_address <= addresses[1]:
                return True
        return False

    def search(self, direction, protocol, port):
        #brought some idea from exponential search
        #data form of port is [([5,8],1), ([10,10],0)]
        portsPool = self.ruleMap[direction][protocol]["port"]
        keyOfPorts = []
        index = 1
        while index < len(portsPool)+1:
            item = portsPool[index-1] # data structure for item is([5,8], 1) represent the port range 5-8 key is 1
            if port > item[0][1]:
                if index*2 < len(portsPool)+1:
                    index *= 2
                else:
                    index +=1
            else:
                if port in range(item[0][0], item[0][1]+1):
                    keyOfPorts.append(item[1])
                index +=1
        return keyOfPorts

    
fw = FireWall("fw.csv")
print(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2")) # True
print(fw.accept_packet("inbound", "udp", 53, "192.168.2.1")) # True
print(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11")) # True
print(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2")) # False
print(fw.accept_packet("inbound", "udp", 24, "52.12.48.92")) # False

