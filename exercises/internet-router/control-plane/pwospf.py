from select import select
from scapy.all import conf, ETH_P_ALL, MTU, plist, Packet, Ether, IP, ARP, sendp, ByteField, ShortField, IntField
from scapy.packet import Packet, bind_layers
from threading import Thread
import time

ARP_OP_REPLY = 0x0002
ARP_OP_REQ = 0x0001
ARP_TIMEOUT = 30
HELLO_TYPE = 0x01
ICMP_ECHO_REPLY_CODE = 0x00
ICMP_ECHO_REPLY_TYPE = 0x00
ICMP_HOST_UNREACHABLE_CODE = 0x01
ICMP_HOST_UNREACHABLE_TYPE = 0x03
ICMP_PROT_NUM = 0x01
LSU_TYPE = 0x04
OSPF_PROT_NUM = 0x59
PWOSPF_HELLO_DEST = '224.0.0.5'
TYPE_CPU_METADATA = 0x080a

def sniff(store=False, prn=None, lfilter=None, stop_event=None, refresh=.1, *args, **kwargs):
    s = conf.L2listen(type=ETH_P_ALL, *args, **kwargs)
    lst = []
    try:
        while True:
            if stop_event and stop_event.is_set():
                break
            sel = select([s], [], [], refresh)
            if s in sel[0]:
                p = s.recv(MTU)
                if p is None:
                    break
                if lfilter and not lfilter(p):
                    continue
                if store:
                    lst.append(p)
                if prn:
                    r = prn(p)
                    if r is not None:
                        print(r)
    except KeyboardInterrupt:
        pass
    finally:
        s.close()
    return plist.PacketList(lst, "Sniffed")

# Control plane: Interface object holds basic info and neighbor table.
class Interface():
    def __init__(self, addr, mask, helloint, port):
        # Handle neighbors: initialize an empty neighbor table.
        self.addr = addr
        self.mask = mask
        self.helloint = helloint
        self.port = port  # This should be the name of the system interface for sending/receiving.
        self.neighbors = {}  # Dictionary to store neighbor information keyed by routerID.

# ARPManager: Thread to process ARP packets.
class ARPManager(Thread):
    def __init__(self, cntrl):
        super(ARPManager, self).__init__()
        self.cntrl = cntrl

    def run(self):
        # Handle ARP packets: Listen for ARP requests and send replies.
        def arp_filter(p):
            return ARP in p
        def process_arp(p):
            arp_pkt = p[ARP]
            if arp_pkt.op == ARP_OP_REQ:
                print("Received ARP request for", arp_pkt.pdst)
                # Create a simple ARP reply using the controller's MAC.
                arp_reply = ARP(op=ARP_OP_REPLY, hwsrc=self.cntrl.MAC, psrc=arp_pkt.pdst,
                                hwdst=arp_pkt.hwsrc, pdst=arp_pkt.psrc)
                ether = Ether(dst=arp_pkt.hwsrc, src=self.cntrl.MAC, type=0x806)
                reply = ether / arp_reply
                sendp(reply, iface=self.cntrl.iface, verbose=False)
                print("Sent ARP reply for", arp_pkt.pdst)
        sniff(prn=process_arp, lfilter=arp_filter)

# HelloManager: Thread to send periodic Hello messages.
class HelloManager(Thread):
    def __init__(self, cntrl, intf):
        super(HelloManager, self).__init__()
        self.cntrl = cntrl
        self.intf = intf

    def run(self):
        # Handle Hello packets: Periodically send Hello packets out on the interface.
        while True:
            hello_pkt = (Ether(src=self.cntrl.MAC, dst="01:00:5e:00:00:05") /
                         IP(dst=PWOSPF_HELLO_DEST, proto=OSPF_PROT_NUM) /
                         PWOSPF(type=HELLO_TYPE, routerID=self.cntrl.routerID, areaID=self.cntrl.areaID) /
                         Hello(hello_interval=self.intf.helloint,
                               dead_interval=self.intf.helloint * 4,
                               router_priority=1,
                               reserved=0))
            sendp(hello_pkt, iface=self.intf.port, verbose=False)
            print("Sent Hello packet on interface", self.intf.port)
            time.sleep(self.intf.helloint)

# LSUManager: Thread to process Link State Update packets.
class LSUManager(Thread):
    def __init__(self, cntrl, lsuint):
        super(LSUManager, self).__init__()
        self.lsuint = lsuint
        self.cntrl = cntrl

    def run(self):
        # Handle LSU packets: Listen for LSU packets and process them.
        def lsu_filter(p):
            return p.haslayer(LSU)
        def process_lsu(p):
            lsu_pkt = p[LSU]
            print("Received LSU packet with sequence", lsu_pkt.sequence)
            # Here, update routing table based on LSU info (not fully implemented).
        sniff(prn=process_lsu, lfilter=lsu_filter)

# RouterController: Main control plane thread for PWOSPF.
class RouterController(Thread):
    def __init__(self, sw, routerID, MAC, areaID, intfs, lsuint=2, start_wait=0.3):
        # Create a PWOSPF Controller.
        super(RouterController, self).__init__()
        self.sw = sw
        self.routerID = routerID
        self.MAC = MAC
        self.areaID = areaID
        self.intfs = intfs  # List of Interface objects.
        self.lsuint = lsuint
        self.start_wait = start_wait
        self.routing_table = {}  # Simple routing table (for demonstration).
        # Assume a primary interface for control messages.
        self.iface = intfs[0].port

    def run(self):
        print("Starting PWOSPF Router Controller with RouterID:", self.routerID)
        # Start ARP manager.
        arp_manager = ARPManager(self)
        arp_manager.daemon = True
        arp_manager.start()
        # Start Hello managers for each interface.
        for intf in self.intfs:
            hello_manager = HelloManager(self, intf)
            hello_manager.daemon = True
            hello_manager.start()
        # Start LSU manager.
        lsu_manager = LSUManager(self, self.lsuint)
        lsu_manager.daemon = True
        lsu_manager.start()
        # Main loop: periodically print routing table.
        while True:
            print("Current routing table:", self.routing_table)
            time.sleep(10)

# Packet definitions for control plane protocols using Scapy.

class CPUMetadata(Packet):
    name = "CPUMetadata"
    fields_desc = [
        ShortField("origEtherType", 0)
    ]

class PWOSPF(Packet):
    name = "PWOSPF"
    fields_desc = [
        ByteField("type", 0),         # PWOSPF type: e.g., HELLO or LSU
        IntField("routerID", 0),       # Router identifier
        IntField("areaID", 0)          # Area identifier
    ]

class Hello(Packet):
    name = "Hello"
    fields_desc = [
        ShortField("hello_interval", 0),  # Interval in seconds between HELLO messages
        ShortField("dead_interval", 0),   # Time until neighbor declared dead
        ByteField("router_priority", 0),  # Router priority
        ByteField("reserved", 0)          # Reserved field for alignment
    ]

class LSUad(Packet):
    name = "LSUad"
    fields_desc = [
        IntField("link_id", 0),   # Identifier for the advertised link
        ShortField("cost", 0)     # Cost of the link
    ]

class LSU(Packet):
    name = "LSU"
    fields_desc = [
        IntField("sequence", 0),           # Sequence number for LSU messages
        ByteField("num_advertisements", 0),  # Number of link advertisements
        # Three reserved bytes for padding/alignment
        ByteField("reserved1", 0),
        ByteField("reserved2", 0),
        ByteField("reserved3", 0)
    ]

# Bind protocol layers for packet dissection.
bind_layers(Ether, CPUMetadata, type=TYPE_CPU_METADATA)
bind_layers(CPUMetadata, IP, origEtherType=0x0800)
bind_layers(CPUMetadata, ARP, origEtherType=0x0806)
bind_layers(IP, PWOSPF, proto=OSPF_PROT_NUM)
bind_layers(PWOSPF, Hello, type=HELLO_TYPE)
bind_layers(PWOSPF, LSU, type=LSU_TYPE)
