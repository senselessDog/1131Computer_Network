from ryu.base import app_manager
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER,CONFIG_DISPATCHER
from ryu.lib.packet import packet,ethernet
from ryu.topology import event
from ryu.topology.api import get_switch,get_link
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp   # 添加 ARP 協議的 import
import networkx as nx
 
class MyShortestForwarding(app_manager.RyuApp):
    '''
    class to achive shortest path to forward, based on minimum hop count
    '''
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
 
    def __init__(self,*args,**kwargs):
        super(MyShortestForwarding,self).__init__(*args,**kwargs)
 
        #set data structor for topo construction
        self.network = nx.DiGraph()        #store the dj graph
        self.paths = {}        #store the shortest path
        self.topology_api_app = self
        self.logger.info("控制器初始化開始...")
    
        # 清理所有數據結構
        self.clear_all_states()
        
        self.switch_mac_matches = {}  # 格式: {dpid: set(matches)}
        self.logger.info("開啟防loop模式...")

    def clear_all_states(self):
        """清理所有控制器狀態"""
        self.network.clear()
        self.paths.clear()
        self.logger.info("所有控制器狀態已清理")
 
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures,CONFIG_DISPATCHER)
    def switch_features_handler(self,ev):
        '''
        manage the initial link between switch and controller
        '''
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
 
        match = ofp_parser.OFPMatch()    #for all packet first arrive, match it successful, send it ro controller
        actions  = [ofp_parser.OFPActionOutput(
                            ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER
                            )]
 
        self.add_flow(datapath, 0, match, actions)
 
    def add_flow(self,datapath,priority,match,actions):
        '''
        fulfil the function to add flow entry to switch
        '''
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
 
        inst = [ofp_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
 
        mod = ofp_parser.OFPFlowMod(datapath=datapath,priority=priority,match=match,instructions=inst)
 
        datapath.send_msg(mod)

    def is_ipv6_multicast(self,mac):
        """檢查是否為 IPv6 多播 MAC 地址"""
        return mac.startswith('33:33')

    @set_ev_cls(ofp_event.EventOFPPacketIn,MAIN_DISPATCHER)
    def packet_in_handler(self,ev):
        '''
        manage the packet which comes from switch
        '''
        #first get event infomation
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
 
        in_port = msg.match['in_port']
        dpid = datapath.id
 
        #second get ethernet protocol message
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        # self.logger.info(f"""
        #             收到封包:
        #             源MAC: {eth_pkt.src}
        #             目的MAC: {eth_pkt.dst}
        #             類型: 0x{format(eth_pkt.ethertype, '04x')}
        #             """)
        # 忽略 LLDP 封包
        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            return
 
        
        eth_src = eth_pkt.src     #note: mac info willn`t  change in network
        eth_dst = eth_pkt.dst
        # # 忽略 IPv6 多播
        # if self.is_ipv6_multicast(eth_dst):
        #     return
        # # 只處理有效的主機MAC地址
        # if not (eth_src.startswith('00:00:00:00:00') and eth_dst.startswith('00:00:00:00:00')):
        #     self.logger.debug(f"忽略非主機MAC地址: src={eth_src}, dst={eth_dst}")
        #     return
        if (eth_dst == 'ff:ff:ff:ff:ff:ff'):
                # 解析 ARP 封包
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt:
                # 從 ARP 請求中獲取目標 IP
                target_ip = arp_pkt.dst_ip
                self.logger.info(f"[packet_in_handler] ARP Request: {eth_src} looking for IP {target_ip}")
                
                # 修改 mac_match_key 加入目標 IP
                mac_match_key = (eth_src, eth_dst, target_ip)
                
                if dpid not in self.switch_mac_matches:
                    self.switch_mac_matches[dpid] = set()
                    
                if mac_match_key in self.switch_mac_matches[dpid]:
                    self.logger.info(f"[packet_in_handler] Already receive ARP request = {mac_match_key}")
                    return
                else:
                    self.logger.info(f"[packet_in_handler] New ARP request = {mac_match_key}")
                    self.switch_mac_matches[dpid].add(mac_match_key)
        # IPV6不需要進入get_out_port，但IPV6好像不能直接取消
        if self.is_ipv6_multicast(eth_dst):
            actions = []
        else:
            out_port = self.get_out_port(datapath,eth_src,eth_dst,in_port)
            actions = [ofp_parser.OFPActionOutput(out_port)]
            
            match = ofp_parser.OFPMatch(in_port=in_port,eth_dst=eth_dst)

            if out_port != ofproto.OFPP_FLOOD:
                
                self.add_flow(datapath,1,match,actions)
 
        out = ofp_parser.OFPPacketOut(
                datapath=datapath,buffer_id=msg.buffer_id,in_port=in_port,
                actions=actions,data=msg.data
            )
 
        datapath.send_msg(out)
 
    @set_ev_cls(event.EventSwitchEnter,[CONFIG_DISPATCHER,MAIN_DISPATCHER])    #event is not from openflow protocol, is come from switchs` state changed, just like: link to controller at the first time or send packet to controller
    def get_topology(self,ev):
        # 清理現有拓撲
        self.network.clear()
        
        # 添加交換機
        switch_list = get_switch(self.topology_api_app,None)
        switches = [switch.dp.id for switch in switch_list]
        self.network.add_nodes_from(switches)
        self.logger.info("[get topology] 交換機列表: %s", switches)
        
        # 正確記錄連接信息
        link_list = get_link(self.topology_api_app,None)
        self.logger.info("[get topology] link列表: %s", link_list)
        for link in link_list:
            # 使用源端口號
            self.network.add_edge(link.src.dpid, link.dst.dpid, 
                                attr_dict={'port': link.src.port_no})
            # 使用目的端口號作為反向連接
            self.network.add_edge(link.dst.dpid, link.src.dpid, 
                                attr_dict={'port': link.dst.port_no})
            self.logger.info(f"[get topology] 添加鏈路: {link.src.dpid}->{link.dst.dpid}, "
                            f"端口: {link.src.port_no}->{link.dst.port_no}")
        self.logger.info(f"[get topology] Number of link: {len(link_list)} ")
    def is_host_mac(self, mac):
        """檢查是否為 Mininet 分配的主機 MAC 地址"""
        return mac.startswith('00:00:00:00:00')

    def get_out_port(self,datapath,src,dst,in_port):
        '''
        datapath: is current datapath info
        src,dst: both are the host info
        in_port: is current datapath in_port
        '''
        dpid = datapath.id
        self.logger.info(f"[get_out_port] 計算路徑: 從 {src} 到 {dst}, 當前交換機 {dpid}")
        #the first :Doesn`t find src host at graph
        if src not in self.network:
            self.logger.info(f"[get_out_port] 添加新主機 {src} 到拓撲")
            self.network.add_node(src)
            self.network.add_edge(dpid, src, attr_dict={'port':in_port})
            self.network.add_edge(src, dpid)
            self.paths.setdefault(src, {})
 
        #second: search the shortest path, from src to dst host
        if dst in self.network:
            self.logger.info(f"[get_out_port] 找到{dst}, 當前交換機 {dpid}")
            if dst not in self.paths[src]:    #if not cache src to dst path,then to find it
                try:
                    path = nx.shortest_path(self.network,src,dst)
                    self.logger.info(f"[get_out_port] 計算出的路徑: {path}")
                    self.paths[src][dst]=path
                except nx.NetworkXNoPath:
                    self.logger.info(f"[get_out_port] 找不到從 {src} 到 {dst} 的路徑")

            path = self.paths[src][dst]
            next_hop = path[path.index(dpid)+1]
            #print("1ooooooooooooooooooo")
            #print(self.network[dpid][next_hop])
            out_port = self.network[dpid][next_hop]['attr_dict']['port']
            #print("2ooooooooooooooooooo")
            #print(out_port)
 
            #get path info
            #print("6666666666 find dst")
            #print(path)
        else:
            self.logger.info(f"[get_out_port] Not find {dst}, implement flood")
            out_port = datapath.ofproto.OFPP_FLOOD    #By flood, to find dst, when dst get packet, dst will send a new back,the graph will record dst info
            #print("8888888888 not find dst")
        return out_port