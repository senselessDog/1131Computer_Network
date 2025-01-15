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
    class to achieve shortest path forwarding with dual paths support
    '''
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
 
    def __init__(self,*args,**kwargs):
        super(MyShortestForwarding,self).__init__(*args,**kwargs)
        self.network = nx.DiGraph()
        self.paths = {}
        self.topology_api_app = self
        self.logger.info("控制器初始化開始...")
        self.clear_all_states()
        self.switch_mac_matches = {}
        self.group_ids = {}  # 用於追踪 group entries
        self.logger.info("開啟雙路徑和防loop模式...")

    def clear_all_states(self):
        """清理所有控制器狀態"""
        self.network.clear()
        self.paths.clear()
        self.logger.info("所有控制器狀態已清理")

    def add_flow(self,datapath,priority,match,actions):
        '''添加流表項'''
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        inst = [ofp_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        mod = ofp_parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

    def add_dual_path_group(self, datapath, out_ports):
        '''添加群組表項支持雙路徑'''
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        
        # 為每個輸出端口創建一個 bucket
        buckets = []
        for port in out_ports:
            actions = [ofp_parser.OFPActionOutput(port)]
            bucket = ofp_parser.OFPBucket(
                weight=50,
                watch_port=port,
                watch_group=ofproto.OFPG_ANY,
                actions=actions
            )
            buckets.append(bucket)
        
        # 生成唯一的 group_id
        dpid = datapath.id
        if dpid not in self.group_ids:
            self.group_ids[dpid] = 0
        group_id = self.group_ids[dpid]
        self.group_ids[dpid] += 1

        # 創建 group mod 消息
        req = ofp_parser.OFPGroupMod(
            datapath=datapath,
            command=ofproto.OFPGC_ADD,
            type_=ofproto.OFPGT_SELECT,
            group_id=group_id,
            buckets=buckets
        )
        datapath.send_msg(req)
        return group_id

    def is_ipv6_multicast(self,mac):
        """檢查是否為 IPv6 多播 MAC 地址"""
        return mac.startswith('33:33')

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures,CONFIG_DISPATCHER)
    def switch_features_handler(self,ev):
        '''處理交換機特性'''
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        
        match = ofp_parser.OFPMatch()
        actions = [ofp_parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER,
            ofproto.OFPCML_NO_BUFFER
        )]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn,MAIN_DISPATCHER)
    def packet_in_handler(self,ev):
        '''處理封包進入事件'''
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        eth_src = eth_pkt.src
        eth_dst = eth_pkt.dst

        # 處理廣播封包
        if (eth_dst == 'ff:ff:ff:ff:ff:ff'):
        # 解析 ARP 封包以記錄目標 IP
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt:
                target_ip = arp_pkt.dst_ip
                # 確保該交換機有自己的 match 集合
                if dpid not in self.switch_mac_matches:
                    self.switch_mac_matches[dpid] = set()
                
                # 將 match 轉換為可雜湊的形式，包含目標 IP
                mac_match_key = (eth_src, eth_dst, target_ip)
                
                # 如果是重複的 match 且是 flood，就忽略
                if mac_match_key in self.switch_mac_matches[dpid]:
                    self.logger.info(f"[packet_in_handler] Already receive ARP request = {mac_match_key}, 當前交換機 {dpid}")
                    return
                else:
                    self.logger.info(f"[packet_in_handler] New ARP request = {mac_match_key}, 目標 IP {target_ip}, 當前交換機 {dpid}")
                    self.switch_mac_matches[dpid].add(mac_match_key)

        # IPV6不需要進入get_out_port，但IPV6好像不能直接取消
        if self.is_ipv6_multicast(eth_dst):
            actions = []
        else:
            out_ports = self.get_out_ports(datapath,eth_src,eth_dst,in_port)
            actions = [ofp_parser.OFPActionOutput(out_ports)]
            
            match = ofp_parser.OFPMatch(in_port=in_port,eth_dst=eth_dst)

            if out_ports != ofproto.OFPP_FLOOD:
                if len(out_ports) == 1:  # 單一路徑或 FLOOD
                    actions = [ofp_parser.OFPActionOutput(out_ports[0])]
                    
                    if out_ports[0] != ofproto.OFPP_FLOOD:
                        match = ofp_parser.OFPMatch(in_port=in_port,eth_dst=eth_dst)
                        self.add_flow(datapath,1,match,actions)
                else:  # 多路徑情況
                    # 創建 group table
                    group_id = self.add_dual_path_group(datapath, out_ports)
                    
                    # 添加指向 group 的流表項
                    actions = [ofp_parser.OFPActionGroup(group_id)]
                    match = ofp_parser.OFPMatch(in_port=in_port,eth_dst=eth_dst)
                    self.add_flow(datapath,1,match,actions)

        out = ofp_parser.OFPPacketOut(
                datapath=datapath,buffer_id=msg.buffer_id,in_port=in_port,
                actions=actions,data=msg.data
            )

        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter,[CONFIG_DISPATCHER,MAIN_DISPATCHER])
    def get_topology(self,ev):
        '''獲取網路拓撲'''
        self.network.clear()
        
        switch_list = get_switch(self.topology_api_app,None)
        switches = [switch.dp.id for switch in switch_list]
        self.network.add_nodes_from(switches)
        self.logger.info("[get topology] 交換機列表: %s", switches)
        
        link_list = get_link(self.topology_api_app,None)
        self.logger.info("[get topology] link列表: %s", link_list)
        for link in link_list:
            self.network.add_edge(
                link.src.dpid,
                link.dst.dpid,
                attr_dict={'port': link.src.port_no}
            )
            self.network.add_edge(
                link.dst.dpid,
                link.src.dpid,
                attr_dict={'port': link.dst.port_no}
            )
            self.logger.info(f"[get topology] 添加鏈路: {link.src.dpid}->{link.dst.dpid}, "
                           f"端口: {link.src.port_no}->{link.dst.port_no}")
        self.logger.info(f"[get topology] Number of links: {len(link_list)}")

    def find_disjoint_paths_from_shortest(self, all_paths, k=2):
        """
        從所有最短路徑中找出最不相交的k條路徑
        
        Parameters:
        all_paths (list): 所有最短路徑的列表
        k (int): 要找出的路徑數量，預設為2
        
        Returns:
        list: 包含k條最不相交路徑的列表
        """
        if len(all_paths) <= k:
            return all_paths
            
        # 計算所有路徑組合的重疊程度
        min_overlap = float('inf')
        best_path_pair = None
        
        for i in range(len(all_paths)):
            for j in range(i + 1, len(all_paths)):
                path1 = set(all_paths[i])
                path2 = set(all_paths[j])
                
                # 計算重疊的節點數量
                overlap = len(path1.intersection(path2))
                
                # 如果找到重疊更少的路徑組合，就更新
                if overlap < min_overlap:
                    min_overlap = overlap
                    best_path_pair = [all_paths[i], all_paths[j]]
                # 如果重疊程度相同，選擇總長度較短的路徑組合
                elif overlap == min_overlap and best_path_pair:
                    current_total_length = len(all_paths[i]) + len(all_paths[j])
                    best_total_length = len(best_path_pair[0]) + len(best_path_pair[1])
                    if current_total_length < best_total_length:
                        best_path_pair = [all_paths[i], all_paths[j]]
        
        return best_path_pair if best_path_pair else [all_paths[0]]
    
    def get_out_ports(self,datapath,src,dst,in_port):
        '''計算輸出端口（支持雙路徑）'''
        dpid = datapath.id
        self.logger.info(f"[get_out_ports] 計算路徑: 從 {src} 到 {dst}, 當前交換機 {dpid}")
        
        if src not in self.network:
            self.logger.info(f"[get_out_ports] 添加新主機 {src} 到拓撲")
            self.network.add_node(src)
            self.network.add_edge(dpid, src, attr_dict={'port':in_port})
            self.network.add_edge(src, dpid)
            self.paths.setdefault(src, {})

        if dst in self.network:
            self.logger.info(f"[get_out_ports] dst 找到{dst}, 當前交換機 {dpid}")
            if dst not in self.paths[src]:
                try:
                    # 找出所有最短路徑
                    all_paths = list(nx.all_shortest_paths(self.network,src,dst))
                    # 選擇前兩條路徑
                    paths = self.find_disjoint_paths_from_shortest(all_paths)
                    self.logger.info(f"[get_out_ports] 計算出的最不相交路徑: {paths}")
                    self.paths[src][dst] = paths
                except nx.NetworkXNoPath:
                    self.logger.info(f"[get_out_ports] 找不到從 {src} 到 {dst} 的路徑")
                    return [datapath.ofproto.OFPP_FLOOD]

            out_ports = []
            for path in self.paths[src][dst]:
                if dpid in path:
                    next_hop = path[path.index(dpid)+1]
                    out_ports.append(self.network[dpid][next_hop]['attr_dict']['port'])
            return out_ports
        else:
            self.logger.info(f"[get_out_ports] Not find {dst}, implement flood")
            return [datapath.ofproto.OFPP_FLOOD]