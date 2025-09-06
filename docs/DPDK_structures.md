+-------------------------+
| rte_mbuf (mbuf)         |
|-------------------------|
| buf_addr --------------+----+
| data_off --------------+----+--> Actual packet data starts here
| pkt_len                 |
| data_len                |
| ...other metadata...     |
+-------------------------+

Memory Layout:

[ buf_addr ]  
  |----------------------------- Total buffer memory
  |                             <-- mbuf->buf_addr
  |    [unused or headroom]    
  |    <-- mbuf->data_off  
  |----------------------------- Packet starts here (pointer returned by rte_pktmbuf_mtod)
  |    [Ethernet header]        <-- (struct ether_hdr *)
  |    [IP header]              <-- (struct ipv4_hdr *)
  |    [UDP/TCP payload]        <-- (void *)

[mbuf->buf_addr] ---> [Headroom | Ethernet header | IP header | Payload | Tailroom]
                       ^
                       |
       rte_pktmbuf_mtod(mbuf, struct ether_hdr *) points here
