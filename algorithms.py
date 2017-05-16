from collections import defaultdict



def get_detail_path(src,dst,all_path,topo):
    detail_path = {}
    print("start to route! from: ",src," to: ",dst)
    full_path = all_path[src][dst]

    print("raw path is ",full_path)

    if full_path is None:
        return detail_path
    
    if len(full_path) < 3:
        return detail_path
    

    # detail_path[full_path[1]] = []

    for i in range(1,len(full_path)-1):
        left = full_path[i-1]
        node = full_path[i]
        right = full_path[i+1]

        link_left= topo[left][node]
        in_port = int(link_left['dst']['port_no'])

        link_right = topo[node][right]
        out_port = int(link_right['src']['port_no'])
        detail_path[node] = [in_port,out_port]

    
    print(detail_path)

    return detail_path



def get_path(src,nodes,path):

    all_path = {}


    for node in nodes:
        if node == src:
            continue
        
        pre = path[node]

        all_path[node] = [node]
        # print("path ",node," is: ",)

        while pre != src:
            all_path[node].insert(0,pre)
            
            pre = path[pre]
        # print(src," ")

        all_path[node].insert(0,src)
    return all_path



def dijkstra(src,topo):
    '''
    topo is in Adjacency list format
    topo[src][dst] = msg

    msg is in format like below:
    {
    'dst': {'port_no': '00000001', 
            'name': 's2-eth1', 
            'hw_addr': '52:9c:f6:6d:d3:5f', 
            'dpid': '0000000000000002'}, 
    'src': {'port_no': '00000001', 
            'name': 's1-eth1', 
            'hw_addr': '22:33:5a:65:de:62', 
            'dpid': '0000000000000001'}
    }
    '''

    MAXINT = 300

    nodes = list(topo.keys())

    num = len(nodes)

    # print("nodes: ",nodes)

    final = [ 0 for i in range(num)]

    Distance = [MAXINT for i in range(num)]

    path = {}

    for node in nodes:
        path[node] = src

    pos_src = 0

    for i,node in enumerate(nodes):
        if node == src:
            pos_src = i
        if topo[src][node] is not None:
            Distance[i] = 1

    Distance[pos_src] = 0
    final[pos_src] = 1


    # print("pre dis: ",Distance)

    for i in range(num-1):
        mins = MAXINT
        v = 0
        
        for j in range(num):
            if final[j] == 0 and Distance[j] < mins:
                v = j
                mins = Distance[j]

        final[v] = 1

        # print("update j: ",nodes[v])
        # print("new final: ",final)

        for j in range(num):
            if final[j] == 1 or topo[nodes[v]][nodes[j]] is None:
                continue
            if mins + 1 < Distance[j]:
                Distance[j] = mins + 1
                path[nodes[j]] = nodes[v]

            # print("     ups: ",nodes[j])



    # print("final dis:",Distance)
    # print("paths    :",path)

    all_path = get_path(src,nodes,path)

    return all_path
        

def get_all_path(hosts,topo):
    nodes = list(hosts.keys())

    all_path = defaultdict(lambda: defaultdict(lambda: None))

    for src in nodes:
        
        path = dijkstra(src,topo)
        for dst in path.keys():
            all_path[src][dst] = path[dst]
        # print("start: ",src)
        # print(path)
    return all_path
    # return all_path


if __name__ == "__main__":
    topo = defaultdict(lambda: defaultdict(lambda: None))
    topo['a']['f'] = 1
    topo['a']['e'] = 1
    topo['a']['c'] = 1
    topo['b']['c'] = 1
    topo['c']['b'] = 1
    topo['c']['a'] = 1
    topo['c']['d'] = 1
    topo['d']['c'] = 1
    topo['d']['f'] = 1
    topo['d']['e'] = 1
    topo['e']['d'] = 1
    topo['e']['a'] = 1
    topo['e']['f'] = 1
    topo['f']['a'] = 1
    topo['f']['e'] = 1
    topo['f']['d'] = 1

    # path = dijkstra('b',topo)
    # print(path)
    paths = get_all_path(topo)

    print(paths)


        