#import numpy as np

def dijkstra(router_list, current_router):
	N = len(router_list)
	node = list(router_list.keys())
	links = [[0] * N for i in range(N)]
	port = [[0] * N for i in range(N)]
	oldPort = [[0] * N for i in range(N)]
	for i in range(N):
		count = 1 
		for j in range(N):
			if node[j] in router_list[node[i]]:		
				links[i][j]=1
				port[i][j]=count
				oldPort[i][j]=count
				count = count+1	
	
	latency = links

	nextHop = {}
	#based on nodes, link info (is it a neighbor), latancy to neigbor and output port, the optimal output port from each node to it's neighbor is calculated. 
	for i in range(N):
		D=[0] * N
		w=[0] * N
		w[i]=1
		
		for j in range(N):
			if links[i][j]==1 or j==i:
		    		D[j]=links[i][j]
			else:
		    		D[j]=100000    #practically infinite

	    	count=1
	    	while (count<=(N-1)):
			mini=100000     #practically infinite
			minlo=i
			for k in range(N):
		    		if latency[i][k]<mini and w[k]!=1 and links[i][k]==1:
					mini=latency[i][k]
					minlo=k
			w[minlo]=1
			for k in range(N):
		    		if w[k]!=1 and links[minlo][k]==1:
					if D[k]>(D[minlo]+latency[minlo][k]):
			    			port[i][k]=port[i][minlo]
					D[k]=min(D[k],D[minlo]+latency[minlo][k])
			count=count+1
		if i == current_router :
			for j in range(N):
				if i != j:
					sudoPort = port[i][j]
					for k in range(N):
						if oldPort[i][k]==sudoPort:
							nextPort = k
					nextHop[node[j]] = node[nextPort]

	return(nextHop)  #return the updated information on which packet should take which port
