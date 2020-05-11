import sys
from collections import defaultdict
from router import Router
from packet import Packet
from json import dumps, loads


class DVrouter(Router):
    """Distance vector routing protocol implementation."""

    def __init__(self, addr, heartbeatTime):
        """TODO: add your own class fields and initialization code here"""
        Router.__init__(self, addr)  # initialize superclass - don't remove
        self.heartbeatTime = heartbeatTime
        self.last_time = 0
        self.fwdtable = {} #endpoint paired with {cost:, nextHop:, port:}
        self.localcopies = {} #distance vectors of neighbours
        self.mydistancevector = {} #endpoint-cost pairs
        self.neighbours = {} #address-port pairs for linked routers


    def handlePacket(self, port, packet):

        if packet.isTraceroute():
            if packet.dstAddr in self.fwdtable: #If destination exists in table
                linkport = self.fwdtable[packet.dstAddr]["port"] #Find port to forward to
                if not linkport == None:
                	self.send(linkport, packet)

        else:
        	distancevector = loads(packet.content)
        	change = False #Variable indicates whether or not something in the distance vector has been changed

        	# if packet.srcAddr not in self.neighbours:
        	# 	self.neighbours[packet.srcAddr] = port

        	if self.localcopies.get(packet.srcAddr) == distancevector: #check cache
        		return

        	self.localcopies[packet.srcAddr] = distancevector #save local copy
        	
        	for endpoint, table in distancevector.items():
        		if endpoint == self.addr: continue

        		newCost = table["cost"] + self.mydistancevector[packet.srcAddr] #compute distance for new route
        		if endpoint in self.fwdtable:
        			if newCost < self.mydistancevector[endpoint]: #is computed distance less than existing distance
        				self.fwdtable[endpoint] = {"cost": newCost, "nextHop": packet.srcAddr, "port": self.neighbours[packet.srcAddr]} #change cost and route
        				self.mydistancevector[endpoint] = newCost
        				if endpoint in self.neighbours: self.neighbours[endpoint] = self.neighbours[packet.srcAddr]
        				change = True
        		else: #create endpoint entry in fwdtable
        			self.fwdtable[endpoint] = {"cost": newCost, "nextHop": packet.srcAddr, "port": self.neighbours[packet.srcAddr]}
        			self.mydistancevector[endpoint] = newCost
        			if endpoint in self.neighbours: self.neighbours[endpoint] = self.neighbours[packet.srcAddr]
        			change = True

        	if change == True: #Distance vector changed. Broadcast forwarding table to neighbours.
        		for neighbour, neighbourport in self.neighbours.items():
        			if not neighbourport == None:
        				dvpacket = Packet(Packet.ROUTING, self.addr, neighbour, dumps(self.fwdtable))
        				self.send(neighbourport, dvpacket)

    def handleNewLink(self, port, endpoint, cost):
        # print("added", endpoint)

        if endpoint not in self.mydistancevector or self.mydistancevector[endpoint] > cost: #Add only if it doesnt exist or new cost is less than old cost
        	self.fwdtable[endpoint] = {"cost": cost, "nextHop": endpoint, "port": port}
        	self.localcopies[endpoint] = None
        	self.mydistancevector[endpoint] = cost
        	self.neighbours[endpoint] = port

        for neighbour, neighbourport in self.neighbours.items(): #Broadcast changed forwading table
        	if not neighbourport == None:
        		dvpacket = Packet(Packet.ROUTING, self.addr, neighbour, dumps(self.fwdtable))
        		self.send(neighbourport, dvpacket)

    def handleRemoveLink(self, port):
        # print("remove link")
        X = None
        for endpoint, structure in self.fwdtable.items(): #find endpoint with port value
            if structure["port"] == port:
                # print("removed", endpoint)
                self.mydistancevector[endpoint] = 16 #set to infinity
                self.localcopies[endpoint] = None
                self.fwdtable[endpoint] = {"cost": 16, "nextHop": None, "port": None} #set to infinity. No route.
                # if endpoint in self.neighbours: self.neighbours[endpoint] = None #Remove port from neighbours dictionary

        for endpoint, structure in self.fwdtable.items(): #recalculate routes and costs
            if endpoint in self.neighbours and self.fwdtable[endpoint]["nextHop"] == endpoint: continue
            for router, vector in self.localcopies.items():
                if not vector == None and endpoint in vector:
                    newCost = vector[endpoint]["cost"] + self.mydistancevector[router]
                    if newCost < self.mydistancevector[endpoint]:
                        # print("changing cost of", endpoint, "from", self.mydistancevector[endpoint], "to", newCost)
                        self.fwdtable[endpoint] = {"cost": newCost, "nextHop": router, "port": self.neighbours[router]}
                        self.mydistancevector[endpoint] = newCost
                        if endpoint in self.neighbours: self.neighbours[endpoint] = self.neighbours[router]

        for neighbour, neighbourport in self.neighbours.items(): #Broadcast
        	if not neighbourport == None:
        		dvpacket = Packet(Packet.ROUTING, self.addr, neighbour, dumps(self.fwdtable))
        		self.send(neighbourport, dvpacket)

    def handleTime(self, timeMillisecs):

        if timeMillisecs - self.last_time >= self.heartbeatTime: #Trigger broadcast

            for neighbour, neighbourport in self.neighbours.items():
            	if not neighbourport == None:
            		dvpacket = Packet(Packet.ROUTING, self.addr, neighbour, dumps(self.fwdtable))
            		self.send(neighbourport, dvpacket)

        self.last_time = timeMillisecs

    def debugString(self):
        """TODO: generate a string for debugging in network visualizer"""
        return "debug me daddy"
