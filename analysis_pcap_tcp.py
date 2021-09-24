import dpkt


class PcapParser:
    def __init__(self, pcapFile):
        self.pcapFile = pcapFile

    def readFile(self):
        numFlows = 0
        ports = []

        with open(self.pcapFile, 'rb') as file:
            pcap = dpkt.pcap.Reader(file)  # coverts PCAP packet from binary to byte format
            for epochTime, buffer in pcap:
                byteSource = buffer[34:36]
                byteDestination = buffer[36:38]
                byteSequence = buffer[38:42]
                byteAcknowledge = buffer[42:46]
                byteWindow = buffer[48:50]
                flag = buffer[47]
                source = int.from_bytes(byteSource, byteorder='big')
                destination = int.from_bytes(byteDestination, byteorder='big')
                sequenceNum = int.from_bytes(byteSequence, byteorder='big')
                acknowledgeNum = int.from_bytes(byteAcknowledge, byteorder='big')
                scalingFactor = int.from_bytes(byteWindow, byteorder='big')

                if flag == 2:  # new flow started
                    self.addFlow(source, destination, buffer[73], ports)  # add flow to port list

                for flow in ports:  # find corresponding flow
                    if (flow[0] == source and flow[1] == destination) \
                            or (flow[1] == source and flow[0] == destination):  # we found the flow of current buffer

                        if flow[3] == 0:
                            flow[3] = epochTime  # start time of flow
                        else:
                            flow[4] = epochTime  # end time for flow

                        flow[5] += 1  # increment number of packets

                        if flag == 16:  # counts retransmissions
                            retransmissions = flow[8]
                            if acknowledgeNum in retransmissions:
                                retransmissions[acknowledgeNum] += 1
                            else:
                                retransmissions[acknowledgeNum] = 1
                            if retransmissions[acknowledgeNum] == 3:
                                flow[7] += 1

                        if flow[6] < 2 and flag == 16:  # print first 2 transactions
                            flow[6] += 1
                            print("\tTransaction " + str(flow[6]) + "  - ACK")
                            print("\tSource port: " + str(flow[0]))
                            print("\tSource IP address: 130.245.145.12")
                            print("\tDestination port: " + str(flow[1]))
                            print("\tDestination IP address: 128.208.2.198")
                            print("\tSequence number: " + str(sequenceNum))
                            print("\tAck number: " + str(acknowledgeNum))
                            WindowSize = pow(2, flow[2]) * scalingFactor
                            print("\tWindow size: " + str(WindowSize))
                            print("   -------------------------------------------")
                        if flag == 17:  # FIN-ACK, flow ends
                            numFlows += 1
                            print("port " + str(destination))
                            print(str(flow[5]) + " packets")
                            print("RTT: " + str(flow[4] - flow[3]))
                            throughput = flow[5] / (flow[4] - flow[3])
                            print("Sender throughput in Flow " + str(numFlows) + ": " + str(throughput))
                            print("Retransmissions due to triple duplicate ack: " + str(flow[7]))
                            print('──────────────────────────────────────────────────\n')

        file.close()
        print("Number of TCP flows: " + str(numFlows))

    def checkDuplicateFlow(self, sourcePort, destinationPort, flowList):  # looks for duplicate flow in list
        for flow in flowList:
            return (flow[0] == sourcePort and flow[1] == destinationPort) \
                   or (flow[0] == destinationPort and flow[1] == sourcePort)

    def addFlow(self, sourcePort, destinationPort, scalingWindow, flowList):
        if self.checkDuplicateFlow(sourcePort, destinationPort, flowList):
            return flowList
        else:
            newFlow = [sourcePort, destinationPort, scalingWindow, 0, 0, 1, 0, 0, {}]
            flowList.append(newFlow)


if __name__ == "__main__":
    fileName = 'assignment2.pcap'
    currentFile = PcapParser(fileName)
    currentFile.readFile()
