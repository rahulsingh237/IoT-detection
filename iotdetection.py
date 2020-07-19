"""
assistant 111 30 42 59 70
camera 128 145 78
misc 216 46 84 91
mobile 45
outlet 222 67

each device is 192.168.1.#, the # is replaced by the number in the list
so assistant is 192.168.1.111, 192.168.1.30 etc.
"""

import os
import glob

ip_filter = {}

ip_filter['TCP_Mobile'] = "'tcp && (ip.src==192.168.1.45)'"
ip_filter['TCP_Outlet'] = "'tcp && (ip.src==192.168.1.222) || (ip.src==192.168.1.67)'"
ip_filter['TCP_Assistant'] = "'tcp && (ip.src==192.168.1.111) || (ip.src==192.168.1.30) || (ip.src==192.168.1.42) || (ip.src==192.168.1.59) || (ip.src==192.168.1.70)'"
ip_filter['TCP_Camera'] = "'tcp && (ip.src==192.168.1.128) || (ip.src==192.168.1.145) || (ip.src==192.168.1.78)'"
ip_filter['TCP_Miscellaneous'] = "'tcp && (ip.src==192.168.1.216) || (ip.src=192.168.1.46) || (ip.src==192.168.1.84) || (ip.src==192.168.1.91)'"

##############################################

labelFeature = open("label_feature_small.csv",'a')
labelFeature.writelines("label,IPlength,IPHeaderLength,IPFlags,TTL,Protocol,IPID,IPchecksum,SourcePort,Destport,SequenceNumber,AckNumber,WindowSize,TCPHeaderLength,TCPflags,TCPLength,TCPChecksum.TCPStream,TCPUrgentPointer\n")

##############################################

for original in glob.glob('original_pcap/*.pcap'):
    for k in ip_filter.keys():
        os.system("tshark -r" + original + "-w- -Y" + ip_filter[k] + ">>filtered_pcap/" + k + ".pcap")

##############################################

for filteredFile in glob.glob('filtered_pcap/*.pcap'):
    print(filteredFile)
    filename = filteredFile.split('/')[-1]
    label = filename.replace('.pcap','')
    tsharkCommand = "tshark -r" + filteredFile + "-T fields -e ip.len -e ip.hdr_len -e ip.ttl -e ip.proto -e ip.id -e ip.checksum -e tcp.srcport -e tcp.dstport -e tcp.seq -e tcp.ack -e tcp.window_size_value -e tcp.hdr_len -e tcp.flags -e tcp.len -e tcp.checksum -e tcp.stream -e tcp.urgent_pointer"
    allFeatures = str(os.popen(tsharkCommand).read())
    allFeatures = allFeatures.replace('\t',',')
    allFeaturesList = allFeatures.splitlines()
    for features in allFeaturesList:
        labelFeature.writelines(label + "," + features + "\n")

##############################################

print("Done")