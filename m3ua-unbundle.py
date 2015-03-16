#!/usr/bin/env python
#
#   M3UA unbundle
#   
__author__ = 'Andrey Usov <https://github.com/ownport/wireshark-pytools>'
__version__ = '0.2.4'
__license__ = """
Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 'AS IS'
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE."""


import sys
import math
import re

PROTOCOLS = {
    'SCTP': 132,
}

SCTP_CHUNK_TYPES = {
    'DATA': 0,
    'INIT': 1,
    'INIT ACK': 2,
    'SACK': 3,	
    'HEARTBEAT': 4,
    'HEARTBEAT ACK': 5, 
    'ABORT': 6,
    'SHUTDOWN': 7,
    'SHUTDOWN ACK': 8,
    'ERROR': 9,
    'COOKIE ECHO': 10,
    'COOKIE ACK': 11,
    'ECNE': 12,
    'CWR': 13,
    'SHUTDOWN': 14,
}

def remove_extra(chunk):
    ''' remove extra symbols '''
    
    chunk = chunk[0:53]
    fields = chunk.split(' ')[2:18]
    return ' '.join(fields)

def handle_packet(text2pcap_process, current_time, data, args):
    ''' handle packet '''
    data = data.split(' ')
    
    if args['sll']:
        (sll_header, data) = extract_sll(data)
        if sll_header['sll.etype'] <> ['08', '00']:
            # raise RuntimeError('Unknown IP type: %s' % ethernet_header['ip.type'])
            # return data
            return data
    else:
        (ethernet_header, data) = extract_ethernet(data)
        if ethernet_header['ip.type'] <> ['08', '00']:
            # raise RuntimeError('Unknown IP type: %s' % ethernet_header['ip.type'])
            # return data
            return
    
    (ipv4_header, data) = extract_ipv4(data)
    if ipv4_header['protocol'] <> PROTOCOLS['SCTP']:
        # raise RuntimeError('Unknown protocol: %s' % ipv4_header['protocol'])
        # return data
        return 
        
    # (sctp_data, data) = extract_sctp(data)
    # return data
    extract_sctp(text2pcap_process, current_time, data, args)
    return

def extract_ethernet(data):
    ''' extract ethernet header data '''

    header = dict()
    header['mac.desctination'] = data[0:6]
    header['mac.source'] = data[6:12]
    header['ip.type'] = data[12:14]
    return (header, data[14:])

def extract_sll(data):
    ''' extract linux cooked capture header '''

    #/*
    # * A DLT_LINUX_SLL fake link-layer header.
    # */
    ##define SLL_HDR_LEN 16      /* total header length */
    ##define SLL_ADDRLEN 8       /* length of address field */
    #
    #struct sll_header {
    #    u_int16_t sll_pkttype;      /* packet type */
    #    u_int16_t sll_hatype;       /* link-layer address type */
    #    u_int16_t sll_halen;        /* link-layer address length */
    #    u_int8_t sll_addr[SLL_ADDRLEN]; /* link-layer address */
    #    u_int16_t sll_protocol;     /* protocol */
    #};

    header = dict()
    header['sll.pkttype'] = data[0:2]
    header['sll.hatype'] = data[2:4]
    halen = header['sll.halen'] = data[4:6]
    header['sll.src.eth'] = data[6: 6 + int(halen[0] + halen[1], 16)]
    header['sll.etype'] = data[14:16]
    return (header, data[16:])

def extract_ipv4(data):
    ''' extract ipv4 header data '''  
      
    header = dict()
    header['version'] = data[0][0]
    header['length'] = int(data[0][1],16) * 4 # length in bytes
    header['dscp'] = data[1]
    header['total_length'] = data[2:4]
    header['identification'] = data[4:6]
    header['flags'] = data[6]
    header['fragment_offset'] = data[6:8]
    header['ttl'] = data[8]
    header['protocol'] = int(data[9], 16)
    return (header, data[header['length']:])

def extract_sctp(text2pcap_process, current_time, data, args):
    ''' extact sctp header data '''
    
    header = dict()
    header['source_port'] = data[0:2]
    header['desctination_port'] = data[2:4]
    header['verification_tag'] = data[4:8]
    header['checksum'] = data[8:12]
    data = data[12:]
    
    while True:
        if len(data) == 0:
            break
        (sctp_chunk, data) = extract_sctp_chunk(data)
        if sctp_chunk['type'] == SCTP_CHUNK_TYPES['DATA']:
            if sctp_chunk['length'] == 0:
                break
            # protocol payload identifier
            payload_identifier = int(''.join(sctp_chunk['data'][12:16]), 16)
            if payload_identifier == 3: # M3UA
                if (sctp_chunk['length'] - 16) < 8:  # small chunk
                    continue
                payload = sctp_chunk['data'][16:sctp_chunk['length']]
                m3ua_hdr, payload = m3ua_header(payload)
                mtp3_hdr = None
                if args['ansi']:
                    mtp3_hdr = m3ua_to_ansi_mtp3(m3ua_hdr)
                else:
                    mtp3_hdr = m3ua_to_mtp3(m3ua_hdr)
                if not mtp3_hdr:
                    continue
                if 'protocol.padding' in m3ua_hdr:
                    payload = mtp3_hdr + payload[:-m3ua_hdr['protocol.padding']]
                else:
                    payload = mtp3_hdr + payload
                # return header, payload
                save_data(text2pcap_process, current_time, payload)
            else:
                if sctp_chunk['length'] % 4 <> 0:
                    chunk_padding = 4 - sctp_chunk['length'] % 4
                    data = data[chunk_padding:]
    return header, data

def extract_sctp_chunk(data):
    ''' extract sctp chunk data '''
    header = dict()
    header['type'] = int(data[0], 16)
    header['flags'] = data[1]
    if len(data) < 4:
        header['length'] = 0
        return (header, None)
    header['length'] = int(''.join(data[2:4]), 16)
    header['data'] = data[0:header['length']]    
    return (header, data[header['length']:])

def m3ua_header(data):
    ''' extract M3UA header information '''
    def network_appearance(data):
        ''' return network_appearance parameters '''
        
        header = dict()
        length = int(''.join(data[0:2]),16)
        header['network_appearance'] = int(''.join(data[2:6]),16)
        return (header, data[length - 2:])

    def protocol(data):
        ''' return protocol parameters '''
        
        header = dict()
        length = int(''.join(data[0:2]),16)
        header['protocol.opc'] = int(''.join(data[2:6]),16)
        header['protocol.dpc'] = int(''.join(data[6:10]),16)
        header['protocol.si'] = int(data[10],16)
        header['protocol.ni'] = int(data[11],16)
        header['protocol.mp'] = data[12]
        header['protocol.sls'] = int(data[13],16)
        if length % 4 <> 0:
            header['protocol.padding'] = 4 - length % 4
        return (header, data[14:])

    header = dict()
    header['version'] = data[0]
    header['reserved'] = data[1]
    header['message_class'] = data[2]
    header['message_type'] = data[3]
    header['message_length'] = int(''.join(data[4:8]),16)

    # handle tags
    data = data[8:]
    pdata = []
    while True:
        try:
            tag = data[0:2]
            if tag == ['00','06']:
                data = data[8:]    
            elif tag == ['02','00']:
                (na_hdr, data) = network_appearance(data[2:])
                header.update(na_hdr)
            elif tag == ['02','10']:
                (protocol_hdr, data) = protocol(data[2:])
                header.update(protocol_hdr)
                pdata = data
            else:
                break
        except ValueError:
            break
        except IndexError:
            break
    return (header, pdata)

def m3ua_to_mtp3(m3ua_header):
    mtp3_header = list()
    # Service information octet
    try:
        sio = '%02x' % ((m3ua_header['protocol.ni'] << 6) + m3ua_header['protocol.si'])
        mtp3_header.append(sio)
        routing_label = (m3ua_header['protocol.sls'] << 28) + \
                        (m3ua_header['protocol.opc'] << 14) + \
                        m3ua_header['protocol.dpc']
        routing_label = '%08x' % routing_label
        routing_label = [routing_label[i:i+2] for i in range(0, len(routing_label), 2)]
        routing_label.reverse()
        mtp3_header.extend(routing_label)
    except KeyError:
        return None
    return mtp3_header

def m3ua_to_ansi_mtp3(m3ua_header):
    mtp3_header = list()
    # Service information octet
    try:
        sio = '%02x' % ((m3ua_header['protocol.ni'] << 6) + m3ua_header['protocol.si'])
        mtp3_header.append(sio)
        routing_label = (m3ua_header['protocol.sls'] << 48) + \
                        (m3ua_header['protocol.opc'] << 24) + \
                        m3ua_header['protocol.dpc']
        routing_label = '%014x' % routing_label
        routing_label = [routing_label[i:i+2] for i in range(0, len(routing_label), 2)]
        routing_label.reverse()
        mtp3_header.extend(routing_label)
    except KeyError:
        return None
    return mtp3_header

def save_data(process, current_time, data):
    ''' save data block to process '''

    process.stdin.write('%s\n' % current_time)  
    row_id = 0
    while True:
        if row_id >= len(data):
            break
        process.stdin.write('%04X %s\n' % (row_id, ' '.join(data[row_id:row_id+16])))
        row_id += 16
    process.stdin.write('\n')

def unbundling(tshark_process, text2pcap_process, args):
    ''' m3ua unbundling process '''
    
    current_time = ''
    timestamp_pattern = re.compile(r'\b(\d+\.\d+)\b')
    data_block = list()
       
    while tshark_process.poll() is None:

        tshark_line = tshark_process.stdout.readline()
        if not tshark_line:
            break
        if tshark_line[-1] == '\n':
            tshark_line = tshark_line[:-1]
        
        # windows platforms     
        if tshark_line and tshark_line[-1] == '\r':
            tshark_line = tshark_line[:-1]
                
        if tshark_line:
            data_block.append(tshark_line)
        else:
            if len(data_block) > 1:
                filtered_block = ''
                for chunk in data_block:
                    filtered_block += ' ' + remove_extra(chunk)
                    filtered_block = filtered_block.strip()
                #payload = handle_packet(filtered_block)
                #if payload:
                #    save_data(text2pcap_process, current_time, payload)
                handle_packet(text2pcap_process, current_time, filtered_block, args)
            elif len(data_block) == 1:
                timestamp = timestamp_pattern.search(data_block[0])
                if timestamp:
                    current_time = timestamp.group(0)

            data_block = list()
    
if __name__ == '__main__':

    import argparse
    import subprocess
    
    parser = argparse.ArgumentParser(description='m3ua unbundle')
    parser.add_argument('--filter', action='store', help='wireshark filter')
    parser.add_argument('-s', '--sll', action='store_true', help='Linux cooked-mode capture (SLL)')
    parser.add_argument('-a', '--ansi', action='store_true', help='ANSI MTP3')
    parser.add_argument('source', action='store', help='source pcap file')
    parser.add_argument('result', action='store', help='result pcap file')
    args = parser.parse_args()
    
    # tshark
    tshark_args = ['tshark', '-x', '-te', '-r', args.source]
    if args.filter:
        tshark_args.append(args.filter)
    tshark_process = subprocess.Popen(  tshark_args, 
                                        stdout=subprocess.PIPE)    

    # text2pcap
    text2pcap_args = ['text2pcap', '-l141', '-t', '%s.', '-', args.result]
    text2pcap_process = subprocess.Popen(text2pcap_args, 
                                        stdin=subprocess.PIPE)    
    
    try:
        unbundling(tshark_process, text2pcap_process, {'sll': args.sll, 'ansi': args.ansi})
    except KeyboardInterrupt:
        print 'Interrupted by user'
        sys.exit()

