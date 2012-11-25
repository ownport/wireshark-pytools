#!/usr/bin/env python
#
#   rf5 to pcap
#
__author__ = 'Andrey Usov <https://github.com/ownport/wireshark-pytools>'
__version__ = '0.1'
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

import re
import sys
import subprocess

def convert(tshark_process, text2pcap_process):
    ''' convert handler from rf5 to pcap '''
    
    while tshark_process.poll() is None:
        tshark_line = tshark_process.stdout.readline()
        if not tshark_line:
            break
        if tshark_line[-1] == '\n':
            tshark_line = tshark_line[:-1] 
        header = re.findall(r'^\s*(\d+)\s+(\d+\.\d+).+', tshark_line)        
        if header:
            secs, msecs = map(int, header[0][1].split('.'))
            hours = secs / 3600
            mins = (secs - hours * 3600) / 60
            secs = (secs - hours * 3600 - mins * 60)
            text2pcap_process.stdin.write("%02d:%02d:%02d.%06d\n" % (hours, mins, secs, msecs))
            tshark_line = tshark_process.stdout.readline()
        else:
            text2pcap_process.stdin.write('{}\n'.format(tshark_line))

if __name__ == '__main__':

    import argparse
    
    parser = argparse.ArgumentParser(description='convert rf5 files to pcap')
    parser.add_argument('--filter', action='store', help='wireshark filter')
    parser.add_argument('--layer', action='store', 
                        help='link-layer header type, http://www.tcpdump.org/linktypes.html')
    parser.add_argument('source', action='store', help='rf5 file')
    parser.add_argument('target', action='store', help='pcap file')
    args = parser.parse_args()
    
    # tshark
    tshark_args = ['tshark', '-x', '-r', args.source]
    if args.filter:
        tshark_args.append(args.filter)
    tshark_process = subprocess.Popen(  tshark_args, 
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.STDOUT)    

    # text2pcap
    text2pcap_args = ['text2pcap',]
    if args.layer:
        text2pcap_args.extend(['-l', args.layer])
    text2pcap_args.extend(['-', args.target])
    text2pcap_process = subprocess.Popen(text2pcap_args, 
                                        stdin=subprocess.PIPE, 
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE)    
    
    # rf5 -> pcap
    try:
        convert(tshark_process, text2pcap_process)
    except KeyboardInterrupt:
        print 'Interrupted by user'
        sys.exit()
        


