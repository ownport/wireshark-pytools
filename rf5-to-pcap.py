#!/usr/bin/env python
#
#   rf5 to pcap
#
#   Example how to convert data from rf5 format to pcap (Gb interface, FrameRelay)
#   tshark -x -r <source.rf5> | ./rf5-to-pcap.py  | text2pcap -l 107 -t "%H:%M:%S." - <result.pcap>
# 
__author__ = 'Andrey Usov <https://github.com/ownport/m3ua-unbundle>'
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
        line = tshark_process.stdout.readline()
        if not line:
            break
        if line[-1] == '\n':
            line = line[:-1] 
        header = re.findall(r'^\s*(\d+)\s+(\d+\.\d+).+', line)        
        if header:
            secs, msecs = map(int, header[0][1].split('.'))
            hours = secs / 3600
            mins = (secs - hours * 3600) / 60
            secs = (secs - hours * 3600 - mins * 60)
            text2pcap_process.stdin.write("%02d:%02d:%02d.%06d\n" % (hours, mins, secs, msecs))
            line = tshark_process.stdout.readline()
        else:
            text2pcap_process.stdin.write('{}\n'.format(line))

if __name__ == '__main__':

    import argparse
    
    parser = argparse.ArgumentParser(description='rf5-to-pcap')
    parser.add_argument()
    if len(sys.argv) <> 3:
        print 'usage: ./rf5-to-pcap.py <source.rf5> <target.pcap>'
        sys.exit()
    
    source = sys.argv[1]
    target = sys.argv[2]
        
    tshark_process = subprocess.Popen(
                        ['tshark', '-x', '-r', source], 
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT)    

    text2pcap_process = subprocess.Popen(
                        ['text2pcap', '-l', '107', '-', target], 
                        stdin=subprocess.PIPE,
                        stderr=subprocess.PIPE)    
    try:
        convert(tshark_process, text2pcap_process)
    except KeyboardInterrupt:
        print 'Interrupted by user'
        sys.exit()
        


