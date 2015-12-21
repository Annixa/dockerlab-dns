#!/usr/bin/env python
# coding=utf-8

# Credit to pklaus and adreif on github for the gist on which this server is based
# Found at: https://gist.github.com/pklaus/b5a7876d4d2cf7271873

import argparse
import datetime
import signal
import sys
import time
import threading
import traceback
import SocketServer
import struct
import os
from pydal import DAL, Field
try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
    sys.exit(2)



# using get will return `None` if a key is not present rather than raise a `KeyError`
db_host = os.environ.get('POSTGRES_HOST')
db_name = os.environ.get('POSTGRES_DB')
db_user = os.environ.get('POSTGRES_USER')
db_pass = os.environ.get('POSTGRES_PASSWORD')

if not (db_name and db_user and db_pass):
    print "You kinda need db creds first, k?"
    print "Please include as environment (env_file or environment in docker-compose) POSTGRES_HOST, POSTGRES_DB, POSTGRES_USER, and POSTGRES_PASSWORD so dockerlab-dns can properly server DNS records."
    sys.exit(2)


#Connect with migrate = False  and define tables so DAL can use the schema natively
db = DAL('postgres://%s:%s@%s/%s'%(db_user, db_pass, db_host, db_name), migrate=True)
if db:
    print "Successfully connected to db \"%s\" on host \"%s\""%(db_name, db_host)

db.define_table('dns_zones',
    Field('name', 'string'), #ends in . (e.g. example.com.); input should probably have a validator to ensure zones end in a .
    )

db.define_table('dns_zone_records',
    Field('zone', 'reference dns_zones'),
    Field('record_name', 'string'), # (e.g. ns1.example.com.)
    Field('record_type', 'string', default = 'A'), # (e.g. A, AAAA, CNAME, MX, NS)
    Field('record_value', 'string'), # (e.g. an IP for A or AAAA, an address for CNAME, and an address and priority for MX)
    Field('record_ttl', 'integer', default = 60*5) #A TTL in seconds before a client should check for a new value. Can reasonably set to lower or higher depending on the volatility of the records
    )


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


# D = DomainName('example.com.')
# IP = '127.0.0.1'
# TTL = 60 * 5

# soa_record = SOA(
#     mname=D.ns1,  # primary name server
#     rname=D.andrei,  # email of the domain administrator
#     times=(
#         201307231,  # serial number
#         60 * 60 * 1,  # refresh
#         60 * 60 * 3,  # retry
#         60 * 60 * 24,  # expire
#         60 * 60 * 1,  # minimum
#     )
# )
# ns_records = [NS(D.ns1), NS(D.ns2)]
# records = {
#     D: [A(IP), AAAA((0,) * 16), MX(D.mail), soa_record] + ns_records,
#     D.ns1: [A(IP)],  # MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
#     D.ns2: [A(IP)],
#     D.mail: [A(IP)],
#     D.andrei: [CNAME(D)],
# }


def dns_response(data):
    request = DNSRecord.parse(data)

    print(request)

    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]

    print "Looking for zone and record type: %s, type: %s"%(qn, qt)

    # if qn == D or qn.endswith('.' + D):
    # Sheiße, multi `.` tlds suck (e.g. .co.uk)
    zone=None
    for z in db(db.dns_zones).select():
        if qn == z.name or qn.endswith('.' + z.name):
            zone=z
            break

    if zone:
        print "Found zone: %s"%(zone)

        # Lookup records in zone. Required for wildcard queries
        for record in db((db.dns_zone_records.zone == zone.id) & (db.dns_zone_records.record_name == qn)).select():
            rqt = record.record_type
            print "Possible record in zone (%s): %s: %s"%(qn, record.record_type, record.record_value)

            # Found a record in the requested types!
            if qt in ['*', rqt]:
                print "Found record in zone (%s): %s: %s "%(qn, record.record_type, record.record_value)

                # Be sure requested type is indeed in dnslib
                if qt in dir(dns):
                    record_value = record.record_value.split(" ")
                    # Handles MX priorities explicitly or implicitly and other records
                    reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=record.record_ttl, rdata=getattr(dns,qt)(record_value[1], int(record_value[0])) if record.record_type == 'MX' and len(record_value) > 1 else getattr(dns,qt)(record_value[0])))
                else:
                    print "Error: Requested a non DNS record type: %s"%(qt)

        for rdata in db((db.dns_zone_records.id == zone.id) & (db.dns_zone_records.record_type == 'NS')).select():
            reply.add_ar(RR(rname=zone.name, rtype=QTYPE.NS, rclass=1, ttl=record.record_ttl, rdata=NS(rdata.record_value)))

        SOA_rec=db((db.dns_zone_records.id == zone.id) & (db.dns_zone_records.record_type == 'SOA')).select().first()
        if SOA_rec:
            SOA_vals = SOA_rec.record_value.split(" ")
            reply.add_auth(RR(rname=zone.name, rtype=QTYPE.SOA, rclass=1, ttl=SOA_rec.record_ttl, rdata=SOA(SOA_vals[0], SOA_vals[1], times=tuple([int(n) for n in SOA_vals[2:]]))))

    print("---- Reply:\n", reply)

    return reply.pack()


class BaseRequestHandler(SocketServer.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        print("\n\n%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],
                                               self.client_address[1]))
        try:
            data = self.get_data()
            print(len(data), data)  # repr(data).replace('\\x', '')[1:-1]
            self.send_data(dns_response(data))
        except Exception:
            traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = struct.unpack('>H', data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


def main():
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python.')
    parser.add_argument('--port', default=53, type=int, help='The port to listen on.')
    parser.add_argument('--tcp', action='store_true', help='Listen to TCP connections.')
    parser.add_argument('--udp', action='store_true', help='Listen to UDP datagrams.')
    
    args = parser.parse_args()
    if not (args.udp or args.tcp): parser.error("Please select at least one of --udp or --tcp.")

    print("Starting nameserver...")

    servers = []
    if args.udp: servers.append(SocketServer.ThreadingUDPServer(('', args.port), UDPRequestHandler))
    if args.tcp: servers.append(SocketServer.ThreadingTCPServer(('', args.port), TCPRequestHandler))

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    status=dict(sigintted=False)
    def signal_handler(signal, frame):
            print('Received SIGINT from system')
            status["sigintted"]=True
    signal.signal(signal.SIGINT, signal_handler)

    try:
        while not status["sigintted"]:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()

if __name__ == '__main__':
    main()
