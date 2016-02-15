#!/usr/bin/env python
# coding=utf-8

import datetime
import time
from validators import IS_IN_SET
from pydal import DAL, Field

# Generate list of supported record types
RECORD_TYPES = ['A', 'NS', 'CNAME', 'SOA', 'PTR', 'MX', 'TXT', 'RP', 'AFSDB', 'SIG', 'KEY', 'AAAA', 'LOC', 'SRV', 'NAPTR', 'KX', 'CERT', 'DNAME', 'OPT', 'APL', 'DS', 'SSHFP', 'IPSECKEY', 'RRSIG', 'NSEC', 'DNSKEY', 'DHCID', 'NSEC3', 'NSEC3PARAM', 'TLSA', 'HIP', 'SPF', 'TKEY', 'TSIG', 'IXFR', 'AXFR', 'ANY', 'TYPE257', 'TA', 'DLV']

# I gave a lot of thought to this class name.
# http://stackoverflow.com/questions/2853531/how-do-you-pep-8-name-a-class-whose-name-is-an-acronym
class DNSAPI(object):
	"""DNSAPI is an easy way to use your database so dockerlab-dns knows how to read your records. Use this class to interact with the database or just use it as an example."""
	def __init__(self, db_user, db_pass, db_host, db_name, migrate=False):
		super(DNSAPI, self).__init__()
		self.db = DAL('postgres://%s:%s@%s/%s'%(db_user, db_pass, db_host, db_name), migrate=migrate)
	
		if self.db:
		    print "Successfully connected to db \"%s\" on host \"%s\""%(db_name, db_host)

		self.db.define_table('dns_zones',
		    Field('name', 'string'), #ends in . (e.g. example.com.); input should probably have a validator to ensure zones end in a .
		    )

		self.db.define_table('dns_zone_records',
		    Field('zone', 'reference dns_zones'),
		    Field('record_name', 'string'), # (e.g. ns1.example.com.)
		    Field('record_type', 'string', default = 'A', requires=IS_IN_SET(RECORD_TYPES)), # (e.g. A, AAAA, CNAME, MX, NS)
		    Field('record_value', 'string'), # (e.g. an IP for A or AAAA, an address for CNAME, and an address and priority for MX)
		    Field('record_ttl', 'integer', default = 60*5) #A TTL in seconds before a client should check for a new value. Can reasonably set to lower or higher depending on the volatility of the records
		    )


	def get_zones(self):
		return self.db(self.db.dns_zones).select().as_list()

	def get_zone(self, zone_name):
		return self.db(self.db.dns_zones.name == zone_name).select().as_list()

	def get_records(self, zone_id):
		return self.db((self.db.dns_zone_records.zone == zone_id)).select().as_list()

	def get_records_matching(self, zone_id, record_name=None, record_type=None):
		q = (self.db.dns_zone_records.zone == zone_id)
		if not record_name is None:
			q = (q & (self.db.dns_zone_records.record_name == record_name))
		if not record_type is None:
			q = (q & (self.db.dns_zone_records.record_type == record_type))
		return self.db(q).select().as_list()



	def delete_zone(self, zone_name):
		self.db.dns_zones((self.db.dns_zone_records.zone == self.db.dns_zones.id ) & (self.db.dns_zones.name == zone_name)).delete()
		return self.db(self.db.dns_zones.name == zone_name).delete()

	def delete_record(self, record_id):
		return self.db((self.db.dns_zone_records.id == record_id)).delete()

	def delete_record_matching(self, zone_id, record_name, record_type):
		return self.db((self.db.dns_zone_records.zone == zone_id) & (self.db.dns_zone_records.record_name == record_name) & (self.db.dns_zone_records.record_type==record_type)).delete()



	def create_zone(self, zone_name):
		return self.db.dns_zones.insert(name=zone_name)

	def create_record(self, zone_id, record_name, record_type, record_value, record_ttl):
		return self.db.dns_zone_records.insert(zone=zone_id, record_name=record_name, record_type=record_type, record_value=record_value, record_ttl=record_ttl)

