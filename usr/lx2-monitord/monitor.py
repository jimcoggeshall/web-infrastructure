#!/opt/conda/bin/python

import nest_asyncio
import asyncio
import concurrent.futures
import functools
from functools import partial

import socket
import socketserver
import sys
import os
import posix
import websockets

import json
from json import JSONDecodeError
import datetime
from pytz import timezone

import ipaddress
import functools
import numpy as np
import pandas as pd
import time
import queue
import radix
import tldextract
import math
import collections

import pyspark
from pyspark import SparkContext
from pyspark.streaming import StreamingContext
from pyspark.sql import Row, SparkSession
from pyspark.sql.types import *
import pyspark.sql.functions as func

            
vars_in_score = [
    "weight_20min_dns_query_name",
    "weight_20min_dns_query_sld_by_query_sld_fraction",
    "weight_5min_dns_query_sld_by_query_sld_fraction",
    "weight_5min_server_pfx",
    "weight_5min_server_addr",
    "weight_5min_server_orgname_by_asn_fraction",
    "weight_5min_server_port_desc"
]
show_weights = False

class PacketHandler(socketserver.BaseRequestHandler):

    def setup(self):
        with open("/home/jovyan/work/ip-protocol-numbers.json", "r") as f:
            self._ip_protocols = json.load(f)
        ports = pd.read_csv("/home/jovyan/work/ports.csv")
        self._ports_list = {
            "TCP": {
                str(k): v 
                for (k, v) in ports[ports["protocol"] == "TCP"]
                    .set_index("port")["description"]
                    .to_dict()
                    .items()
            },
            "UDP": {
                str(k): v 
                for (k, v) in ports[ports["protocol"] == "UDP"]
                    .set_index("port")["description"]
                    .to_dict()
                    .items()
            }
        }
        self._asn_info = radix.Radix()
        with open("/home/jovyan/work/ip2asn-v4.tsv", "r") as f:
            for rline in f.readlines():
                sline = rline.rstrip().split("\t")
                net_start = ipaddress.IPv4Address(sline[0])
                net_end = ipaddress.IPv4Address(sline[1])
                asn = sline[2]
                country = sline[3]
                orgname = sline[4]
                as_org_list = orgname.split(" ")
                if orgname != "Not routed" and len(as_org_list) > 1:
                    orgname = " ".join(as_org_list[1:]).lstrip(" - ")
                rec = {
                    "asn": asn,
                    "country": country,
                    "orgname": orgname
                }
                for net in ipaddress.summarize_address_range(net_start, net_end):
                    pfx = net.with_prefixlen
                    node = self._asn_info.add(pfx)
                    node.data["data"] = {
                        "prefix": pfx,
                        **rec
                    }
    
    def _get_hostnames_if_necessary(self):
        if not hasattr(self, "_hostnames_init"):
            self._update_hostnames()
            self._hostnames_init = True
            self._hostnames_sent = datetime.datetime.now()
            return self._get_hostnames()
        if (datetime.datetime.now() - self._hostnames_sent).total_seconds() < 30:
            return None
        self._hostnames_sent = datetime.datetime.now()
        return self._get_hostnames()

    def _extract_host(self, line):
        sline = line.rstrip().split("\t")
        return (sline[0], sline[-1])
    
    def _extract_asinfo(self, addr):
        best_result = self._asn_info.search_best(addr)
        if best_result == None:
            return {
                "asn": 0,
                "country": "",
                "orgname": "Not routed",
                "prefix": "0.0.0.0/0",
            }
        return best_result.data["data"]

    def _update_hostnames(self):
        with open("/etc/lx2-hosts", "r") as f:
            self._hostnames = dict(self._extract_host(line) for line in f)
        self._hostnames_updated = datetime.datetime.now()

    def _get_hostnames(self):
        if (datetime.datetime.now() - self._hostnames_updated).total_seconds() > 300:
            self._update_hostnames()
        return self._hostnames

    def handle(self):
        streamer = iter(self._stream_packets(self._parse_message))
        while True:
            p = next(streamer)
            hostnames = self._get_hostnames_if_necessary()
            if hostnames != None:
                hostnames_out = {
                    "hostname_map": hostnames
                }
                p.insert(0, hostnames_out)
            for mr in p:
                m = self._enrich_message(mr)
                json_out = json.dumps(m, separators=(",", ":")) + "\n"
                self.request.sendall(
                    bytes(
                        json_out, 
                        "utf-8"
                    )
                )

    def _stream_packets(self, _parse):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", 22055))
            while True:
                p, _ = s.recvfrom(65536)
                parsed = ""
                while parsed == "":
                    try:
                        parsed = _parse(p)
                    except JSONDecodeError:
                        parsed = ""
                        pn, _ = s.recvfrom(65536)
                        p += pn
                yield parsed

    def _parse_message(self, x):
        s = x.decode("utf-8").rstrip()
        return [json.loads(m) for m in s.split("\n")]
        
    def _enrich_message(self, x):
        if "cflow" in x.get("layers", {}):
            if "text_cflow_protocol" in x["layers"]["cflow"]:
                if type(x["layers"]["cflow"]["text_cflow_protocol"]) is list:
                    flow_ip_protocol = [
                        self._ip_protocols.get(proto, {}).get("keyword", proto)
                        for proto in x["layers"]["cflow"]["text_cflow_protocol"]
                    ]
                    if "text_cflow_srcport" in x["layers"]["cflow"]:
                        if type(x["layers"]["cflow"]["text_cflow_srcport"]) is list:
                            src_port_list = x["layers"]["cflow"]["text_cflow_srcport"]
                            src_port_desc = [
                                self._ports_list.get(pr, {}).get(port, "/".join([port, pr]))
                                for (pr, port) in zip(flow_ip_protocol, src_port_list)
                            ]
                            x["layers"]["cflow"].update({"src_port_desc": src_port_desc})
                    if "text_cflow_dstport" in x["layers"]["cflow"]:
                        if type(x["layers"]["cflow"]["text_cflow_dstport"]) is list:
                            dst_port_list = x["layers"]["cflow"]["text_cflow_dstport"]
                            dst_port_desc = [
                                self._ports_list.get(pr, {}).get(port, "/".join([port, pr]))
                                for (pr, port) in zip(flow_ip_protocol, dst_port_list)
                            ]
                            x["layers"]["cflow"].update({"dst_port_desc": dst_port_desc})
                else:
                    proto = x["layers"]["cflow"]["text_cflow_protocol"]
                    flow_ip_protocol = self._ip_protocols.get(proto, {}).get("keyword", proto)
                    if "text_cflow_srcport" in x["layers"]["cflow"]:
                        if type(x["layers"]["cflow"]["text_cflow_srcport"]) is str:
                            src_port = x["layers"]["cflow"]["text_cflow_srcport"]
                            src_port_desc = self._ports_list.get(
                                flow_ip_protocol, {}
                            ).get(
                                src_port, "/".join([src_port, flow_ip_protocol])
                            )
                            x["layers"]["cflow"].update({"src_port_desc": src_port_desc})
                    if "text_cflow_dstport" in x["layers"]["cflow"]:
                        if type(x["layers"]["cflow"]["text_cflow_dstport"]) is str:
                            dst_port = x["layers"]["cflow"]["text_cflow_dstport"]
                            dst_port_desc = self._ports_list.get(
                                flow_ip_protocol, {}
                            ).get(
                                dst_port, "/".join([dst_port, flow_ip_protocol])
                            )
                            x["layers"]["cflow"].update({"dst_port_desc": dst_port_desc})
                x["layers"]["cflow"].update({"flow_ip_protocol": flow_ip_protocol})
            if "text_cflow_srcaddr" in x["layers"]["cflow"]:
                if type(x["layers"]["cflow"]["text_cflow_srcaddr"]) is list:
                    src_as_info = [
                        self._extract_asinfo(srcaddr)
                        for srcaddr in x["layers"]["cflow"]["text_cflow_srcaddr"]
                    ]
                else:
                    src_as_info = self._extract_asinfo(
                        x["layers"]["cflow"]["text_cflow_srcaddr"]
                    )
                x["layers"]["cflow"].update({"src_as_info": src_as_info})
            if "text_cflow_dstaddr" in x["layers"]["cflow"]:
                if type(x["layers"]["cflow"]["text_cflow_dstaddr"]) is list:
                    dst_as_info = [
                        self._extract_asinfo(dstaddr)
                        for dstaddr in x["layers"]["cflow"]["text_cflow_dstaddr"]
                    ]
                else:
                    dst_as_info = self._extract_asinfo(
                        x["layers"]["cflow"]["text_cflow_dstaddr"]
                    )
                x["layers"]["cflow"].update({"dst_as_info": dst_as_info})
        return x

def serve_packets():
    with socketserver.TCPServer(("0.0.0.0", 11111), PacketHandler) as server:
        server.allow_reuse_address = True
        server.serve_forever()


def error_record(x):
    x.update({"record_type": "error"})
    return x


def is_addr_local(saddr):
    addr = ipaddress.IPv4Address(saddr)
    if not addr.is_private:
        return False
    if addr in ipaddress.IPv4Network("10.0.0.0/8"):
        return True
    if addr in ipaddress.IPv4Network("192.168.0.0/16"):
        return True
    if addr in ipaddress.IPv4Network("172.16.0.0/12"):
        return True
    return False


def extract_cflow_payload(cflow_record):
    src_port = int(cflow_record.get("text_cflow_srcport", "0"))
    dst_port = int(cflow_record.get("text_cflow_dstport", "0"))
    flow_packets = int(cflow_record.get("text_cflow_packets", "0"))
    flow_bytes = int(cflow_record.get("text_cflow_octets", "0"))
    flow_direction = int(cflow_record.get("text_cflow_direction", "0"))
    flow_timestart = cflow_record.get("cflow_timedelta_cflow_timestart", "0")
    flow_timeend = cflow_record.get("cflow_timedelta_cflow_timeend", "0")
    src_is_client = False
    dst_is_client = False
    src_addr = cflow_record["text_cflow_srcaddr"]
    dst_addr = cflow_record["text_cflow_dstaddr"]
    src_is_private = is_addr_local(src_addr)
    dst_is_private = is_addr_local(dst_addr)
    src_is_client = src_is_private and not dst_is_private
    dst_is_client = dst_is_private and not src_is_private
    if src_is_client == dst_is_client:
        dst_is_client = src_port < dst_port and dst_is_private
        src_is_client = dst_port < src_port and src_is_private
        if src_is_client == dst_is_client:
            dst_is_client = src_port < dst_port
            src_is_client = dst_port < src_port
            if src_is_client == dst_is_client:
                src_is_client = flow_direction == 0
                dst_is_client = not src_is_client
    if src_is_client:
        client_addr = src_addr
        server_addr = dst_addr
        client_port = src_port
        server_port = dst_port
        server_as_info = cflow_record.get("dst_as_info", {})
        server_asn = server_as_info.get("asn", 0)
        server_country = server_as_info.get("country", "")
        server_orgname = server_as_info.get("orgname", "")
        server_prefix = server_as_info.get("prefix", "")
        server_port_desc = cflow_record.get("dst_port_desc", server_port)
    if dst_is_client:
        client_addr = dst_addr
        server_addr = src_addr
        client_port = dst_port
        server_port = src_port
        server_as_info = cflow_record.get("src_as_info", {})
        server_asn = server_as_info.get("asn", 0)
        server_country = server_as_info.get("country", "")
        server_orgname = server_as_info.get("orgname", "")
        server_prefix = server_as_info.get("prefix", "")
        server_port_desc = cflow_record.get("src_port_desc", server_port)
        
    cflow_payload = {
        "flow_packets": flow_packets,
        "flow_bytes": flow_bytes,
        "flow_direction": flow_direction,
        "flow_timestart": flow_timestart,
        "flow_timeend": flow_timeend,
        "client_addr": client_addr,
        "server_addr": server_addr,
        "client_port": client_port,
        "server_port": server_port,
        "src_addr": src_addr,
        "dst_addr": dst_addr,
        "src_port": src_port,
        "dst_port": dst_port,
        "server_asn": server_asn,
        "server_country": server_country,
        "server_orgname": server_orgname,
        "server_port_desc": server_port_desc,
        "server_pfx": server_prefix
    }
    return cflow_payload


def extract_second_level_domain(x):
    try:
        extract_result = tldextract.extract(x)
        return extract_result.registered_domain
    except:
        return ""


def extract_dns_payload(dns_record, ip_record):
    client_addr = ip_record["ip_ip_dst"]
    dns_query_name = dns_record["text_dns_qry_name"]
    dns_query_sld = extract_second_level_domain(dns_query_name)
    dns_resp_types = dns_record["text_dns_resp_type"]
    dns_rcode = dns_record["dns_flags_dns_flags_rcode"]
    dns_payload = {
        "client_addr": client_addr,
        "dns_query_name": dns_query_name,
        "dns_query_sld": dns_query_sld,
        "dns_resp_types": dns_resp_types,
        "dns_rcode": dns_rcode
    }
    return dns_payload


def parse_record(x):
        
    this_record = {"payload": {"_original_record": x}}
    records = []
    errored = False
    
    try:
        this_record.update(json.loads(x))
    except JSONDecodeError:
        errored = True
        records.append(error_record(this_record))
    
    try:
    
        if "hostname_map" in this_record:
            hostname_map = this_record.get("hostname_map")
            for (client_addr, client_hostname) in hostname_map.items():
                this_hostname_map_record = {
                    "record_type": "hostname_map",
                    "payload": {
                        "hostname_map": {
                            "client_addr": client_addr,
                            "client_hostname": client_hostname
                        }
                    }
                }
                records.append(this_hostname_map_record)
        elif "cflow" in this_record.get("layers", {}):
            if "text_cflow_srcaddr" not in this_record["layers"]["cflow"].keys():
                this_record.update({"record_type": "cflow_template"})
                records.append(this_record)
            else:
                this_record.update({"record_type": "cflow"})
                cflow_record = this_record.get("layers")\
                    .get("cflow")

                if type(cflow_record["text_text"]) is list:
                    nflows = len(cflow_record["text_text"])
                    list_fields_this = [
                        k for (k, v) in cflow_record.items()
                        if type(v) is list
                    ]
                    flow_fields_this = [
                        k for k in list_fields_this
                        if len(cflow_record[k]) == nflows
                    ]
                    for field_values in zip(
                        *[cflow_record[f] for f in flow_fields_this]
                    ):
                        this_cflow_record = {
                            **this_record,
                            "payload": {
                                "cflow": extract_cflow_payload({
                                    k: v for (k, v) in zip(
                                        flow_fields_this, 
                                        field_values
                                    )
                                })
                            }
                        }
                        records.append(this_cflow_record)
                elif type(cflow_record["text_text"]) is str:
                    this_cflow_record = {
                        **this_record,
                        "payload": {
                            "cflow": extract_cflow_payload(cflow_record)
                        }
                    }
                    records.append(this_cflow_record)
                elif not errored: 
                    errored = True
                    records.append(error_record(this_record))

        elif "dns" in this_record.get("layers", {}):
            this_record.update({
                "record_type": "dns",
                "payload": {
                    "dns" : extract_dns_payload(
                        this_record.get("layers").get("dns"),
                        this_record.get("layers").get("ip")
                    )
                }
            })
            records.append(this_record)
        elif not errored: 
            errored = True
            records.append(error_record(this_record))

    except KeyError:
        errored = True
        records.append(error_record(this_record))
        
    for out in records:
        yield out

        
def filter_record(x):
    return x["record_type"] in set(["hostname_map", "cflow", "dns"])


def update_univeral_state(part, universal_state):

    if universal_state is None:
        universal_state = {
            "dns_query_name_counter": collections.Counter(),
            "dns_query_sld_counter": collections.Counter(),
            "server_addr_counter": collections.Counter(),
            "server_asn_counter": collections.Counter(),
            "records": []
        }

    this_part_records = []
    dns_query_name_counter = universal_state["dns_query_name_counter"]
    dns_query_sld_counter = universal_state["dns_query_sld_counter"]
    server_addr_counter = universal_state["server_addr_counter"]
    server_asn_counter = universal_state["server_asn_counter"]
    for x in part:
        this_record_type = x["record_type"]
        if x["record_type"] == "dns":
            this_dns_query_name = x["payload"]["dns"]["dns_query_name"]
            dns_query_name_counter[this_dns_query_name] += 1
            x["payload"]["dns"]["dns_query_name_counts"] = dns_query_name_counter[this_dns_query_name]
            x["payload"]["dns"]["dns_query_name_fraction"] = dns_query_name_counter[this_dns_query_name]/sum(dns_query_name_counter.values())
            this_dns_query_sld = x["payload"]["dns"]["dns_query_sld"]
            dns_query_sld_counter[this_dns_query_sld] += 1
            x["payload"]["dns"]["dns_query_sld_counts"] = dns_query_sld_counter[this_dns_query_sld]
            x["payload"]["dns"]["dns_query_sld_fraction"] = dns_query_sld_counter[this_dns_query_sld]/sum(dns_query_sld_counter.values())
        elif x["record_type"] == "cflow":
            if x["payload"]["cflow"]["server_orgname"] != "Not routed":
                this_server_addr = x["payload"]["cflow"]["server_addr"]
                server_addr_counter[this_server_addr] += 1
                x["payload"]["cflow"]["server_addr_counts"] = server_addr_counter[this_server_addr]
                x["payload"]["cflow"]["server_addr_fraction"] = server_addr_counter[this_server_addr]/sum(server_addr_counter.values())
                this_server_asn = x["payload"]["cflow"]["server_asn"]
                server_asn_counter[this_server_asn] += 1
                x["payload"]["cflow"]["server_asn_counts"] = server_asn_counter[this_server_asn]
                x["payload"]["cflow"]["server_asn_fraction"] = server_asn_counter[this_server_asn]/sum(server_asn_counter.values())
        this_part_records.append(x)
    
    universal_state["dns_query_name_counter"] = collections.Counter(dns_query_name_counter.most_common(1000))
    universal_state["dns_query_sld_counter"] = collections.Counter(dns_query_sld_counter.most_common(500))
    universal_state["server_addr_counter"] = collections.Counter(server_addr_counter.most_common(5000))
    universal_state["server_asn_counter"] = collections.Counter(server_asn_counter.most_common(500))
    universal_state["records"] = this_part_records

    return universal_state


def update_client_addr(part, client_addr_state):
    
    now = datetime.datetime.now()

    client_addr_event_weights = {
        "weight_5min_record_type": 50.0*(1/(5*60)),
        "weight_20min_dns_query_name": 100.0*(1/(20*60)),
        "weight_5min_dns_query_name": 50.0*(1/(5*60)),
        "weight_20min_dns_query_sld": 100.0*(1/(20*60)),
        "weight_5min_dns_query_sld": 10.0*(1/(5*60)),
        "weight_20min_dns_query_sld_by_query_sld_fraction": 100.0*(1/(20*60)),
        "weight_5min_dns_query_sld_by_query_sld_fraction": 10.0*(1/(5*60)),
        "weight_5min_server_pfx": 10.0*(1/(5*60)),
        "weight_5min_server_addr": 10.0*(1/(5*60)),
        "weight_5min_server_port": 10.0*(1/(5*60)),
        "weight_5min_server_orgname": 10.0*(1/(5*60)),
        "weight_5min_server_orgname_by_asn_fraction": 10.0*(1/(5*60)),
        "weight_5min_server_port_desc": 10.0*(1/(5*60))
    }
    
    if client_addr_state != None:
        recent_update = datetime.datetime.fromisoformat(client_addr_state["client_recent_update"])
        delta_seconds_recent = (now - recent_update).total_seconds()
        for (k, v) in client_addr_state.items():
            event_weight = client_addr_event_weights.get(k, 0)
            if k.startswith("weight_5min"):
                for (n, c) in v.items():
                    client_addr_state[k][n] = c*np.exp(-delta_seconds_recent/(5*60))
            if k.startswith("weight_20min"):
                for (n, c) in v.items():
                    client_addr_state[k][n] = c*np.exp(-delta_seconds_recent/(20*60))
                    
    if client_addr_state is None:
        client_addr_state = {
            "client_recent_update": now.isoformat(),
            "client_hostname": "",
            "score": 0,
            "weight_5min_record_type": {},
            "weight_20min_dns_query_name": {},
            "weight_5min_dns_query_name": {},
            "weight_20min_dns_query_sld": {},
            "weight_5min_dns_query_sld": {},
            "weight_20min_dns_query_sld_by_query_sld_fraction": {},
            "weight_5min_dns_query_sld_by_query_sld_fraction": {},
            "weight_5min_server_pfx": {},
            "weight_5min_server_addr": {},
            "weight_5min_server_port": {},
            "weight_5min_server_orgname": {},
            "weight_5min_server_orgname_by_asn_fraction": {},
            "weight_5min_server_port_desc": {}
        }    
        
    for x in part:
            
        this_record_type = x["record_type"]
        weight_5min_this_record_type = client_addr_state["weight_5min_record_type"]\
            .get(this_record_type, 0) + 1
        client_addr_state["weight_5min_record_type"][this_record_type] = weight_5min_this_record_type
        if x["record_type"] == "hostname_map":
            client_addr_state["client_hostname"] = x["payload"]["hostname_map"]["client_hostname"]
        elif x["record_type"] == "dns":
            this_dns_query_name = x["payload"]["dns"]["dns_query_name"]
            weight_5min_this_dns_query_name = client_addr_state["weight_5min_dns_query_name"]\
                .get(this_dns_query_name, 0) + client_addr_event_weights.get("weight_5min_dns_query_name", 0)
            client_addr_state["weight_5min_dns_query_name"][this_dns_query_name] = weight_5min_this_dns_query_name
            this_dns_query_name = x["payload"]["dns"]["dns_query_name"]
            weight_20min_this_dns_query_name = client_addr_state["weight_20min_dns_query_name"]\
                .get(this_dns_query_name, 0) + client_addr_event_weights.get("weight_20min_dns_query_name", 0)
            client_addr_state["weight_20min_dns_query_name"][this_dns_query_name] = weight_20min_this_dns_query_name
            this_dns_query_sld_fraction = x["payload"]["dns"]["dns_query_sld_fraction"]
            this_dns_query_sld = x["payload"]["dns"]["dns_query_sld"]
            weight_5min_this_dns_query_sld = client_addr_state["weight_5min_dns_query_sld"]\
                .get(this_dns_query_sld, 0) + client_addr_event_weights.get("weight_5min_dns_query_sld", 0)
            client_addr_state["weight_5min_dns_query_sld"][this_dns_query_sld] = weight_5min_this_dns_query_sld
            weight_5min_this_dns_query_sld_by_query_sld_fraction = client_addr_state["weight_5min_dns_query_sld_by_query_sld_fraction"]\
                .get(this_dns_query_sld, 0) + client_addr_event_weights.get("weight_5min_dns_query_sld_by_query_sld_fraction", 0)/this_dns_query_sld_fraction
            client_addr_state["weight_5min_dns_query_sld_by_query_sld_fraction"][this_dns_query_sld] = weight_5min_this_dns_query_sld_by_query_sld_fraction
            weight_20min_this_dns_query_sld = client_addr_state["weight_20min_dns_query_sld"]\
                .get(this_dns_query_sld, 0) + client_addr_event_weights.get("weight_20min_dns_query_sld", 0)
            client_addr_state["weight_20min_dns_query_sld"][this_dns_query_sld] = weight_20min_this_dns_query_sld
            weight_20min_this_dns_query_sld_by_query_sld_fraction = client_addr_state["weight_20min_dns_query_sld_by_query_sld_fraction"]\
                .get(this_dns_query_sld, 0) + client_addr_event_weights.get("weight_20min_dns_query_sld_by_query_sld_fraction", 0)/this_dns_query_sld_fraction
            client_addr_state["weight_20min_dns_query_sld_by_query_sld_fraction"][this_dns_query_sld] = weight_20min_this_dns_query_sld_by_query_sld_fraction
            client_addr_state["client_recent_update"] = datetime.datetime.now().isoformat()
        elif x["record_type"] == "cflow":
            if x["payload"]["cflow"]["server_orgname"] != "Not routed":
                this_server_addr = x["payload"]["cflow"]["server_addr"]
                weight_5min_this_server_addr = client_addr_state["weight_5min_server_addr"]\
                    .get(this_server_addr, 0) + client_addr_event_weights.get("weight_5min_server_addr", 0)
                client_addr_state["weight_5min_server_addr"][this_server_addr] = weight_5min_this_server_addr
                this_server_asn_fraction = x["payload"]["cflow"]["server_asn_fraction"]
                this_server_orgname = x["payload"]["cflow"]["server_orgname"]
                weight_5min_this_server_orgname = client_addr_state["weight_5min_server_orgname"]\
                    .get(this_server_orgname, 0) + client_addr_event_weights.get("weight_5min_server_orgname", 0)
                client_addr_state["weight_5min_server_orgname"][this_server_orgname] = weight_5min_this_server_orgname        
                weight_5min_this_server_orgname_by_asn_fraction = client_addr_state["weight_5min_server_orgname_by_asn_fraction"]\
                    .get(this_server_orgname, 0) + client_addr_event_weights.get("weight_5min_server_orgname", 0)/this_server_asn_fraction
                client_addr_state["weight_5min_server_orgname_by_asn_fraction"][this_server_orgname] = weight_5min_this_server_orgname_by_asn_fraction
                this_server_port = x["payload"]["cflow"]["server_port"]
                weight_5min_this_server_port = client_addr_state["weight_5min_server_port"]\
                    .get(this_server_port, 0) + client_addr_event_weights.get("weight_5min_server_port", 0)
                client_addr_state["weight_5min_server_port"][this_server_port] = weight_5min_this_server_port
                this_server_port_desc = x["payload"]["cflow"]["server_port_desc"]
                weight_5min_this_server_port_desc = client_addr_state["weight_5min_server_port_desc"]\
                    .get(this_server_port_desc, 0) + client_addr_event_weights.get("weight_5min_server_port_desc", 0)
                client_addr_state["weight_5min_server_port_desc"][this_server_port_desc] = weight_5min_this_server_port_desc
                this_server_pfx = x["payload"]["cflow"]["server_pfx"] + " (" + this_server_orgname + ")"
                weight_5min_this_server_pfx = client_addr_state["weight_5min_server_pfx"]\
                    .get(this_server_pfx, 0) + client_addr_event_weights.get("weight_5min_server_pfx", 0)
                client_addr_state["weight_5min_server_pfx"][this_server_pfx] = weight_5min_this_server_pfx
            client_addr_state["client_recent_update"] = datetime.datetime.now().isoformat()

    for (k, v) in client_addr_state.items():
        if k.startswith("weight"):
            keys_to_delete = []
            for (n, c) in v.items():
                if c < 0.01:
                    keys_to_delete.append(n)
            for m in keys_to_delete:
                del v[m]

    client_addr_state["score"] = int(min(sum(
        [
            sum([
                min(vv, 2000/len(vars_in_score)) for (kk, vv) in client_addr_state[v].items()
            ]) for v in vars_in_score
        ]
    ), 999))

    return client_addr_state
        
    
def map_to_client_addr_tuple(x):
    record_type = x["record_type"]
    return (x["payload"][record_type]["client_addr"], x)


def pad_right_to_length(length, value):
    ilength = int(length)
    svalue = str(value)
    return str(svalue.ljust(ilength + 1, " "))[:ilength]
 

def pad_left_to_length(length, value):
    reversed_value = str(value)[::-1]
    reversed_trimmed = pad_right_to_length(length, reversed_value)
    return reversed_trimmed[::-1]


def value_truncate(name, value):
    tr_op_names = {
        "weight_20min_dns_query_name": partial(pad_left_to_length, 45),
        "weight_5min_dns_query_name": partial(pad_left_to_length, 45),
        "weight_20min_dns_query_sld": partial(pad_left_to_length, 25),
        "weight_5min_dns_query_sld": partial(pad_left_to_length, 25),
        "weight_20min_dns_query_sld_by_query_sld_fraction": partial(pad_left_to_length, 25),
        "weight_5min_dns_query_sld_by_query_sld_fraction": partial(pad_left_to_length, 25),
        "weight_5min_server_pfx": partial(pad_right_to_length, 30),
        "weight_5min_server_addr": partial(pad_right_to_length, 20),
        "weight_5min_server_orgname": partial(pad_right_to_length, 40),
        "weight_5min_server_orgname_by_asn_fraction": partial(pad_right_to_length, 40),
        "weight_5min_server_port_desc": partial(pad_right_to_length, 30),
        "client_hostname": partial(pad_right_to_length, 27),
        "score": lambda x: x
    }
    tr_op = tr_op_names.get(name, str)
    return tr_op(value)
    


def format_record(x):
    out = {}
    num_to_show = max([
        min(max(int((len(v)/4)), 10), 25) for (k, v) in x.items()
        if k in vars_in_score
    ])
    for (k, v) in x.items():
        if k.startswith("weight"):
            varlist = [(d, v[d]) for d in sorted(v, key=v.get, reverse=True)]
            varlist_trunc = varlist[0:num_to_show]
            varlist_overflow = varlist[num_to_show:]
            overflow_sum_weight = sum([d[1] for d in varlist_overflow])
            overflow_num = len(varlist_overflow)
            if overflow_num == 1:
                varlist_trunc.append(varlist_overflow[0])
            elif overflow_num > 1:
                varlist_trunc.append(("+" + str(overflow_num) + " others", overflow_sum_weight))
            if show_weights:
                out_temp = "<br>".join(
                    [
                        value_truncate(k, str(int(vv)).zfill(3) + " " + str(kk)).replace(" ", "&nbsp;")
                        for (kk, vv) in varlist_trunc
                    ]
                )
            else:
                out_temp = "<br>".join(
                    [
                        value_truncate(k, str(kk)).replace(" ", "&nbsp;")
                        for (kk, vv) in varlist_trunc
                    ]
                )
            out[k] = out_temp
        elif k != "score":
            out[k] = value_truncate(k, v).replace(" ", "&nbsp;")
        else:
            out[k] = value_truncate(k, v)
    this_timestamp = datetime.datetime.fromisoformat(out["client_recent_update"]).timestamp()
    out["client_recent_update"] = float(this_timestamp)
    return out


def format_client_hostname_dataframe(df):
    if "client_hostname" not in df.columns.values:
        return timezone('US/Pacific').localize(datetime.datetime.utcnow()).ctime() + "<br>" + "Waiting for data"
    ts_now = datetime.datetime.now().timestamp()
    df.set_index("client_hostname", inplace=True)
    df.sort_values(by="score", inplace=True, ascending=False)
    df["score"].astype(str, copy=False)
    del df["weight_5min_record_type"]
    del df["weight_5min_dns_query_name"]
    del df["weight_20min_dns_query_name"]
    del df["weight_5min_dns_query_sld"]
    del df["weight_20min_dns_query_sld"]
    del df["weight_5min_dns_query_sld_by_query_sld_fraction"]
    del df["client_recent_update"]
    del df["weight_5min_server_addr"]
    del df["weight_5min_server_port"]
    del df["weight_5min_server_pfx"]
    del df["weight_5min_server_orgname"]
    return df.to_html(
        header=False,
        justify="left", 
        escape=False, 
        index_names=False, 
        table_id="monitor-table"
    ).replace("\n", "")


def write_dataframe_to_socket(x):
    df = pd.DataFrame.from_dict(
        x.map(lambda r: r[1])
            .map(format_record)
            .collect()
    )
    html = format_client_hostname_dataframe(df)
    fd = os.open("/home/jovyan/STREAM", os.O_RDWR)
    os.set_blocking(fd, os.O_NONBLOCK)
    os.write(fd, bytes(html + "\n", "utf-8"))


def main():
        
    thread_executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)
    background_event_loop = asyncio.new_event_loop()

    record_handle = background_event_loop.run_in_executor(
        thread_executor,
        serve_packets
    )


    spark = SparkSession.builder\
        .appName("Stream Socket")\
        .master("local[*]")\
        .enableHiveSupport()\
        .getOrCreate()

    sc = spark.sparkContext
    ssc = StreamingContext(sc, 1)
    ssc.checkpoint("/tmp/streamsocket")

    packets = ssc.socketTextStream("127.0.0.1", 11111)\
        .flatMap(parse_record)\
        .filter(filter_record)\
        .map(lambda x: ("", x))\
        .updateStateByKey(update_univeral_state)\
        .flatMap(lambda x: x[1]["records"])

    packets_client_addr = packets.map(map_to_client_addr_tuple)\
        .updateStateByKey(update_client_addr)\
        .filter(lambda x: sum([x[1]["weight_5min_record_type"].get(t, 0) for t in ["dns", "cflow"]]) > 0)

    os.mkfifo("/home/jovyan/STREAM")
    packets_client_addr.foreachRDD(write_dataframe_to_socket)

    ssc.start()

    readers = set()

    async def broadcast(websocket, path):
        readers.add(websocket)
        try:
            fd = os.open("/home/jovyan/STREAM", os.O_RDONLY)
            os.set_blocking(fd, os.O_NONBLOCK)
            with open(fd, "rb", closefd=False) as f:
                while True:
                    message = f.readline()
                    await asyncio.wait([r.send(message.decode("utf-8")) for r in readers])
        finally:
            readers.remove(websocket)


    start_server = websockets.serve(broadcast, "0.0.0.0", 9080)

    asyncio.get_event_loop().run_until_complete(start_server)
    asyncio.get_event_loop().run_forever()


if __name__ == "__main__":
    main()
