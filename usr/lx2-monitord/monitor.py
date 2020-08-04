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
import ipaddress
import functools
import numpy as np
import pandas as pd
import time
import queue
import radix

import IPython.display
from IPython.display import HTML
import ipywidgets as widgets

import pyspark
from pyspark import SparkContext
from pyspark.streaming import StreamingContext
from pyspark.sql import Row, SparkSession
from pyspark.sql.types import *
import pyspark.sql.functions as func

            

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

    def _update_hostnames(self):
        with open("/home/jovyan/work/lx2-hosts", "r") as f:
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
                        self._asn_info.search_best(srcaddr).data["data"]
                        for srcaddr in x["layers"]["cflow"]["text_cflow_srcaddr"]
                    ]
                else:
                    src_as_info = self._asn_info.search_best(
                        x["layers"]["cflow"]["text_cflow_srcaddr"]
                    ).data["data"]
                x["layers"]["cflow"].update({"src_as_info": src_as_info})
            if "text_cflow_dstaddr" in x["layers"]["cflow"]:
                if type(x["layers"]["cflow"]["text_cflow_dstaddr"]) is list:
                    dst_as_info = [
                        self._asn_info.search_best(dstaddr).data["data"]
                        for dstaddr in x["layers"]["cflow"]["text_cflow_dstaddr"]
                    ]
                else:
                    dst_as_info = self._asn_info.search_best(
                        x["layers"]["cflow"]["text_cflow_dstaddr"]
                    ).data["data"]
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


def extract_dns_payload(dns_record, ip_record):
    client_addr = ip_record["ip_ip_dst"]
    dns_query_name = dns_record["text_dns_qry_name"]
    dns_resp_types = dns_record["text_dns_resp_type"]
    dns_rcode = dns_record["dns_flags_dns_flags_rcode"]
    dns_payload = {
        "client_addr": client_addr,
        "dns_query_name": dns_query_name,
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


def update_client_addr(part, client_addr_state):
    
    now = datetime.datetime.now()
    
    if client_addr_state != None:
        recent_update = datetime.datetime.fromisoformat(client_addr_state["client_recent_update"])
        delta_seconds_recent = (now - recent_update).total_seconds()
        for (k, v) in client_addr_state.items():
            if k.startswith("counts"):
                for (n, c) in v.items():
                    client_addr_state[k][n] = c - 0.3*c*(1 - np.exp(-delta_seconds_recent/300))
                    
    if client_addr_state is None:
        client_addr_state = {
            "client_recent_update": now.isoformat(),
            "client_hostname": "",
            "counts_record_type": {},
            "counts_dns_query_name": {},
            "counts_server_pfx": {},
            "counts_server_addr": {},
            "counts_server_port": {},
            "counts_server_orgname": {},
            "counts_server_port_desc": {}
        }    
        
    for x in part:
            
        this_record_type = x["record_type"]
        counts_this_record_type = client_addr_state["counts_record_type"]\
            .get(this_record_type, 0) + 1
        client_addr_state["counts_record_type"][this_record_type] = counts_this_record_type
        if x["record_type"] == "hostname_map":
            client_addr_state["client_hostname"] = x["payload"]["hostname_map"]["client_hostname"]
        elif x["record_type"] == "dns":
            this_dns_query_name = x["payload"]["dns"]["dns_query_name"]
            counts_this_dns_query_name = client_addr_state["counts_dns_query_name"]\
                .get(this_dns_query_name, 0) + 2
            client_addr_state["counts_dns_query_name"][this_dns_query_name] = counts_this_dns_query_name
            client_addr_state["client_recent_update"] = datetime.datetime.now().isoformat()
        elif x["record_type"] == "cflow":
            this_server_addr = x["payload"]["cflow"]["server_addr"]
            counts_this_server_addr = client_addr_state["counts_server_addr"]\
                .get(this_server_addr, 0) + 1
            client_addr_state["counts_server_addr"][this_server_addr] = counts_this_server_addr  
            this_server_orgname = x["payload"]["cflow"]["server_orgname"]
            counts_this_server_orgname = client_addr_state["counts_server_orgname"]\
                .get(this_server_orgname, 0) + 1
            client_addr_state["counts_server_orgname"][this_server_orgname] = counts_this_server_orgname        
            this_server_port = x["payload"]["cflow"]["server_port"]
            counts_this_server_port = client_addr_state["counts_server_port"]\
                .get(this_server_port, 0) + 1
            client_addr_state["counts_server_port"][this_server_port] = counts_this_server_port
            this_server_port_desc = x["payload"]["cflow"]["server_port_desc"]
            counts_this_server_port_desc = client_addr_state["counts_server_port_desc"]\
                .get(this_server_port_desc, 0) + 1
            client_addr_state["counts_server_port_desc"][this_server_port_desc] = counts_this_server_port_desc
            this_server_pfx = x["payload"]["cflow"]["server_pfx"]
            counts_this_server_pfx = client_addr_state["counts_server_pfx"]\
                .get(this_server_pfx, 0) + 1
            client_addr_state["counts_server_pfx"][this_server_pfx] = counts_this_server_pfx
            client_addr_state["client_recent_update"] = datetime.datetime.now().isoformat()

    for (k, v) in client_addr_state.items():
        if k.startswith("counts"):
            keys_to_delete = []
            for (n, c) in v.items():
                if c < 0.8:
                    keys_to_delete.append(n)
            for m in keys_to_delete:
                del v[m]
        
    return client_addr_state
        
    
def map_to_client_addr_tuple(x):
    record_type = x["record_type"]
    return (x["payload"][record_type]["client_addr"], x)


def format_record(x):
    out = {}
    for (k, v) in x.items():
        if k.startswith("counts"):
            out[k] = "<br>".join([str(d) for d in sorted(v, key=v.get, reverse=True)])
        else:
            out[k] = v
    this_timestamp = datetime.datetime.fromisoformat(out["client_recent_update"]).timestamp()
    out["client_recent_update"] = float(this_timestamp)
    return out


def format_client_hostname_dataframe(df):
    if "client_hostname" not in df.columns.values:
        return "Waiting for data--current time is " + datetime.datetime.now().isoformat()
    ts_now = datetime.datetime.now().timestamp()
    ts_5min_ago = ts_now - 300
    df = df[df["client_recent_update"] > ts_5min_ago]
    df.set_index("client_hostname", inplace=True)
    df.sort_values(by="client_hostname", inplace=True)
    del df["counts_record_type"]
    del df["client_recent_update"]
    del df["counts_server_addr"]
    del df["counts_server_port"]
    return df.to_html(escape=False).replace("\n", "")


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
#    posix.close(fd)


def main():
        
    thread_executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)
    background_event_loop = asyncio.new_event_loop()

    record_handle = background_event_loop.run_in_executor(
        thread_executor,
        serve_packets
    )


    spark = SparkSession.builder\
        .appName("Stream Socket")\
        .master("local[2]")\
        .enableHiveSupport()\
        .getOrCreate()

    sc = spark.sparkContext
    ssc = StreamingContext(sc, 1)
    ssc.checkpoint("/tmp/streamsocket")

    packets = ssc.socketTextStream("127.0.0.1", 11111)\
        .flatMap(parse_record)\
        .filter(filter_record)

    packets_client_addr = packets.map(map_to_client_addr_tuple)\
        .updateStateByKey(update_client_addr)\
        .filter(lambda x: sum([x[1]["counts_record_type"].get(t, 0) for t in ["dns", "cflow"]]) > 0)

    os.mkfifo("/home/jovyan/STREAM")
    packets_client_addr.foreachRDD(write_dataframe_to_socket)

    ssc.start()

    readers = set()

    async def broadcast(websocket, path):
        readers.add(websocket)
        try:
            await websocket.send("1\n")
            fd = os.open("/home/jovyan/STREAM", os.O_RDONLY)
            await websocket.send("2\n")
            os.set_blocking(fd, os.O_NONBLOCK)
            await websocket.send("3\n")
            with open(fd, "rb", closefd=False) as f:
                await websocket.send("4\n")
                while True:
                    await websocket.send("5\n")
                    message = f.readline()
                    await websocket.send("6\n")
                    await asyncio.wait([w.send(message.decode("utf-8")) for w in readers])
        finally:
            readers.remove(websocket)


    start_server = websockets.serve(broadcast, "0.0.0.0", 9080)

    asyncio.get_event_loop().run_until_complete(start_server)
    asyncio.get_event_loop().run_forever()


if __name__ == "__main__":
    main()
