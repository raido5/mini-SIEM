from datetime import datetime
import re 
import csv

ssh_motif = r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) server sshd\[\d+\]: (\w+) password for (\w+) from ([\d.]+)"
http_motif = r'^(\d+\.\d+\.\d+\.\d+) - - \[([^\]]+)\] "(\w+) ([^ ]+) ([^"]+)" (\d{3}) (\d+)'


def convert_http_timestamp(raw):
    raw = raw.split(" ")[0]                             
    dt = datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S")    
    return dt.strftime("%Y-%m-%d %H:%M:%S")            

def parse_ssh_line(line):
    result=re.search(ssh_motif,line)
    if not result:
        return None
    status="success" if result.group(2) =="Accepted" else "failed"
    return{
        "timestamp": result.group(1),
        "source":"ssh",
        "ip":result.group(4),
        "event_type":"login",
        "user":result.group(3),
        "path": None,
        "status": status,
        "status_code": None,
        "label": None,
    }

def parse_ssh_file(filepath):
    events=[]
    with open(filepath,"r",encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line:
                continue
            event=parse_ssh_line(line)
            if event is None:
                continue
            events.append(event)
    return events

def parse_http_line(line):
    result=re.search(http_motif,line)
    if not result:
        return None
    status_code = int(result.group(6))
    status = "success" if 200 <= status_code < 400 else "failed"
    return {
        "timestamp": convert_http_timestamp(result.group(2)),
        "source":"http",
        "ip":result.group(1),
        "event_type":"request",
        "user":None,
        "path":result.group(4),
        "status":status,
        "status_code":status_code,
        "label":None,     
    }

def parse_http_file(filepath):
    events = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            event = parse_http_line(line)
            if event is None:
                continue
            events.append(event)
    return events


COLONNES = ["timestamp", "source", "ip", "event_type", "user", "path", "status", "status_code", "label"]


def write_csv(events,output_path):
    with open(output_path,"w",newline="",encoding="utf-8") as f:
        writer=csv.DictWriter(f,fieldnames=COLONNES,restval="")
        writer.writeheader()
        for event in events:
            writer.writerow(event)


if __name__=="__main__":
    events_ssh = parse_ssh_file("data/raw/ssh/sample_auth.log")
    events_http = parse_http_file("data/raw/http/sample_acces.log")
    all_events= events_ssh+events_http
    write_csv(all_events, "data/interim/parsed_events.csv")

