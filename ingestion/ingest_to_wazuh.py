import pandas as pd
import socket
import json
import time
import os
from datetime import datetime

WAZUH_HOST = '127.0.0.1'
WAZUH_PORT = 514
DATASET = os.path.join(os.path.dirname(__file__), '../datasets/ics_train.csv')

def send_to_wazuh(message: str):
    """Send syslog UDP message to Wazuh"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message.encode('utf-8'), (WAZUH_HOST, WAZUH_PORT))
        sock.close()
    except Exception as e:
        print(f"[ERROR] Failed to send: {e}")

def build_syslog(row):
    """Convert a dataset row into a structured syslog message Wazuh can parse"""
    timestamp = datetime.now().strftime('%b %d %H:%M:%S')
    hostname = 'tangedco-scada-01'
    
    event = {
        'ics_timestamp': row['DATETIME'],
        'src_device': hostname,
        'L_T1': row['L_T1'],
        'L_T2': row['L_T2'],
        'L_T3': row['L_T3'],
        'F_PU1': row['F_PU1'],
        'S_PU1': int(row['S_PU1']),
        'F_PU2': row['F_PU2'],
        'S_PU2': int(row['S_PU2']),
        'P_J1': row['P_J1'],
        'P_J2': row['P_J2'],
        'P_J3': row['P_J3'],
        'att_flag': int(row['ATT_FLAG']),
        'att_type': row['ATT_TYPE']
    }
    
    syslog_msg = f"<134>{timestamp} {hostname} ICS_EVENT: {json.dumps(event)}"
    return syslog_msg

def run_ingestion(speed=0.05):
    df = pd.read_csv(DATASET)
    print(f"[*] Loaded {len(df)} events from dataset")
    print(f"[*] Sending to Wazuh at {WAZUH_HOST}:{WAZUH_PORT}")
    print(f"[*] Speed: {1/speed:.0f} events/sec\n")
    
    alerts_sent = 0
    for _, row in df.iterrows():
        msg = build_syslog(row)
        send_to_wazuh(msg)
        
        if row['ATT_FLAG'] == 1:
            alerts_sent += 1
            print(f"[ATTACK] {row['DATETIME']} | {row['ATT_TYPE']} | "
                  f"PU1={row['S_PU1']} PU2={row['S_PU2']} "
                  f"T1={row['L_T1']} P1={row['P_J1']}")
        
        time.sleep(speed)
    
    print(f"\n[+] Done. {len(df)} events sent, {alerts_sent} attack events.")

if __name__ == '__main__':
    run_ingestion()
