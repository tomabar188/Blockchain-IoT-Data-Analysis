import pandas as pd
import numpy as np
import random
import string
import time
import requests


def generate_uid():
    return random.randint(1352, 1366)


def generate_conn_state():
    states = ['OTH', 'REJ', 'RSTO', 'RSTOS0', 'RSTR', 'RSTRH', 'S0', 'S1', 'S2', 'S3', 'SF', 'SH', 'SHR']
    return random.choice(states)


flask_server_url = "http://127.0.0.1:5000/predict"


while True:
    conn_state = generate_conn_state()
    
    data = {
        'orig_h_encoded': random.randint(1, 255),
        'duration': round(np.random.uniform(-1.0, 78840.329305), 6),  
        'orig_bytes': random.randint(-1, 1744830458),
        'resp_bytes': random.randint(-1, 336516351),
        'missed_bytes': round(np.random.uniform(0.0, 20272.0), 6),
        'orig_pkts': round(np.random.uniform(0.0, 66027354.0), 6),
        'orig_ip_bytes': round(np.random.uniform(0.0, 1914793266.0), 6),
        'resp_pkts': round(np.random.uniform(0.0, 239484.0), 6),
        'resp_ip_bytes': round(np.random.uniform(0.0, 349618679.0), 6),
        'proto_icmp': random.randint(0, 1),
        'proto_tcp': random.randint(0, 1),
        'proto_udp': random.randint(0, 1),
        'conn_state_OTH': 1 if conn_state == 'OTH' else 0,
        'conn_state_REJ': 1 if conn_state == 'REJ' else 0,
        'conn_state_RSTO': 1 if conn_state == 'RSTO' else 0,
        'conn_state_RSTOS0': 1 if conn_state == 'RSTOS0' else 0,
        'conn_state_RSTR': 1 if conn_state == 'RSTR' else 0,
        'conn_state_RSTRH': 1 if conn_state == 'RSTRH' else 0,
        'conn_state_S0': 1 if conn_state == 'S0' else 0,
        'conn_state_S1': 1 if conn_state == 'S1' else 0,
        'conn_state_S2': 1 if conn_state == 'S2' else 0,
        'conn_state_S3': 1 if conn_state == 'S3' else 0,
        'conn_state_SF': 1 if conn_state == 'SF' else 0,
        'conn_state_SH': 1 if conn_state == 'SH' else 0,
        'conn_state_SHR': 1 if conn_state == 'SHR' else 0,
        'device_id': generate_uid()  
    }

    
    response = requests.post(flask_server_url, json=data)
    
    if response.status_code == 200:
        print(f"Serwer Flask przetworzył dane: {response.json()}")
    else:
        print(f"Błąd podczas wysyłania danych: {response.status_code}")

   
    time.sleep(0.7)
