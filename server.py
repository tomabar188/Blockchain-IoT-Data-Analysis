from flask import Flask, jsonify, request, render_template_string, redirect, url_for
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib
import numpy as np
import pandas as pd
from web3 import Web3


model = joblib.load('random_forest_model.pkl')



app = Flask(__name__)


w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))
contract_address = '0x1b925C4b23bB9aA490E0E3d931104404500BD3D7'  
contract_abi = [
{
      "inputs": [
        {
          "internalType": "string",
          "name": "_message",
          "type": "string"
        }
      ],
      "stateMutability": "nonpayable",
      "type": "constructor"
    },
    {
      "anonymous": False,
      "inputs": [
        {
          "indexed": True,
          "internalType": "address",
          "name": "device",
          "type": "address"
        },
        {
          "indexed": False,
          "internalType": "string",
          "name": "threat_type",
          "type": "string"
        },
        {
          "indexed": False,
          "internalType": "string",
          "name": "timestamp",
          "type": "string"
        }
      ],
      "name": "ThreatRecorded",
      "type": "event"
    },
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "name": "allDevices",
      "outputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": True
    },
    {
      "inputs": [],
      "name": "message",
      "outputs": [
        {
          "internalType": "string",
          "name": "",
          "type": "string"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": True
    },
    {
      "inputs": [
        {
          "internalType": "address",
          "name": "",
          "type": "address"
        },
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "name": "threats",
      "outputs": [
        {
          "components": [
            {
              "internalType": "string",
              "name": "device_id",
              "type": "string"
            },
            {
              "internalType": "string",
              "name": "threat_type",
              "type": "string"
            },
            {
              "internalType": "string",
              "name": "timestamp",
              "type": "string"
            },
            {
              "internalType": "uint256",
              "name": "duration",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "orig_bytes",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "resp_bytes",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "missed_bytes",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "orig_h_encoded",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "orig_pkts",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "orig_ip_bytes",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "resp_pkts",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "resp_ip_bytes",
              "type": "uint256"
            },
            {
              "internalType": "uint8",
              "name": "proto_icmp",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "proto_tcp",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "proto_udp",
              "type": "uint8"
            }
          ],
          "internalType": "struct MyContract.ThreatData",
          "name": "data",
          "type": "tuple"
        },
        {
          "components": [
            {
              "internalType": "uint8",
              "name": "OTH",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "REJ",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "RSTO",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "RSTOS0",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "RSTR",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "RSTRH",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "S0",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "S1",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "S2",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "S3",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "SF",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "SH",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "SHR",
              "type": "uint8"
            }
          ],
          "internalType": "struct MyContract.ConnState",
          "name": "conn_state",
          "type": "tuple"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": True
    },
    {
      "inputs": [
        {
          "internalType": "string",
          "name": "_message",
          "type": "string"
        }
      ],
      "name": "setMessage",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [
        {
          "components": [
            {
              "internalType": "string",
              "name": "device_id",
              "type": "string"
            },
            {
              "internalType": "string",
              "name": "threat_type",
              "type": "string"
            },
            {
              "internalType": "string",
              "name": "timestamp",
              "type": "string"
            },
            {
              "internalType": "uint256",
              "name": "duration",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "orig_bytes",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "resp_bytes",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "missed_bytes",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "orig_h_encoded",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "orig_pkts",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "orig_ip_bytes",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "resp_pkts",
              "type": "uint256"
            },
            {
              "internalType": "uint256",
              "name": "resp_ip_bytes",
              "type": "uint256"
            },
            {
              "internalType": "uint8",
              "name": "proto_icmp",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "proto_tcp",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "proto_udp",
              "type": "uint8"
            }
          ],
          "internalType": "struct MyContract.ThreatData",
          "name": "_data",
          "type": "tuple"
        },
        {
          "components": [
            {
              "internalType": "uint8",
              "name": "OTH",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "REJ",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "RSTO",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "RSTOS0",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "RSTR",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "RSTRH",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "S0",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "S1",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "S2",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "S3",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "SF",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "SH",
              "type": "uint8"
            },
            {
              "internalType": "uint8",
              "name": "SHR",
              "type": "uint8"
            }
          ],
          "internalType": "struct MyContract.ConnState",
          "name": "_conn_state",
          "type": "tuple"
        }
      ],
      "name": "recordThreat",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "getAllThreats",
      "outputs": [
        {
          "components": [
            {
              "components": [
                {
                  "internalType": "string",
                  "name": "device_id",
                  "type": "string"
                },
                {
                  "internalType": "string",
                  "name": "threat_type",
                  "type": "string"
                },
                {
                  "internalType": "string",
                  "name": "timestamp",
                  "type": "string"
                },
                {
                  "internalType": "uint256",
                  "name": "duration",
                  "type": "uint256"
                },
                {
                  "internalType": "uint256",
                  "name": "orig_bytes",
                  "type": "uint256"
                },
                {
                  "internalType": "uint256",
                  "name": "resp_bytes",
                  "type": "uint256"
                },
                {
                  "internalType": "uint256",
                  "name": "missed_bytes",
                  "type": "uint256"
                },
                {
                  "internalType": "uint256",
                  "name": "orig_h_encoded",
                  "type": "uint256"
                },
                {
                  "internalType": "uint256",
                  "name": "orig_pkts",
                  "type": "uint256"
                },
                {
                  "internalType": "uint256",
                  "name": "orig_ip_bytes",
                  "type": "uint256"
                },
                {
                  "internalType": "uint256",
                  "name": "resp_pkts",
                  "type": "uint256"
                },
                {
                  "internalType": "uint256",
                  "name": "resp_ip_bytes",
                  "type": "uint256"
                },
                {
                  "internalType": "uint8",
                  "name": "proto_icmp",
                  "type": "uint8"
                },
                {
                  "internalType": "uint8",
                  "name": "proto_tcp",
                  "type": "uint8"
                },
                {
                  "internalType": "uint8",
                  "name": "proto_udp",
                  "type": "uint8"
                }
              ],
              "internalType": "struct MyContract.ThreatData",
              "name": "data",
              "type": "tuple"
            },
            {
              "components": [
                {
                  "internalType": "uint8",
                  "name": "OTH",
                  "type": "uint8"
                },
                {
                  "internalType": "uint8",
                  "name": "REJ",
                  "type": "uint8"
                },
                {
                  "internalType": "uint8",
                  "name": "RSTO",
                  "type": "uint8"
                },
                {
                  "internalType": "uint8",
                  "name": "RSTOS0",
                  "type": "uint8"
                },
                {
                  "internalType": "uint8",
                  "name": "RSTR",
                  "type": "uint8"
                },
                {
                  "internalType": "uint8",
                  "name": "RSTRH",
                  "type": "uint8"
                },
                {
                  "internalType": "uint8",
                  "name": "S0",
                  "type": "uint8"
                },
                {
                  "internalType": "uint8",
                  "name": "S1",
                  "type": "uint8"
                },
                {
                  "internalType": "uint8",
                  "name": "S2",
                  "type": "uint8"
                },
                {
                  "internalType": "uint8",
                  "name": "S3",
                  "type": "uint8"
                },
                {
                  "internalType": "uint8",
                  "name": "SF",
                  "type": "uint8"
                },
                {
                  "internalType": "uint8",
                  "name": "SH",
                  "type": "uint8"
                },
                {
                  "internalType": "uint8",
                  "name": "SHR",
                  "type": "uint8"
                }
              ],
              "internalType": "struct MyContract.ConnState",
              "name": "conn_state",
              "type": "tuple"
            }
          ],
          "internalType": "struct MyContract.Threat[]",
          "name": "",
          "type": "tuple[]"
        }
      ],
      "stateMutability": "view",
      "type": "function",
      "constant": True
    }]  
contract = w3.eth.contract(address=contract_address, abi=contract_abi)


le_orig_h = LabelEncoder()
le_label = LabelEncoder()
le_orig_h.classes_ = joblib.load('le_orig_h.pkl')
le_label.classes_ = joblib.load('le_label.pkl')


pending_threats = []

def update_label_encoder(le, new_labels):
    
    current_classes = set(le.classes_)
    new_classes = set(new_labels) - current_classes

    if new_classes:
        
        le.classes_ = np.append(le.classes_, list(new_classes))
        le.classes_ = np.sort(le.classes_)  


def prepare_data_for_training(threats_list):
    
    df = pd.DataFrame(threats_list)
    
    print("le_orig_h classes:", le_orig_h.classes_)
    print("le_orig_h data type:", type(le_orig_h.classes_[0]))

    print("le_label classes:", le_label.classes_)
    print("le_label data type:", type(le_label.classes_[0]))
    
    update_label_encoder(le_orig_h, df['device_id'])
    update_label_encoder(le_label, df['threat_type'])
        
      
    
    df['orig_h_encoded'] = le_orig_h.transform(df['device_id'])  
    
    df['label_encoded'] = le_label.transform(df['threat_type'])  
    print(f"{df['label_encoded']}")
    
    
    X = df[['orig_h_encoded', 'duration', 'orig_bytes', 'resp_bytes', 'missed_bytes',
            'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
            'proto_icmp', 'proto_tcp', 'proto_udp',
            'conn_state_OTH', 'conn_state_REJ', 'conn_state_RSTO', 'conn_state_RSTOS0',
            'conn_state_RSTR', 'conn_state_RSTRH', 'conn_state_S0', 'conn_state_S1',
            'conn_state_S2', 'conn_state_S3', 'conn_state_SF', 'conn_state_SH', 'conn_state_SHR']]
    
    
    y = df['label_encoded']
    if len(y.shape) == 1:
        print("Kształt y jest poprawny:", y.shape)
    else:
        print("Kształt y nie jest jednowymiarowy, aktualny kształt:", y.shape)
    return X, y

def retrain_model_on_blockchain_data(X, y):
    
    original_data = pd.read_csv('iot23_combined.csv', sep=',')
    original_data['orig_h_encoded'] = le_orig_h.transform(original_data['id.orig_h'])
    original_data['label_encoded'] = le_label.transform(original_data['label'])

    
    X_original = original_data[['orig_h_encoded', 'duration', 'orig_bytes', 'resp_bytes', 'missed_bytes',
                                'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
                                'proto_icmp', 'proto_tcp', 'proto_udp',
                                'conn_state_OTH', 'conn_state_REJ', 'conn_state_RSTO', 'conn_state_RSTOS0',
                                'conn_state_RSTR', 'conn_state_RSTRH', 'conn_state_S0', 'conn_state_S1',
                                'conn_state_S2', 'conn_state_S3', 'conn_state_SF', 'conn_state_SH', 'conn_state_SHR']]
    y_original = original_data['label_encoded']
    
    X_combined = pd.concat([X_original, X], axis=0)
    y_combined = pd.concat([y_original, y], axis=0)
    
    X_train, X_test, y_train, y_test = train_test_split(X_combined, y_combined, test_size=0.3, random_state=42)
    
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    print("MODEL TRAINED")
    y_pred = model.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print(classification_report(y_test, y_pred))
    joblib.dump(model, 'random_forest_model.pkl')
    model = joblib.load('random_forest_model.pkl')


def retrain_on_blockchain():
    try:
        threats = contract.functions.getAllThreats().call()
        
        threats_list = []
        threat_type_mapping = {
                '0': '-   Benign   -',
                '1': 'Attack',
                '2': 'Benign',
                '3': 'C&C',
                '4': 'C&C-FileDownload',
                '5': 'C&C-HeartBeat',
                '6': 'C&C-HeartBeat-FileDownload',
                '7': 'C&C-Mirai',
                '8': 'C&C-Torii',
                '9': 'DDoS',
                '10': 'FileDownload',
                '11': 'Okiru',
                '12': 'PartOfAHorizontalPortScan'
            }
        for threat in threats:
            threat_data = threat[0]  
            conn_state = threat[1]  
            mapped_threat_type = threat_type_mapping.get(threat_data[1], 'Unknown')
            threats_list.append({
                'device_id': threat_data[0],
                'threat_type': mapped_threat_type,
                'timestamp': threat_data[2],
                'duration': threat_data[3],
                'orig_bytes': threat_data[4],
                'resp_bytes': threat_data[5],
                'missed_bytes': threat_data[6],
                'orig_pkts': threat_data[7],
                'orig_ip_bytes': threat_data[8],
                'resp_pkts': threat_data[9],
                'resp_ip_bytes': threat_data[10],
                'proto_icmp': threat_data[11],
                'proto_tcp': threat_data[12],
                'proto_udp': threat_data[13],
                'conn_state_OTH': conn_state[0],
                'conn_state_REJ': conn_state[1],
                'conn_state_RSTO': conn_state[2],
                'conn_state_RSTOS0': conn_state[3],
                'conn_state_RSTR': conn_state[4],
                'conn_state_RSTRH': conn_state[5],
                'conn_state_S0': conn_state[6],
                'conn_state_S1': conn_state[7],
                'conn_state_S2': conn_state[8],
                'conn_state_S3': conn_state[9],
                'conn_state_SF': conn_state[10],
                'conn_state_SH': conn_state[11],
                'conn_state_SHR': conn_state[12]
            })
           

        
        X, y = prepare_data_for_training(threats_list)

        
        retrain_model_on_blockchain_data(X, y)

        return jsonify({'status': 'Model retrained successfully on blockchain data'}), 200

    except Exception as e:
        return jsonify({'error': 'Błąd podczas pobierania danych z blockchaina lub trenowania modelu', 'details': str(e)}), 500


@app.route('/all')
def get_all_threats():
    try:
        
        threats = contract.functions.getAllThreats().call()

        
        threats_list = []
        for threat in threats:
            threat_data = threat[0]  
            conn_state = threat[1]  

            threats_list.append({
                'device_id': threat_data[0],
                'threat_type': threat_data[1],
                'timestamp': threat_data[2],
                'duration': threat_data[3],
                'orig_bytes': threat_data[4],
                'resp_bytes': threat_data[5],
                'missed_bytes': threat_data[6],
                'orig_pkts': threat_data[7],
                'orig_ip_bytes': threat_data[8],
                'resp_pkts': threat_data[9],
                'resp_ip_bytes': threat_data[10],
                'proto_icmp': threat_data[11],
                'proto_tcp': threat_data[12],
                'proto_udp': threat_data[13],
                'conn_state': {
                    'OTH': conn_state[0],
                    'REJ': conn_state[1],
                    'RSTO': conn_state[2],
                    'RSTOS0': conn_state[3],
                    'RSTR': conn_state[4],
                    'RSTRH': conn_state[5],
                    'S0': conn_state[6],
                    'S1': conn_state[7],
                    'S2': conn_state[8],
                    'S3': conn_state[9],
                    'SF': conn_state[10],
                    'SH': conn_state[11],
                    'SHR': conn_state[12]
                }
            })

        
        html = render_template_string("""
        <h1>Wszystkie zagrożenia zapisane w systemie</h1>
        <ul>
        {% for threat in threats %}
            <li>
                <strong>Device ID:</strong> {{ threat.device_id }}<br>
                <strong>Threat Type:</strong> {{ threat.threat_type }}<br>
                <strong>Timestamp:</strong> {{ threat.timestamp }}<br>
                <strong>Duration:</strong> {{ threat.duration }}<br>
                <strong>Orig Bytes:</strong> {{ threat.orig_bytes }}<br>
                <strong>Resp Bytes:</strong> {{ threat.resp_bytes }}<br>
                <strong>Missed Bytes:</strong> {{ threat.missed_bytes }}<br>
                <strong>Orig Packets:</strong> {{ threat.orig_pkts }}<br>
                <strong>Orig IP Bytes:</strong> {{ threat.orig_ip_bytes }}<br>
                <strong>Resp Packets:</strong> {{ threat.resp_pkts }}<br>
                <strong>Resp IP Bytes:</strong> {{ threat.resp_ip_bytes }}<br>
                <strong>Proto ICMP:</strong> {{ threat.proto_icmp }}<br>
                <strong>Proto TCP:</strong> {{ threat.proto_tcp }}<br>
                <strong>Proto UDP:</strong> {{ threat.proto_udp }}<br>
                <strong>Conn State:</strong> {{ threat.conn_state }}<br>
            </li>
        {% endfor %}
        </ul>
        """, threats=threats_list)

        return html

    except Exception as e:
        return jsonify({'error': 'Błąd podczas pobierania wszystkich danych', 'details': str(e)}), 500

@app.route('/review', methods=['GET', 'POST'])
def review_threats():
    global pending_threats
    if request.method == 'POST':
        decision = request.form.get('decision')
        index = int(request.form.get('index'))
        if decision == 'accept':
            try:
                tx_hash = contract.functions.recordThreat(
                    pending_threats[index]['threat_data'],
                    pending_threats[index]['conn_state_blockchain']
                ).transact({'from': w3.eth.accounts[0]})
                w3.eth.wait_for_transaction_receipt(tx_hash)
                
                retrain_on_blockchain()
                
            except Exception as e:
                return jsonify({'error': 'Błąd podczas zapisu do blockchaina', 'details': str(e)}), 500
            pending_threats.pop(index)
            return redirect(url_for('review_threats'))
        elif decision == 'reject':
            pending_threats.pop(index)
            return redirect(url_for('review_threats'))

    if pending_threats:
        return render_template_string("""
        <h1>Review Threats</h1>
        {% for i in range(threats|length) %}
            <div>
                <h3>Threat {{ i+1 }}</h3>
                <p>Device ID: {{ threats[i]['threat_data']['device_id'] }}</p>
                <p>Threat Type: {{ threats[i]['threat_data']['threat_type'] }}</p>
                <p>Timestamp: {{ threats[i]['threat_data']['timestamp'] }}</p>
                <p>Duration: {{ threats[i]['threat_data']['duration'] }}</p>
                <p>Orig Bytes: {{ threats[i]['threat_data']['orig_bytes'] }}</p>
                <p>Resp Bytes: {{ threats[i]['threat_data']['resp_bytes'] }}</p>
                <p>Missed Bytes: {{ threats[i]['threat_data']['missed_bytes'] }}</p>
                <p>Orig Packets: {{ threats[i]['threat_data']['orig_pkts'] }}</p>
                <p>Orig IP Bytes: {{ threats[i]['threat_data']['orig_ip_bytes'] }}</p>
                <p>Resp Packets: {{ threats[i]['threat_data']['resp_pkts'] }}</p>
                <p>Resp IP Bytes: {{ threats[i]['threat_data']['resp_ip_bytes'] }}</p>
                <form method="POST">
                    <input type="hidden" name="index" value="{{ i }}">
                    <button type="submit" name="decision" value="accept">Accept</button>
                    <button type="submit" name="decision" value="reject">Reject</button>
                </form>
            </div>
            <hr>
        {% endfor %}
        """, threats=pending_threats)
    else:
        return "<h1>Review Threats</h1><p>No pending threats to review.</p>"


@app.route('/predict', methods=['POST'])
def predict():
    global pending_threats
    try:
        data = request.json
        features = pd.DataFrame([data]).drop(columns=['device_id'])

        prediction = model.predict(features)[0]

        if prediction in [1, 3, 4, 5, 6, 7, 8, 9, 11, 12]:
            threat = {
                'threat_data': {
                    'device_id': str(data.get('device_id')),
                    'threat_type': str(prediction),
                    'timestamp': pd.Timestamp.now().isoformat(),
                    'duration': int(data.get('duration', 0) * 1000),
                    'orig_bytes': int(data.get('orig_bytes', 0)),
                    'resp_bytes': int(data.get('resp_bytes', 0)),
                    'missed_bytes': int(data.get('missed_bytes', 0)),
                    'orig_h_encoded': int(data.get('orig_h_encoded', 0)),
                    'orig_pkts': int(data.get('orig_pkts', 0)),
                    'orig_ip_bytes': int(data.get('orig_ip_bytes', 0)),
                    'resp_pkts': int(data.get('resp_pkts', 0)),
                    'resp_ip_bytes': int(data.get('resp_ip_bytes', 0)),
                    'proto_icmp': int(data.get('proto_icmp', 0)),
                    'proto_tcp': int(data.get('proto_tcp', 0)),
                    'proto_udp': int(data.get('proto_udp', 0)),
                },
                'conn_state_blockchain': {
                    "OTH": data.get('conn_state_OTH', 0),
                    'REJ': data.get('conn_state_REJ', 0),
                    'RSTO': data.get('conn_state_RSTO', 0),
                    'RSTOS0': data.get('conn_state_RSTOS0', 0),
                    'RSTR': data.get('conn_state_RSTR', 0),
                    'RSTRH': data.get('conn_state_RSTRH', 0),
                    'S0': data.get('conn_state_S0', 0),
                    'S1': data.get('conn_state_S1', 0),
                    'S2': data.get('conn_state_S2', 0),
                    'S3': data.get('conn_state_S3', 0),
                    'SF': data.get('conn_state_SF', 0),
                    'SH': data.get('conn_state_SH', 0),
                    'SHR': data.get('conn_state_SHR', 0)
                }
            }
            pending_threats.append(threat)
            print("NOWY")    
        return jsonify({'status': 'Packet recorded'})
        

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)