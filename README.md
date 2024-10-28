# Blockchain IoT Data Analysis

## Project Description
This project analyzes data from IoT devices using a machine learning model and logs detected threats in a blockchain smart contract. The classification model examines various properties of IoT network traffic and detects potential threats.

## Repository Contents

- **dataGenerator.py** - Generates simulated IoT network traffic data and sends it to the Flask server for analysis.
- **new.py** - Script for training a RandomForest model to analyze IoT data and save the model along with label encodings.
- **server.py** - A Flask server that loads the model, analyzes incoming data, and logs threats to a blockchain smart contract.
- **MyContract.sol** - Solidity smart contract code for storing IoT network threat information on the blockchain.
- **MyContract.json** - ABI file for the Solidity contract, required for interaction with the blockchain.
- **truffle-config.js** - Configuration for Truffle to deploy the contract on a local Ethereum network.

## Requirements

- Python 3.6+
- Flask
- Web3.py
- Truffle
- Ganache (or another local Ethereum node)
- Scikit-learn
- IoT-23 Dataset

## Data Preparation and Model Training

1. **Data Loading and Encoding**  
   The data was loaded from a CSV file, `iot23_combined.csv`, using the Pandas library. After verification, key features were identified based on the first rows and column headers. Some text-based columns were converted to numerical format using Label Encoding for two fields: `id.orig_h` (initiator IP addresses) and `label` (event type).

2. **Feature Selection**  
   Selected features for training included various session properties like duration, transmitted bytes (`orig_bytes`, `resp_bytes`), packet count, connection states, and communication protocols. The target label was derived from the encoded values in the `label` column.

3. **Model Training and Validation**  
   Data was split into training and test sets (70/30 split) using `train_test_split` from Scikit-learn, with a random seed for reproducibility (`random_state=42`). A RandomForestClassifier model was chosen for classification, setting the number of estimators to 100. The trained model was tested on the test set and saved for future predictions.

4. **Saving the Model and Encodings**  
   The trained model and encodings were saved to files for future predictions on new data from the blockchain.


## Data Generator

Due to limited access to real IoT data, a data generator was created to simulate network traffic data. The generator produces data that the Flask server's predictive model uses to determine if a network connection is malicious. 

- **Data Generation**: The generator simulates a continuous flow of network data by sending data to the server every 2 seconds, mimicking real-time IoT network activity.
- **Device ID**: Random IDs are generated to replace actual device IDs for testing.
- **Connection State**: Randomly generated from predefined states, simulating various network scenarios.

## Flask Server

The Flask server integrates real-time data analysis with blockchain technology. It connects to the blockchain using Web3, allowing the server to log threats permanently in the blockchain.

- **Endpoint `/predict`**: Accepts network data, uses the model to classify it as benign or malicious, and logs it if a threat is detected. Threat data includes device ID, type, timestamp, and various network metrics.
- **Threat Types**: The model categorizes 12 types of threats, such as "Benign," "DDoS," "C&C," and more.

The `/review` endpoint enables the administrator to review, approve, or reject detected threats before logging them to the blockchain.

## Blockchain Contract

The blockchain contract, deployed on Ganache, integrates IoT data analysis with decentralized storage:

- **Structures**: `ConnState` stores network connection states, and `ThreatData` stores threat details such as device ID, type, timestamp, and session metrics.
- **Event and Functions**:
  - `ThreatRecorded`: Triggered when a new threat is recorded.
  - `recordThreat`: Registers a new threat in the blockchain, verifying input data before storage.
  - `getAllThreats`: Returns all threats, used for model retraining and monitoring.


## Contract Structure
The MyContract.sol contract manages device registrations and stores information about detected threats. The contract's API details can be found in the MyContract.json file.
