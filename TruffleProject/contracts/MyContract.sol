// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MyContract {
    string public message;

    constructor(string memory _message) {
        message = _message;
    }

    function setMessage(string memory _message) public {
        message = _message;
    }

    struct ConnState {
        uint8 OTH;
        uint8 REJ;
        uint8 RSTO;
        uint8 RSTOS0;
        uint8 RSTR;
        uint8 RSTRH;
        uint8 S0;
        uint8 S1;
        uint8 S2;
        uint8 S3;
        uint8 SF;
        uint8 SH;
        uint8 SHR;
    }

    struct ThreatData {
        string device_id;
        string threat_type;
        string timestamp;
        uint256 duration;
        uint256 orig_bytes;
        uint256 resp_bytes;
        uint256 missed_bytes;
        uint256 orig_h_encoded;
        uint256 orig_pkts;
        uint256 orig_ip_bytes;
        uint256 resp_pkts;
        uint256 resp_ip_bytes;
        uint8 proto_icmp;
        uint8 proto_tcp;
        uint8 proto_udp;
    }

    struct Threat {
        ThreatData data;
        ConnState conn_state;
    }
    mapping(address => Threat[]) public threats;
    address[] public allDevices;

    event ThreatRecorded(address indexed device, string threat_type, string timestamp);

    function recordThreat(
        ThreatData memory _data,
        ConnState memory _conn_state

    ) public {
         require(bytes(_data.device_id).length > 0, "Device ID is required");
        require(bytes(_data.threat_type).length > 0, "Threat type is required");
        require(bytes(_data.timestamp).length > 0, "Timestamp is required");
        require(_data.duration > 0, "Duration must be greater than 0");
        require(_data.orig_bytes >= 0, "Original bytes must be non-negative");
        require(_data.resp_bytes >= 0, "Response bytes must be non-negative");
        
        if (threats[msg.sender].length == 0) {
            allDevices.push(msg.sender);
        }
        
        Threat memory newThreat = Threat({
            data: _data,
            conn_state: _conn_state
        });

        threats[msg.sender].push(newThreat);

        emit ThreatRecorded(msg.sender, _data.threat_type, _data.timestamp);
    }

    
    function getAllThreats() public view returns (Threat[] memory) {
        uint256 totalThreatsCount = 0;

        for (uint256 i = 0; i < allDevices.length; i++) {
            totalThreatsCount += threats[allDevices[i]].length;
        }

        Threat[] memory allThreats = new Threat[](totalThreatsCount);
        uint256 index = 0;

        for (uint256 i = 0; i < allDevices.length; i++) {
            Threat[] memory deviceThreats = threats[allDevices[i]];

            for (uint256 j = 0; j < deviceThreats.length; j++) {
                allThreats[index] = deviceThreats[j];
                index++;
            }
        }

        return allThreats;
    }
}
