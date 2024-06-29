# Description

In passive mode, the proxy observes all the cleartext traffic and extracts certain sensitive information. In active mode, the proxy injects malicious Javascript code to the packets. In the phishing mode, the proxy sends a phishing page instead of a legitimate response.

# Usage

```
python -m mode listening_ip listening_port
```
where the proxy will operate in the specified mode (active, passive, or phishing) and listen for connections on the specified listening_ip and listening_port.

# Testing

The system/browser settings can be changed to setup a proxy at the specified IP address and port.
