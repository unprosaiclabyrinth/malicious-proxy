import requests
import argparse


def main():
    # Parse inline arguments
    argparser = argparse.ArgumentParser(description="Malicious proxy")
    argparser.add_argument("-m", help="The mode you want your proxy to operate, which will either be active or passive", type=str, required=True)   
    argparser.add_argument("listening_ip", help="The IP address your proxy will listen for connections on", type=str)   
    argparser.add_argument("listening_port", help="The port your proxy will listen for connections on", type=int)
    args = argparser.parse_args()

    proxy = {"http": f"http://{args.listening_ip}:{args.listening_port}"}
    r = requests.get('http://www.google.com/', proxies=proxy)


if __name__ == "__main__":
    main()