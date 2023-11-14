from mitmproxy import io, http, proxy, options, addons, tools
from mitmproxy.tools import main
from mitmproxy.tools.dump import DumpMaster
import asyncio
import argparse


def main():
    # Parse inline arguments
    argparser = argparse.ArgumentParser(description="Malicious proxy")
    argparser.add_argument("-m", help="The mode you want your proxy to operate, which will either be active or passive", type=str, required=True)   
    argparser.add_argument("listening_ip", help="The IP address your proxy will listen for connections on", type=str)   
    argparser.add_argument("listening_port", help="The port your proxy will listen for connections on", type=int)
    args = argparser.parse_args()

    opts = options.Options(listen_host=args.listening_ip, listen_port=args.listening_port)
    m = DumpMaster(options=opts)
    m.server = addons.proxyserver.ProxyServer()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(m.run())



def request(flow: http.HTTPFlow) -> None:
    print("[*] Received request:")
    print(flow.request.headers)
    print(flow.request.text)


def response(flow: http.HTTPFlow) -> None:
    print("[*] Received response:")
    print(flow.response.headers)
    print(flow.response.text)


if __name__ == "__main__":
    main()