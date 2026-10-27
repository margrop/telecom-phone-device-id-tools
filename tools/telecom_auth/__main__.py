import argparse
import socket

from .server import create_server


def build_parser():
    parser = argparse.ArgumentParser(description="Local China Telecom device authorization")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    return parser


def _lan_address():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 80))
        return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


def main(argv=None):
    arguments = build_parser().parse_args(argv)
    server = create_server(arguments.host, arguments.port)
    host = _lan_address() if arguments.host == "0.0.0.0" else arguments.host
    port = server.server_address[1]
    print(f"Open: http://{host}:{port}/", flush=True)
    if arguments.host != "127.0.0.1":
        print(
            "Warning: use only on a trusted LAN; traffic uses plain HTTP.",
            flush=True,
        )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
