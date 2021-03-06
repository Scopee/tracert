#!/usr/bin/env python3
import argparse
import socket

from arch.tracer import Tracer


def main():
    parser = argparse.ArgumentParser(description="tracert")
    parser.add_argument('address', type=str, help='IP address or DNS name')
    parser.add_argument('-m', default=20, type=int, help='Max TTL')
    args = parser.parse_args()
    ip = args.address
    max_ttl = args.m
    try:
        try:
            socket.gethostbyname(ip)
        except Exception:
            print(ip + ' is invalid')
            exit(-1)
        tracer = Tracer(socket.gethostbyname(ip), max_ttl)
        tracer.ping()
    except PermissionError:
        print("You don't have permissions to do this.")
        print("Please use sudo")
    except Exception as ex:
        raise ex


if __name__ == '__main__':
    main()