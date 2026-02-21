import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import argparse
import json
socket.setdefaulttimeout(1)

baseline_file = "baseline.json"

def parse_arguments():
    parser = argparse.ArgumentParser(
        description= "Port monitoring tool to scan for open ports and identify potential vulnerabilities."
    )
    parser.add_argument("--target",required=True,help="Target host to scan (default: localhost)")
    parser.add_argument("--start",type=int,default=1,help="Starting port number (default:1)")
    parser.add_argument("--end",type=int,default=1024,help="Ending port number (default:1024)")
    parser.add_argument("--baseline",action="store_true",help="Run in baseline mode to only check for commonly vulnerable ports")
    return parser.parse_args()

def scan_port(target,port):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    result = sock.connect_ex((target, port))
    sock.close()
    if result == 0:
        return port
    return None

def run_scan(target, ports):
    print(f"Scanning {target} for open ports...")
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(lambda p: scan_port(target, p), ports)

    open_ports = [port for port in results if port is not None]
    open_ports.sort()
    return open_ports
def handle_baseline(open_ports, baseline_file, save_mode):
    if(save_mode):
        with open(baseline_file, "w") as f:
            json.dump(open_ports, f)
        print("\nBaseline saved.")
    else:
        try:
            with open(baseline_file, "r") as f:
                baseline_ports = json.load(f)
            new_ports = set(open_ports) - set(baseline_ports)
            closed_ports = set(baseline_ports) - set(open_ports)
            if new_ports:
                print("\n New Ports Detected:")
                for port in sorted(new_ports):
                    print(f"  + {port}")

            if closed_ports:
                print("\n Ports no longer open:")
                for port in sorted(closed_ports):
                    print(f"  - {port}")

            if not new_ports and not closed_ports:
                print("\nNo anomalies detected.")
        except FileNotFoundError:
            print("\nBaseline file not found. Run with --baseline to create one.")
        except KeyboardInterrupt:
            print("\nScan interrupted by user.")

def main():
    args = parse_arguments()
    target = args.target
    start_port = args.start
    end_port = args.end
    ports = range(start_port, end_port + 1)
    start_time = datetime.now()
    open_ports = run_scan(target,ports)
    end_time = datetime.now()
    duration = end_time - start_time
    try:
        handle_baseline(open_ports, baseline_file, args.baseline)
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    print(f"\nScan completed in {duration}")
    print(f"Total open ports found: {len(open_ports)}")
    
if __name__ == "__main__":
    main()

    

