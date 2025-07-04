from scapy.all import sniff, TCP, Raw
import re, json

# ---- Settings ----
FTP_INTERFACE = None  # Interfaces to listen to, setting "None" listens to all
JSON_FILE = "filenames.json"  # JSON file to store incoming file names

# Example: 20250420_34ABC123_sedan_incoming_ford.jpg
FILENAME_PATTERN = re.compile(r"^(?P<date>\d{8})_(?P<plate>[A-Z0-9]+)_.+\.(jpg|jpeg|png)$", re.IGNORECASE)


def kaydet(filename: str):
    entry = {"filename": filename}
    try:
        with open(JSON_FILE, "a", encoding="utf-8") as f:
            json.dump(entry, f, ensure_ascii=False)
            f.write("\n")
        print(f"[+] Saved to: {filename}")
    except Exception as e:
        print(f"[X] Error appending to JSON file: {e}")


def parse_ftp_packet(pkt):
    """
    Listens to FTP port, looks up for STOR commands
    """
    if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
        return

    try:
        payload = pkt[Raw].load.decode(errors="ignore")
    except Exception:
        return

    # Check each line with STOR command
    for line in payload.splitlines():
        if "STOR " in line:
            # Save the part after STOR
            try:
                _, filename = line.split("STOR ", 1)
                filename = filename.strip()
                kaydet(filename=filename)
                
                # Save only specific file types:
                """
                if FILENAME_PATTERN.match(filename):
                    kaydet(filename)
                else:
                    print(f"[!] Unexpected format: {filename}")
                """
            except ValueError:
                continue

if __name__ == '__main__':
    print(f"[*] Listening on FTP port 21... Outputs will be saved in '{JSON_FILE}' file.")
    sniff(iface=FTP_INTERFACE, filter="tcp port 21", prn=parse_ftp_packet, store=False)
