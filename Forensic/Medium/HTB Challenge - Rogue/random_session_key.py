#!/usr/bin/env python3
import argparse
import hmac
from Cryptodome.Cipher import ARC4
from Cryptodome.Hash import MD5

def compute_random_session_key(username, domain, nthash_hex, ntproof_hex, encsession_hex, verbose=False):
    nthash = bytes.fromhex(nthash_hex)
    ntproof = bytes.fromhex(ntproof_hex)
    encsession = bytes.fromhex(encsession_hex)

    ud = (username + domain).upper().encode("utf-16le")
    resp_key_nt = hmac.new(nthash, ud, MD5).digest()
    key_exch_key = hmac.new(resp_key_nt, ntproof, MD5).digest()
    rsk = ARC4.new(key_exch_key).decrypt(encsession)

    if verbose:
        print("=== DEBUG INFO ===")
        print(f"USERNAME:     {username}")
        print(f"DOMAIN:       {domain}")
        print(f"NT HASH:      {nthash.hex()}")
        print(f"USER+DOMAIN:  {ud.hex()}")
        print(f"RespKeyNT:    {resp_key_nt.hex()}")
        print(f"NTProofStr:   {ntproof.hex()}")
        print(f"KeyExchKey:   {key_exch_key.hex()}")
        print(f"EncSession:   {encsession.hex()}")
        print("==================")

    return rsk.hex()


def main():
    parser = argparse.ArgumentParser(description="Calculate NTLMv1 ESS Random Session Key from PCAP values.")
    parser.add_argument("-u", "--user", required=True, help="Username (e.g. athomson)")
    parser.add_argument("-d", "--domain", required=True, help="Domain/Workgroup (e.g. CORP)")
    parser.add_argument("-p", "--nthash", required=True, help="NT Hash (32 hex chars)")
    parser.add_argument("-n", "--ntproof", required=True, help="NTProofStr (16 bytes hex)")
    parser.add_argument("-k", "--encsession", required=True, help="Encrypted Session Key (16 bytes hex)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    rsk_hex = compute_random_session_key(
        username=args.user,
        domain=args.domain,
        nthash_hex=args.nthash,
        ntproof_hex=args.ntproof,
        encsession_hex=args.encsession,
        verbose=args.verbose
    )

    print(f"Random Session Key: {rsk_hex}")
	
if __name__ == "__main__":
    main()
