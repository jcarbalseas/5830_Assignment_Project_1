# from web3 import Web3
# import eth_account
# import os

# def get_keys(challenge,keyId = 0, filename = "eth_mnemonic.txt"):
#     """
#     Generate a stable private key
#     challenge - byte string
#     keyId (integer) - which key to use
#     filename - filename to read and store mnemonics

#     Each mnemonic is stored on a separate line
#     If fewer than (keyId+1) mnemonics have been generated, generate a new one and return that
#     """

#     w3 = Web3()

#     msg = eth_account.messages.encode_defunct(challenge)

# 	#YOUR CODE HERE

#     assert eth_account.Account.recover_message(msg,signature=sig.signature.hex()) == eth_addr, f"Failed to sign message properly"

#     #return sig, acct #acct contains the private key
#     return sig, eth_addr

# if __name__ == "__main__":
#     for i in range(4):
#         challenge = os.urandom(64)
#         sig, addr= get_keys(challenge=challenge,keyId=i)
#         print( addr )

from web3 import Web3
import eth_account
import os

def get_keys(challenge, keyId=0, filename="eth_mnemonic.txt"):
    """
    Generate a stable private key
    challenge - byte string
    keyId (integer) - which key to use
    filename - filename to read and store mnemonics

    Each mnemonic is stored on a separate line
    If fewer than (keyId+1) mnemonics have been generated, generate a new one and return that
    """

    w3 = Web3()

    # Generate or load keys
    if os.path.exists(filename):
        with open(filename, "r") as f:
            private_keys = f.readlines()
    else:
        private_keys = []

    if len(private_keys) <= keyId:
        # Generate a new account
        acct = eth_account.Account.create()
        private_keys.append(acct.privateKey.hex())
        with open(filename, "a") as f:
            f.write(acct.privateKey.hex() + "\n")
    else:
        private_key = private_keys[keyId].strip()
        acct = eth_account.Account.from_key(private_key)

    # Sign the challenge
    msg = eth_account.messages.encode_defunct(challenge)
    sig = w3.eth.account.sign_message(msg, private_key=acct.privateKey)

    # Get Ethereum address from the account
    eth_addr = acct.address

    # Verify the signature to ensure everything works
    assert eth_account.Account.recover_message(msg, signature=sig.signature.hex()) == eth_addr, \
        "Failed to sign message properly"

    return sig, eth_addr

if __name__ == "__main__":
    for i in range(4):
        challenge = os.urandom(64)
        sig, addr = get_keys(challenge=challenge, keyId=i)
        print(addr)
