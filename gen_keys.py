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

    if os.path.exists(filename):
        with open(filename, "r") as f:
            mnemonics = f.readlines()
    else:
        mnemonics = []

    if len(mnemonics) <= keyId:
        mnemonic = eth_account.Account.create().mnemonic
        mnemonics.append(mnemonic)
        with open(filename, "a") as f:
            f.write(mnemonic + "\n")
    else:
        mnemonic = mnemonics[keyId].strip()

    account = eth_account.Account.from_mnemonic(mnemonic)

    msg = eth_account.messages.encode_defunct(challenge)
    signature = w3.eth.account.sign_message(msg, private_key=account.privateKey)

    eth_addr = account.address

    assert eth_account.Account.recover_message(msg, signature=signature.signature.hex()) == eth_addr, \
        "Failed to sign message properly"

    return signature, eth_addr

if __name__ == "__main__":
    for i in range(4):
        challenge = os.urandom(64)
        sig, addr = get_keys(challenge=challenge, keyId=i)
        print(addr)
