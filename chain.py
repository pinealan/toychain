'''Basic implementation of a blockchain. No security measure were considered.

TODO:
    Implement client
    Implement server
'''

import functools
import hashlib
import time

from Crypto.Hash      import SHA as sha
from Crypto.PublicKey import RSA
from Crypto.Signature import pss


def HASH(*args):
    h = sha.new()
    for arg in args:
        if isinstance(arg, str):
            arg = arg.encode()
        elif isinstance(arg, int):
            arg = arg.to_bytes(length=128, byteorder='big')
        elif not isinstance(arg, bytes):
            raise TypeError("cannot hash '{}' object".format(type(arg)))
        h.update(arg)
    return h


def tree_hash(*args):
    return HASH(*args).hexdigest()


def key_to_public_hex(key):
    return key.exportKey('DER').hex()


def key_to_private_hex(key):
    return key.publickey().exportKey('DER').hex()


def public_hex_to_key(pub):
    return RSA.importKey(bytes.fromhex(pub))


def private_hex_to_key(priv):
    return RSA.importKey(bytes.fromhex(priv))


def now_in_millisecond():
    return int(time.time() * 1000)


class Tx:
    '''A transaction object.

    Each transaction is initiated with 4 data fields:
    [sender, reciever, amount, msg]

    The signature of a Tx is created by signing off the hash digest of these 4
    data fields, with the private key that matches the sender's public address.
    Together this results in 5 data fields which goes into the final hash ID of
    a transaction.

    The final transaction hash is created with 5 data fields
    [sender, reciever, amount, signature, msg]

    Args:
        by, to: Public address (Hex) of sender and reciever of this transaction
        amount: Value being transacted
        msg (optional): An string message attached to this transaction

    Attributes:
        by, to: Public address (Hex) of sender and reciever of this transaction
        amount: Value being transacted
        signature: Signature by sender, signed with private key
        msg (optional): An string message attached to this transaction
        _prehash: Hash object of this Tx
        _hash: Hash object of this Tx
    '''
    def __init__(self, by, to, amount, msg=0):
        self.by         = by
        self.to         = to
        self.amount     = amount
        self.msg        = msg
        self.signature  = None
        self._prehash   = HASH(by, to, amount, msg)
        self._hash      = None


    def isSigned(self):
        return self.signature is not None


    def isValid(self):
        if not self.isSigned():
            return False
        try:
            verifier = pss.new(public_hex_to_key(self.by))
            verifier.verify(self._prehash, self.signature)
            return True
        except ValueError:
            return False


    def sign(self, key):
        '''Sign this transaction.'''
        self.signature = pss.new(key).sign(self._prehash)
        self._hash = HASH(self.by, self.to, self.amount, self.signature, self.msg)
        return self


    def __hash__(self):
        '''Return int representation of hash digest.'''
        return hash(self._hash.digest())


    @property
    def hash(self):
        '''Return binary representation of hash.'''
        return self._hash.digest()


    @property
    def hexhash(self):
        '''Return hex representation of hash'''
        return self._hash.hexdigest()


    def __repr__(self):
        try:
            hexhash = self.hexhash[:8]
            sign    = self.signature.hex()[:8]
        except:
            hexhash = None
            sign    = None
        return '{}(hash: {}, sign: {})'.format(
                self.__class__.__name__, hexhash, sign)


def hash_txs(*txs):
    return functools.reduce(lambda x, y: tree_hash(x, y), (tx.hash for tx in txs))



class BlockHeader:
    '''A block header. Contains all meta info in a block.

    Attributes:
        prevhash:   Hash of previous block
        roothash:   Root hash of this block's transactions merkle tree
        timestamp:  The block timestamp
        nouce:      An integer
    '''
    def __init__(self, prevhash, roothash, timestamp, nouce):
        self.prevhash   = prevhash
        self.roothash   = roothash
        self.timestamp  = timestamp
        self.nouce      = nouce
        self._hash      = HASH(prevhash, roothash, timestamp, nouce)


    def __hash__(self):
        return hash(self._hash)


    @property
    def hash(self):
        '''Memotization of hash value'''
        return self._hash.digest()


    @property
    def hexhash(self):
        return self._hash.hexdigest()


    def __repr__(self):
        return '{}(hash: {})'.format(self.__class__.__name__, self.hash)



class Block:
    '''A full block. Optionally contains a list of all transactions.

    Attributes:
        tx_count: Number of transactions in this block
        transactions: List of all transactions
    '''
    def __init__(self, prevhash, roothash, timestamp, nouce, transactions=None):
        self.header       = BlockHeader(prevhash, roothash, timestamp, nouce)
        self.hash         = self.header.hash
        self.hexhash      = self.header.hexhash
        self.transactions = transactions or []


    def tx_count(self):
        return len(self.transactions)


    def __hash__(self):
        return hash(self.header)


    def __repr__(self):
        return '{}(hash: {})'.format(self.__class__.__name__, hash(self))



class Chain:
    '''High level interface (UX/UI) to the blockchain '''
    tx_limit = 10

    def __init__(self, timestamp, addr=None):
        '''Initialise new block chain, genesis block included.

        Returns invalid chain by default (None addr).
        '''
        self.blocks = [Block(0, 0, timestamp, 0, [])]
        self.txs    = []
        self.addr   = addr


    def isValid(self):
        '''Check for chain validity'''
        return self.addr is not None


    def validateTx(self, tx):
        '''Reject transaction if sender does not have enough credit.'''
        return tx.isValid() and self.addr[tx.by] >= tx.amount


    def validateBlock(self, block, parent_block):
        valid_hash = block.prevhash == parent_block.hexhash
        valid_time = block.timestamp >= parent_block.timestamp
        return valid_hash and valid_time


    def transact(self, key, to, amount, msg=0, by=None):
        '''Record transaction on chain.'''
        by = by or key_to_public_hex(key)
        tx = Tx(by, to, amount, msg).sign(key)

        if not self.validateTx(tx):
            raise ValueError('invalid tx')

        try:
            self.addr[tx.by] -= amount
            self.addr[tx.to] += amount
        except KeyError:
            self.addr[tx.to] = amount

        self.txs.append(tx)

        if len(self.txs) == self.tx_limit:
            self.addBlock(now_in_millisecond())


    def addBlock(self, timestamp):
        root_hash = hash_txs(*self.txs)
        new_block = Block(self.last_block.hexhash, root_hash, timestamp, 0, self.txs)
        self.blocks.append(new_block)
        self.txs = []


    @property
    def last_block(self):
        return self.blocks[-1]


# Demo
for k in 'abcde':
    key = [RSA.importKey(open(k + '.pem', 'br').read()) for k in 'abcde']
    pri = [key_to_private_hex(k) for k in key]
    pub = [key_to_public_hex(k) for k in key]


addr = {
    pub[0]: 100,
    pub[1]: 250,
    pub[2]: 50
}


c = Chain(timestamp=0, addr=addr)

c.transact(key[0], pub[1], amount=10)
c.transact(key[0], pub[2], amount=40)

c.transact(key[1], pub[2], amount=20)
c.transact(key[1], pub[3], amount=10)
c.transact(key[1], pub[3], amount=30)
c.transact(key[1], pub[4], amount=50)

c.transact(key[2], pub[4], amount=40)

c.transact(key[3], pub[4], amount=10)
c.transact(key[3], pub[2], amount=20)

c.transact(key[4], pub[0], amount=20)
c.transact(key[4], pub[2], amount=10)
