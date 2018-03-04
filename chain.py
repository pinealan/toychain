'''Basic implementation of a blockchain. No security measure were considered.

TODO:
    Implement client
    Implement server
    Consider generating address from private keys
    Consider private key cryptography for Tx verification
    Consider hash object as abstraction over hash representation (like hashlib)
    Separate hash byte representations and int representations
'''

import functools
import hashlib
import time

from Crypto.Hash      import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import pss


# @Refacotr: Use proper functions
HASH = lambda x: abs(hash(x))
TIME = lambda: int(time.time() * 1000) # millisecond


class Tx:
    '''Data structure for a Transaction.

    Implements hashing. Defines byte size of data fields (attributes).
    '''
    addr_bytes = 128 # @Extract: make this a module variable instead?
    coin_space = 256 # @Extract: make this a module variable instead?

    def __init__(self, sender, receiver, amount, timestamp, msg=0):
        self.sender     = sender
        self.recver     = receiver
        self.amount     = amount
        self.timestamp  = timestamp
        self.msg        = msg

    def __hash__(self):
        '''Memotization of hash value'''
        try:
            return self._hash
        except AttributeError:
            self._hash = HASH((
                self.sender,
                self.recver,
                self.amount,
                self.timestamp,
                self.msg
            ))
            return self._hash

    def __repr__(self):
        return 'Tx(Hash: {}, Sender: {}, Receiver: {}, Amount: {}, Time: {})'.format(
                self.__hash__(), self.sender, self.recver, self.amount, self.timestamp)

    @classmethod
    def hash_txs(*txs):
        return functools.reduce(lambda x, y: HASH((x, y)), txs)


class BlockHeader:
    '''Data structure for a Block

    Implements hashing. Defines byte size of data fields (attributes).
    '''
    def __init__(self, prevhash, roothash, timestamp, nouce):
        self.prevhash   = prevhash
        self.roothash   = roothash
        self.timestamp  = timestamp
        self.nouce      = nouce
        self._hash      = None

    def __hash__(self):
        '''Memotization of hash value'''
        if not self._hash:
            self._hash = HASH((
                self.prevhash,
                self.roothash,
                self.timestamp,
                self.nouce
            ))
        return self._hash

    @property
    def hash(self):
        return hash(self)

    @property
    def hexhash(self):
        raise NotImplementedError

    def __repr__(self):
        return '{}({})'.format(
                self.__class__.__name__,
                self.hash,
                self.prevhash,
                self.timestamp)

class Block:
    def __init__(self, prevhash, roothash, timestamp, nouce, transactions=None):
        self.header = BlockHeader(prevhash, roothash, timestamp, nouce)
        self.transactions = transactions or []

    def tx_count(self):
        return len(self.transactions)

    def __hash__(self):
        return hash(self.header)

    def __repr__(self):
        return '{}({})'.format(self.__class__.__name__, hash(self))


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

    def isValidTx(self, tx):
        '''Reject transaction if sender does not have enough credit.'''
        try:
            if self.addr[tx.sender] < tx.amount:
                return False
            else:
                return True
        except KeyError:
            return False

    def isValidBlock(self, block, parent_block):
        valid_hash = block.prevhash == hash(parent_block)
        valid_time = block.timestamp >= parent_block.timestamp
        return valid_hash and valid_time

    def transact(self, sender, recver, amount, timestamp, msg=0):
        '''Make transaction on chain.'''
        tx = Tx(sender, recver, amount, timestamp, msg)

        if not self.isValidTx(tx):
            raise ValueError

        self.addr[tx.sender] -= amount
        try:
            self.addr[tx.recver] += amount
        except KeyError:
            self.addr[tx.recver] = amount

        self.txs.append(Tx)

        if len(self.txs) == self.tx_limit:
            self.makeBlock(timestamp)

    def makeBlock(self, timestamp):
        root_hash = Tx.hash_txs(*self.txs)
        self.blocks.append(Block(self.last_hash, root_hash, timestamp, 0, self.txs))
        self.txs = []

    @property
    def last_hash(self):
        return hash(self.blocks[-1])

    @property
    def last_block(self):
        return self.blocks[-1]


# Demo
addr = {
    0: 100,
    1: 200,
    2: 50
}
c = Chain(timestamp=0, addr=addr)
c.transact(1, 2, amount=50, timestamp=10)
c.transact(0, 3, amount=10, timestamp=11)
c.transact(0, 4, amount=10, timestamp=12)
c.transact(1, 5, amount=10, timestamp=13)
c.transact(1, 6, amount=10, timestamp=14)
c.transact(1, 7, amount=20, timestamp=14)
c.transact(1, 8, amount=20, timestamp=14)
c.transact(2, 9, amount=10, timestamp=14)
c.transact(0, 3, amount=10, timestamp=8)
c.transact(0, 4, amount=10, timestamp=5)
