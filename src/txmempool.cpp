// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txmempool.h"

#include "core.h"
#include "main.h" // for CTransaction
#include "hash.h"
#include "txdb-leveldb.h"

using namespace std;

bool CTxMemPool::addUnchecked(const uint256& hash, CTransaction &tx)
{
    // Add to memory pool without checking anything.  Don't call this directly,
    // call CTxMemPool::accept to properly check the transaction first.
    {
        mapTx[hash] = tx;
        for (unsigned int i = 0; i < tx.vin.size(); i++)
            mapNextTx[tx.vin[i].prevout] = CInPoint(&mapTx[hash], i);
        nTransactionsUpdated++;
    }
    return true;
}


bool CTxMemPool::remove(const CTransaction &tx, bool fRecursive)
{
    // Remove transaction from memory pool
    {
        LOCK(cs);
        uint256 hash = tx.GetHash();
        if (mapTx.count(hash))
        {
            if (fRecursive)
            {
                for (unsigned int i = 0; i < tx.vout.size(); i++)
                {
                    std::map<COutPoint, CInPoint>::iterator it = mapNextTx.find(COutPoint(hash, i));
                    if (it != mapNextTx.end())
                        remove(*it->second.ptx, true);
                };
            };
            BOOST_FOREACH(const CTxIn& txin, tx.vin)
                mapNextTx.erase(txin.prevout);
            mapTx.erase(hash);
            
            if (tx.nVersion == ANON_TXN_VERSION)
            {
                // -- remove key images
                for (unsigned int i = 0; i < tx.vin.size(); ++i)
                {
                    const CTxIn& txin = tx.vin[i];

                    if (!txin.IsAnonInput())
                        continue;
                    
                    ec_point vchImage;
                    txin.ExtractKeyImage(vchImage);
                    
                    mapKeyImage.erase(vchImage);
                };
            };
            
            nTransactionsUpdated++;
        };
    }
    return true;
}

bool CTxMemPool::removeConflicts(const CTransaction &tx)
{
    // Remove transactions which depend on inputs of tx, recursively
    LOCK(cs);
    BOOST_FOREACH(const CTxIn &txin, tx.vin)
    {
        std::map<COutPoint, CInPoint>::iterator it = mapNextTx.find(txin.prevout);
        if (it != mapNextTx.end())
        {
            const CTransaction &txConflict = *it->second.ptx;
            if (txConflict != tx)
                remove(txConflict, true);
        };
    };
    return true;
}

void CTxMemPool::clear()
{
    LOCK(cs);
    mapTx.clear();
    mapNextTx.clear();
    mapKeyImage.clear();
    ++nTransactionsUpdated;
}

void CTxMemPool::queryHashes(std::vector<uint256>& vtxid)
{
    vtxid.clear();

    LOCK(cs);
    vtxid.reserve(mapTx.size());
    for (map<uint256, CTransaction>::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
        vtxid.push_back((*mi).first);
}

bool CTxMemPool::lookup(uint256 hash, CTransaction& result) const
{
    LOCK(cs);
    std::map<uint256, CTransaction>::const_iterator i = mapTx.find(hash);
    if (i == mapTx.end())
        return false;
    result = i->second;
    return true;
}

void CTxMemPool::addAddressIndex(const CTransaction& tx, int64_t nTime)
{
    LOCK(cs);
    std::vector<CMempoolAddressDeltaKey> inserted;
    uint256 txhash = tx.GetHash();
    for (unsigned int j = 0; j < tx.vin.size(); j++) {
        const CTxIn input = tx.vin[j];
        const COutPoint &out = input.prevout;
        CTransaction tx;
        if (CTxDB("r").ReadDiskTx(out, tx))
        {
            if (out.n >= tx.vout.size())
                throw error("addAddressIndex() : n out of range");

            CTxOut &prevout = tx.vout[out.n];
            if (prevout.scriptPubKey.IsPayToScriptHash()) {
                std::vector<unsigned char> hashBytes(prevout.scriptPubKey.begin()+2, prevout.scriptPubKey.begin()+22);
                CMempoolAddressDeltaKey key(2, uint160(hashBytes), txhash, j, 1);
                CMempoolAddressDelta delta(nTime, prevout.nValue * -1, input.prevout.hash, input.prevout.n);
                mapAddress.insert(std::make_pair(key, delta));
                inserted.push_back(key);
            } else if (prevout.scriptPubKey.IsPayToPublicKeyHash()) {
                std::vector<unsigned char> hashBytes(prevout.scriptPubKey.begin()+3, prevout.scriptPubKey.begin()+23);
                CMempoolAddressDeltaKey key(1, uint160(hashBytes), txhash, j, 1);
                CMempoolAddressDelta delta(nTime, prevout.nValue * -1, input.prevout.hash, input.prevout.n);
                mapAddress.insert(std::make_pair(key, delta));
                inserted.push_back(key);
            } else if (prevout.scriptPubKey.IsPayToPublicKey()) {
                uint160 hashBytes(Hash160(prevout.scriptPubKey.begin()+1, prevout.scriptPubKey.end()-1));
                CMempoolAddressDeltaKey key(1, hashBytes, txhash, j, 1);
                CMempoolAddressDelta delta(nTime, prevout.nValue * -1, input.prevout.hash, input.prevout.n);
                mapAddress.insert(std::make_pair(key, delta));
                inserted.push_back(key);
            }
        }
    }
    for (unsigned int k = 0; k < tx.vout.size(); k++) {
        const CTxOut &out = tx.vout[k];
        if (out.scriptPubKey.IsPayToScriptHash()) {
            std::vector<unsigned char> hashBytes(out.scriptPubKey.begin()+2, out.scriptPubKey.begin()+22);
            CMempoolAddressDeltaKey key(2, uint160(hashBytes), txhash, k, 0);
            mapAddress.insert(std::make_pair(key, CMempoolAddressDelta(nTime, out.nValue)));
            inserted.push_back(key);
        } else if (out.scriptPubKey.IsPayToPublicKeyHash()) {
            std::vector<unsigned char> hashBytes(out.scriptPubKey.begin()+3, out.scriptPubKey.begin()+23);
            std::pair<addressDeltaMap::iterator,bool> ret;
            CMempoolAddressDeltaKey key(1, uint160(hashBytes), txhash, k, 0);
            mapAddress.insert(std::make_pair(key, CMempoolAddressDelta(nTime, out.nValue)));
            inserted.push_back(key);
        } else if (out.scriptPubKey.IsPayToPublicKey()) {
            uint160 hashBytes(Hash160(out.scriptPubKey.begin()+1, out.scriptPubKey.end()-1));
            std::pair<addressDeltaMap::iterator,bool> ret;
            CMempoolAddressDeltaKey key(1, hashBytes, txhash, k, 0);
            mapAddress.insert(std::make_pair(key, CMempoolAddressDelta(nTime, out.nValue)));
            inserted.push_back(key);
        }
    }
    mapAddressInserted.insert(std::make_pair(txhash, inserted));
}
bool CTxMemPool::getAddressIndex(std::vector<std::pair<uint160, int> > &addresses,
                                 std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> > &results)
{
    LOCK(cs);
    for (std::vector<std::pair<uint160, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        addressDeltaMap::iterator ait = mapAddress.lower_bound(CMempoolAddressDeltaKey((*it).second, (*it).first));
        while (ait != mapAddress.end() && (*ait).first.addressBytes == (*it).first && (*ait).first.type == (*it).second) {
            results.push_back(*ait);
            ait++;
        }
    }
    return true;
}
bool CTxMemPool::removeAddressIndex(const uint256 txhash)
{
    LOCK(cs);
    addressDeltaMapInserted::iterator it = mapAddressInserted.find(txhash);
    if (it != mapAddressInserted.end()) {
        std::vector<CMempoolAddressDeltaKey> keys = (*it).second;
        for (std::vector<CMempoolAddressDeltaKey>::iterator mit = keys.begin(); mit != keys.end(); mit++) {
            mapAddress.erase(*mit);
        }
        mapAddressInserted.erase(it);
    }
    return true;
}
void CTxMemPool::addSpentIndex(const CTransaction& tx)
{
    LOCK(cs);
    std::vector<CSpentIndexKey> inserted;
    uint256 txhash = tx.GetHash();
    for (unsigned int j = 0; j < tx.vin.size(); j++) {
        const CTxIn input = tx.vin[j];
        const COutPoint &out = input.prevout;
        CTransaction tx;
        if (!CTxDB("r").ReadDiskTx(out, tx))
        {
            if (out.n >= tx.vout.size())
                throw error("addSpentIndex() : n out of range");

            CTxOut &prevout = tx.vout[out.n];
            uint160 addressHash;
            int addressType;
            if (prevout.scriptPubKey.IsPayToScriptHash()) {
                addressHash = uint160(std::vector<unsigned char> (prevout.scriptPubKey.begin()+2, prevout.scriptPubKey.begin()+22));
                addressType = 2;
            } else if (prevout.scriptPubKey.IsPayToPublicKeyHash()) {
                addressHash = uint160(std::vector<unsigned char> (prevout.scriptPubKey.begin()+3, prevout.scriptPubKey.begin()+23));
                addressType = 1;
            } else if (prevout.scriptPubKey.IsPayToPublicKey()) {
                addressHash = Hash160(prevout.scriptPubKey.begin()+1, prevout.scriptPubKey.end()-1);
                addressType = 1;
            } else {
                addressHash = 0;
                addressType = 0;
            }
            CSpentIndexKey key = CSpentIndexKey(input.prevout.hash, input.prevout.n);
            CSpentIndexValue value = CSpentIndexValue(txhash, j, -1, prevout.nValue, addressType, addressHash);
            mapSpent.insert(std::make_pair(key, value));
            inserted.push_back(key);
        }
    }
    mapSpentInserted.insert(std::make_pair(txhash, inserted));
}
bool CTxMemPool::getSpentIndex(CSpentIndexKey &key, CSpentIndexValue &value)
{
    LOCK(cs);
    mapSpentIndex::iterator it;
    it = mapSpent.find(key);
    if (it != mapSpent.end()) {
        value = it->second;
        return true;
    }
    return false;
}
bool CTxMemPool::removeSpentIndex(const uint256 txhash)
{
    LOCK(cs);
    mapSpentIndexInserted::iterator it = mapSpentInserted.find(txhash);
    if (it != mapSpentInserted.end()) {
        std::vector<CSpentIndexKey> keys = (*it).second;
        for (std::vector<CSpentIndexKey>::iterator mit = keys.begin(); mit != keys.end(); mit++) {
            mapSpent.erase(*mit);
        }
        mapSpentInserted.erase(it);
    }
    return true;
}