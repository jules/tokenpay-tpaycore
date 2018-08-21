// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_TXMEMPOOL_H
#define BITCOIN_TXMEMPOOL_H

#include "core.h"
#include "addressindex.h"
#include "spentindex.h"

/*
 * CTxMemPool stores valid-according-to-the-current-best-chain
 * transactions that may be included in the next block.
 *
 * Transactions are added when they are seen on the network
 * (or created by the local node), but not all transactions seen
 * are added to the pool: if a new transaction double-spends
 * an input of a transaction in the pool, it is dropped,
 * as are non-standard transactions.
 */
class CTxMemPool
{
private:
    unsigned int nTransactionsUpdated;
public:
    mutable CCriticalSection cs;
    std::map<uint256, CTransaction> mapTx;
    std::map<COutPoint, CInPoint> mapNextTx;
    
    std::map<std::vector<uint8_t>, CKeyImageSpent> mapKeyImage;

    typedef std::map<CMempoolAddressDeltaKey, CMempoolAddressDelta, CMempoolAddressDeltaKeyCompare> addressDeltaMap;
    addressDeltaMap mapAddress;
    typedef std::map<uint256, std::vector<CMempoolAddressDeltaKey> > addressDeltaMapInserted;
    addressDeltaMapInserted mapAddressInserted;
    typedef std::map<CSpentIndexKey, CSpentIndexValue, CSpentIndexKeyCompare> mapSpentIndex;
    mapSpentIndex mapSpent;
    typedef std::map<uint256, std::vector<CSpentIndexKey> > mapSpentIndexInserted;
    mapSpentIndexInserted mapSpentInserted;
    
    
    CTxMemPool()
    {
        nTransactionsUpdated = 0;
    };
    
    bool addUnchecked(const uint256& hash, CTransaction &tx);
    bool remove(const CTransaction &tx, bool fRecursive = false);
    bool removeConflicts(const CTransaction &tx);
    void clear();
    void queryHashes(std::vector<uint256>& vtxid);

    void addAddressIndex(const CTransaction& tx, int64_t nTime);
    bool getAddressIndex(std::vector<std::pair<uint160, int> > &addresses,
                         std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> > &results);
    bool removeAddressIndex(const uint256 txhash);
    void addSpentIndex(const CTransaction& tx);
    bool getSpentIndex(CSpentIndexKey &key, CSpentIndexValue &value);
    bool removeSpentIndex(const uint256 txhash);
    
    unsigned int GetTransactionsUpdated() const
    {
        LOCK(cs);
        return nTransactionsUpdated;
    }

    void AddTransactionsUpdated(unsigned int n)
    {
        LOCK(cs);
        nTransactionsUpdated += n;
    }

    unsigned long size() const
    {
        LOCK(cs);
        return mapTx.size();
    }

    bool exists(uint256 hash) const
    {
        LOCK(cs);
        return (mapTx.count(hash) != 0);
    }

    bool lookup(uint256 hash, CTransaction& result) const;
    
    bool insertKeyImage(const std::vector<uint8_t>& vchImage, CKeyImageSpent& kis)
    {
        LOCK(cs);
        
        mapKeyImage[vchImage] = kis;
        
        return true;
    }
    bool lookupKeyImage(const std::vector<uint8_t>& vchImage, CKeyImageSpent& result) const
    {
        LOCK(cs);
        
        std::map<std::vector<uint8_t>, CKeyImageSpent>::const_iterator it = mapKeyImage.find(vchImage);
        if (it == mapKeyImage.end())
            return false;
        
        result = it->second;
        
        return true;
    }
};

#endif /* BITCOIN_TXMEMPOOL_H */
