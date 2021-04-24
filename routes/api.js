const express = require('express');
const router = express.Router();

const nanocurrency = require('nanocurrency');
const blake2b = require('blakejs/blake2b');

const Memo = require('../models/memo.js');
const User = require('../models/user.js');

const DB = require('../helpers/db_query');
const NanoMemoTools = require('nanomemotools');
const www = require('../bin/www');

const ObjectId = require('mongoose').Types.ObjectId;
const MAGIC_STRING = 'SomeNano';

function standardize_hash(hash) {
    return hash.toUpperCase();
}

function standardize_key(key) {
    return key.toUpperCase();
}

function standardize_address(address) {
    return address.toLowerCase();
}

function error_response(res, description, user=undefined) {
    return res.json({
        dtg: new Date(),
        success: false,
        credits_balance: (user && user.credits !== undefined ? user.credits : undefined),
        error: description
    });
}

function success_response(res, data, user=undefined) {
    return res.json({
        dtg: new Date(),
        success: true,
        credits_balance: (user && user.credits !== undefined ? user.credits : undefined),
        data: data
    });
}

const filterMemo = function(memo) {
    const ret = {
        message: memo.message,
        hash: memo.hash,
        signature: memo.signature,
        version_sign: memo.version_sign,
        version_encrypt: memo.version_encrypt,
        dtg: memo.dtg,
        signing_address: memo.signing_address,
        decrypting_address: memo.decrypting_address
    }

    return ret;
}

const saveMemo = async function(memo, user) {

    // Validate memo signature
    if (!memo.valid_signature) return {success: false, dtg: new Date(), error: 'Invalid signature on memo'}

    // Check if memo already exists in the database for this hash
    const existing_memo = await DB.get_db_memo_from_hash(memo.hash).catch(function(e) {
        console.error('In api.saveMemo, Error caught while getting memo from hash: '+ hash);
        console.error(e);
        return {success: false, dtg: new Date(), error: 'Error while saving memo'}
    });
    if (existing_memo) {
        return {success: false, dtg: new Date(), error: 'A memo referencing this hash already exists'}
    }

    // Validate memo against Nano Network
    const node_validated = await NanoMemoTools.memo.nodeValidated([memo], process.env.NODE_RPC_PROXY, process.env.NODE_RPC_USER, process.env.NODE_RPC_PASSWORD);
    try {
        if (node_validated.not_found.indexOf(memo.hash) != -1) return {success: false, dtg: new Date(), error: 'Block is not found on the Nano Network.'}
        else if (node_validated.invalid.indexOf(memo.hash) != -1) return {success: false, dtg: new Date(), error: 'Memo is not valid for block on the Nano Network, the wrong secret key may have been used for this block\'s account.'}
        else if (node_validated.valid.indexOf(memo.hash) == -1) return {success: false, dtg: new Date(), error: 'Error validating hash against the Nano Network.'}
    } catch(e) {
        console.error('In saveMemo, an error was caught running NanoMemoTools.memo.nodeValidated');
        console.error(e);
        return {success: false, dtg: new Date(), error: 'Error validating hash against the Nano Network'}
    }

    // Create memo object
    let memo_db = new Memo({
        message: memo.message,
        hash: memo.hash,
        signature: memo.signature,
        version_sign: memo.version_sign,
        version_encrypt: memo.version_encrypt,
        user: user,
        signing_address: memo.signing_address,
        decrypting_address: memo.decrypting_address,
        validated: (node_validated.valid.indexOf(memo.hash) >= 0)
    });

    // Save memo
    await memo_db.save().catch(function(e) {
        console.error('In api.saveMemo, Error saving new memo');
        console.error(memo_db);
        console.error(e);
        return {success: false, dtg: new Date(), error: 'Error saving memo'}
    });

    // Disseminate
    www.wss_disseminate(memo);

    return {success: true, dtg: new Date(), data: memo_db}
}

router.post('/memo/new', async function(req, res, next) {
    // Writes memo data


    // Validate inputs
    if (!NanoMemoTools.memo.validateHash(req.body.hash)) return error_response(res, 'Invalid hash value');
    if (!NanoMemoTools.memo.validateMessage(req.body.message)) return error_response(res, 'Invalid message value');
    if (!NanoMemoTools.memo.validateMessage(req.body.signing_address)) return error_response(res, 'Invalid signing_address value');
    if (req.body.version_encrypt !== undefined && !NanoMemoTools.memo.validateMessage(req.body.decrypting_address)) return error_response(res, 'Invalid decrypting_address value');
    if (!NanoMemoTools.memo.validateMessage(req.body.signature)) return error_response(res, 'Invalid signature value');
    if (req.body.version_sign != NanoMemoTools.version.sign) return error_response(res, 'Invalid version_sign value. Must use: '+ NanoMemoTools.version.sign);
    if (req.body.version_encrypt !== undefined && req.body.version_encrypt != NanoMemoTools.version.encrypt) return error_response(res, 'Invalid version_encrypt value. Must use: '+ NanoMemoTools.version.encrypt);

    // Check for IP Rate Limiting
    let ip_lookup = {};
    if (!req.body.api_key || !req.body.api_secret) {
        // IP Rate Limiting

        const lookup = www.ipConsume(req.ip);
        if (lookup.error !== undefined) {
            return error_response(res, lookup.error);
        } else {
            req.body.api_key = process.env.GENERIC_USER_API_KEY;
            req.body.api_secret = process.env.GENERIC_USER_API_SECRET;
        }
    }

    // Validate User Credentials
    const lookup = await getUser(req.body.api_key, req.body.api_secret).catch(function(e) {
        console.error('In NanoMemo.api /user/new, error caught when running getUser');
        console.error(e);
        return error_response(res, 'Unable to validate API credentials at this time');
    });
    if (lookup.error !== undefined) {
        return error_response(res, lookup.error);
    }
    if (!lookup || lookup.success != true || lookup.data === undefined) {
        return error_response(res, 'Unable to validate API credentials at this time');
    }
    let user = lookup.data;

    if (user.credits == 0 || user.credits < -1) {    // Credit balance of -1 is no limit
        return error_response(res, 'Insufficient credit balance');
    }

    // Set user credits to the IP credits
    if (ip_lookup.credits !== undefined) user.credits = ip_lookup.credits;

    // Create Memo Object
    let memo = undefined;
    try {
        if (req.body.version_encrypt !== undefined) {
            memo = new NanoMemoTools.memo.EncryptedMemo(
                req.body.hash,
                req.body.message,
                req.body.signing_address,
                req.body.decrypting_address,
                req.body.signature,
                req.body.version_sign,
                req.body.version_encrypt
            );
        } else {
            memo = new NanoMemoTools.memo.Memo(
                req.body.hash,
                req.body.message,
                req.body.signing_address,
                req.body.signature,
                req.body.version_sign
            );
        }
    } catch(e) {
        console.error('In /memo/new, an error was caught while creating the memo');
        console.error(req.body);
        console.error(e);
        return error_response(res, 'Unable to create memo with provided parameters');
    }
    
    const memo_saved = await saveMemo(memo, user);
    if (memo_saved.error !== undefined) {
        return error_response(res, memo_saved.error);
    }
    if (!memo_saved || memo_saved.success != true || memo_saved.data === undefined) {
        return error_response(res, 'Unable to save memo at this time');
    }

    // Decrement user's credits (unless its from ipConsume)
    if (ip_lookup.credits === undefined && user.credits > 0) {
        user.credits -= 1;
        if (user.credits < user.daily_credits) {
            user.daily_refill_needed = true;
        } else {
            user.daily_refill_needed = false;
        }
        await user.save().catch(function(e) {
            console.error('In /api/memo/new, Error updating user credit balance');
            console.error(user);
            console.error(e);
        });
    }
    
    return success_response(res, filterMemo(memo_saved.data), user);
});

router.post('/memo/blocks', async function(req, res, next) {
    // Returns array of memo data

    // Validate parameters
    if (!req.body.hashes || req.body.hashes.length == undefined) {
        return error_response(res, 'Invalid hashes provided');
    }
    if (req.body.hashes.length > process.env.MAX_MEMO_RETURN) {
        return error_response(res, 'Requested too many memos, max '+ process.env.MAX_MEMO_RETURN +' memos at one time');
    }
    const hashes = req.body.hashes;

    // Standardize hashes
    for (let i=0 ; i<hashes.length ; i++) hashes[i] = standardize_hash(hashes[i]);

    // Find data in db
    let memos = await DB.get_db_memos_from_hashes(hashes).catch(function(e) {
        console.error('In /api/memo/blocks, Error caught while getting memos from hashes');
        console.error(hashes);
        console.error(e);
        return error_response(res, 'Error searching for memos');
    });
    if (memos === undefined || memos === null) {
        return error_response(res, 'Error searching for memos');
    }

    let filtered_memos = {};
    for (memo of memos) filtered_memos[memo.hash] = filterMemo(memo);

    // Return data
    return success_response(res, filtered_memos);
});

/*************
 * /user
 */
 
function hash(msg, length=24) {
    return Buffer.from(blake2b.blake2b(MAGIC_STRING + msg, null, length)).toString('hex');
}

function userHash(api_key, api_secret) {
    return hash(api_key + api_secret);
}

const validateAPIKey = function(key) {
    // return ObjectId.isValid(key);
    return ((new ObjectId(key)) == key);
}

const validateSecretKey = function(key) {
    return key.length == 64;
}

const getUser = async function(api_key, api_secret) {
    // Validate parameters
    if (!api_key || !validateAPIKey(api_key)) {
        return {success: false, dtg: new Date(), error: 'Invalid api_key provided'};
    }
    if (!api_secret || !validateSecretKey(api_secret)) {
        return {success: false, dtg: new Date(), error: 'Invalid api_secret provided'};
    }

    // Query the db
    const user = await DB.get_user_from_id(api_key).catch(function(e) {
        console.error('In NanoMemo.api.getUser, error caught when running DB.get_user_from_id with id: '+ api_key);
        console.error(e);
        return {success: false, dtg: new Date(), error: 'Unable to validate API credentials at this time'};
    });
    if (!user) {
        return {success: false, dtg: new Date(), error: 'Invalid API credentials'};
    }

    if (user.hash != userHash(api_key, api_secret)) {
        return {success: false, dtg: new Date(), error: 'Invalid API credentials'};
    }

    if (!user.active) {
        return {success: false, dtg: new Date(), error: 'API credentials are not activated at this time'};
    }

    return {success: true, dtg: new Date(), data: user};
}

router.post('/user', async function(req, res, next) {
    // Return user's data
    let lookup = {};
    if (!req.body.api_key || !req.body.api_secret) {

        // IP Rate Limiting
        lookup.data = www.ipCredits(req.ip);
        lookup.data.ip = req.ip;

    } else {

        lookup = await getUser(req.body.api_key, req.body.api_secret).catch(function(e) {
            console.error('In NanoMemo.api /user, error caught when running getUser');
            console.error(e);
            return error_response(res, 'Unable to validate API credentials at this time');
        });
        if (lookup.error !== undefined) {
            return error_response(res, lookup.error);
        }
        if (!lookup || lookup.success != true || lookup.data === undefined) {
            return error_response(res, 'Unable to validate API credentials at this time');
        }

    }

    let now = new Date();
    let daily_credit_refresh = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 0, 0, 0, 0) - now;
    if (daily_credit_refresh < 0) {
        daily_credit_refresh += 86400000; // it's after 0000, try 0000 tomorrow.
    }
    daily_credit_refresh /= 1000;

    const data = {
        api_key: lookup.data.id,
        ip: lookup.data.ip,
        credits_balance: lookup.data.credits,
        daily_credits: lookup.data.daily_credits,
        daily_seconds_remaining: Number(daily_credit_refresh.toFixed(0))
    }
    
    return success_response(res, data);
});

router.post('/admin/user/new', async function(req, res, next) {
    // Return user's data
    const lookup = await getUser(req.body.api_key, req.body.api_secret).catch(function(e) {
        console.error('In NanoMemo.api /user/new, error caught when running getUser');
        console.error(e);
        return error_response(res, 'Unable to validate API credentials at this time');
    });
    if (lookup.error !== undefined) {
        return error_response(res, lookup.error);
    }
    if (!lookup || lookup.success != true || lookup.data === undefined) {
        return error_response(res, 'Unable to validate API credentials at this time');
    }
    const user = lookup.data;
    if (!user.admin) {
        return error_response(res, 'Invalid admin credentials');
    }

    // Create new uesr
    const new_user = new User({
        credits: process.env.USER_DAILY_CREDITS,
        daily_credits: process.env.USER_DAILY_CREDITS,
        daily_refill_needed: false
    });
    const new_api_secret = standardize_key(await nanocurrency.generateSeed());
    new_user.hash = userHash(new_user.id, new_api_secret);
    new_user.save().catch(function(e) {
        console.error('In NanoMemo.api /user/new, error caught when saving new user');
        console.error(new_user);
        console.error(e);
        return error_response(res, 'Unable to create new user at this time');
    });

    const data = {
        api_key: new_user.id,
        api_secret: new_api_secret,
        credits_balance: new_user.credits,
        daily_credits: new_user.daily_credits
    }

    return success_response(res, data);
});

module.exports = router;
