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
    const node_validated = await NanoMemoTools.memo.nodeValidated(memo, process.env.NODE_RPC_PROXY, process.env.NODE_RPC_USER, process.env.NODE_RPC_PASSWORD);
    if (node_validated == false) return {success: false, dtg: new Date(), error: 'Memo is not valid for block on the Nano Network, the wrong secret key may have been used for this block\'s account.'}
    else if (node_validated === undefined) return {success: false, dtg: new Date(), error: 'No block on the Nano Network found with corresponding hash'}

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
        validated: node_validated
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

    // Create Memo Object
    let memo = undefined;
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
    
    const memo_saved = await saveMemo(memo, user);
    if (memo_saved.error !== undefined) {
        return error_response(res, memo_saved.error);
    }
    if (!memo_saved || memo_saved.success != true || memo_saved.data === undefined) {
        return error_response(res, 'Unable to save memo at this time');
    }

    // Decrement user's credits
    if (user.credits > 0) {
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

router.get('/memo/block/:hash', async function(req, res, next) {
    // Returns memo data

    // Validate parameters
    if (!nanocurrency.checkHash(req.params.hash)) {
        return error_response(res, 'Invalid hash provided');
    }
    const hash = standardize_hash(req.params.hash);

    // Find data in db
    let memo = await DB.get_db_memo_from_hash(hash).catch(function(e) {
        console.error('In /api/memo/:hash, Error caught while getting memo from hash: '+ hash);
        console.error(e);
        return error_response(res, 'Error searching for memo');
    });
    if (!memo) {
        return error_response(res, 'Memo not found');
    }

    // Return data
    return success_response(res, filterMemo(memo));
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
    const lookup = await getUser(req.body.api_key, req.body.api_secret).catch(function(e) {
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

    const data = {
        api_key: lookup.data.id,
        credits_balance: lookup.data.credits,
        daily_credits: lookup.data.daily_credits,
        daily_seconds_remaining: ((new Date(now.getFullYear(), now.getMonth(), now.getDate(), 0, 0, 0, 0) - (new Date())) / 1000).toFixed(0)
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
        return error_message(res, 'Unable to create new user at this time');
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
