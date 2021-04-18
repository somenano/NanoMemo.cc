const Memo = require('../models/memo.js');
const User = require('../models/user.js');
const NanoMemoTools = require('nanomemotools');

function convert_db_memo_to_memo(db_memo) {
    // Create Memo Object
    let memo = undefined;
    if (db_memo.version_encrypt !== undefined) {
        memo = new NanoMemoTools.memo.EncryptedMemo(db_memo.hash, db_memo.message, db_memo.signing_address, db_memo.decrypting_address, db_memo.signature, db_memo.version_sign, db_memo.version_encrypt);
    } else {
        memo = new NanoMemoTools.memo.Memo(db_memo.hash, db_memo.message, db_memo.signing_address, db_memo.signature, db_memo.version_sign);
    }

    memo.dtg = db_memo.dtg;
    return memo;
}

exports.get_db_memo_from_hash = function(hash) {
    return Memo.findOne({hash: hash}).exec();
}

exports.get_memo_from_hash = async function(hash) {
    const db_memo = await exports.get_db_memo_from_hash(hash);
    if (!db_memo) return undefined;
    
    return convert_db_memo_to_memo(db_memo);
}

exports.get_recent_db_memos = function(count) {
    return Memo.find({}).sort({dtg: -1}).limit(count).exec();
}

exports.get_recent_memos = async function(count) {
    let memos = [];

    const db_memos = await exports.get_recent_db_memos(count);
    if (!db_memos) return memos;

    for (let db_memo of db_memos) {
        memos.push(convert_db_memo_to_memo(db_memo));
    }
    return memos;
}

exports.delete_memo_from_hash = function(hash) {
    return Memo.deleteOne({hash: hash}).exec();
}

exports.get_user_from_id = function(id) {
    return User.findById(id).exec();
}

exports.get_users_for_daily_credits = function() {
    return User.find({daily_refill_needed: true}).exec();
}