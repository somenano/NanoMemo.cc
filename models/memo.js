const mongoose = require('mongoose');
const mongooseLeanVirtuals = require('mongoose-lean-virtuals');

const js_helper = require('../helpers/js.js');
const User = require('./user.js');

const Schema = mongoose.Schema;

var MemoSchema = new Schema({
    dtg: {
        type: Date,
        default: Date.now,
        required: true
    },
    user: {
        type: Schema.Types.ObjectId,
        required: true,
        ref: 'User'
    },
    message: {
        type: String,
        required: true
    },
    hash: {
        type: String,
        required: true
    },
    signature: {
        type: String,
        required: true
    },
    validated: {
        type: Boolean,
        default: false,
    },
    version_sign: {
        type: Number,
        required: true
    },
    version_encrypt: {
        type: Number,
        required: false
    },
    signing_address: {
        type: String,
        required: true
    },
    decrypting_address: {
        type: String,
        required: false
    },

},{
    versionKey: false,
    toObject: { virtuals: true },
    toJSON: { virtuals: true }
});

MemoSchema.plugin(mongooseLeanVirtuals);

module.exports = mongoose.model('memo', MemoSchema);