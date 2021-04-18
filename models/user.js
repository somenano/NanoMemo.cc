const mongoose = require('mongoose');
const mongooseLeanVirtuals = require('mongoose-lean-virtuals');

const js_helper = require('../helpers/js.js');

const Schema = mongoose.Schema;

var UserSchema = new Schema({
    dtg: {
        type: Date,
        default: Date.now,
        required: true
    },
    admin: {
        type: Boolean,
        default: false
    },
    active: {
        type: Boolean,
        require: true,
        default: true
    },
    hash: {
        type: String,
        required: false
    },
    credits: {
        type: Number,
        required: true,
    },
    daily_credits: {
        type: Number,
        required: true,
    },
    daily_refill_needed: {
        type: Boolean,
        required: true
    }
},{
    versionKey: false,
    toObject: { virtuals: true },
    toJSON: { virtuals: true }
});

UserSchema.plugin(mongooseLeanVirtuals);

module.exports = mongoose.model('user', UserSchema);