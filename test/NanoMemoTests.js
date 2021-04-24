process.env.NODE_ENV = 'test';

const chai = require('chai');
const expect = chai.expect;
const chaiHttp = require('chai-http');
chai.use(chaiHttp);
const www = require('../bin/www');
const Memo = require('../models/memo');
const User = require('../models/user');

process.env.GENERIC_USER_API_KEY = process.env.TEST_USER_API_KEY;
process.env.GENERIC_USER_API_SECRET = process.env.TEST_USER_API_SECRET;

const NanoMemoTools = require('nanomemotools');

const seed = process.env.TEST_SEED;
let accounts = [
    {
        private_key: NanoMemoTools.tools.getPrivateKey(seed, 0),
        public_key: NanoMemoTools.tools.getPublicKeyFromPrivateKey(NanoMemoTools.tools.getPrivateKey(seed, 0))
    },
    {
        private_key: NanoMemoTools.tools.getPrivateKey(seed, 1),
        public_key: NanoMemoTools.tools.getPublicKeyFromPrivateKey(NanoMemoTools.tools.getPrivateKey(seed, 1))
    }
];
accounts[0].address = NanoMemoTools.tools.getAddress(accounts[0].public_key);
accounts[1].address = NanoMemoTools.tools.getAddress(accounts[1].public_key);
const message = 'test message';
const hash = '8AC6C22AE56B546A8BF80DC75E006CE54E206476E9E1687DCBE6B7DE669C796B';

describe("API Endpoints /api/memo", function() {
    beforeEach((done) => {
        Memo.deleteMany({}, (err) => {
            done();
        });
    });

    describe("/api/memo/new", () => {

        it('Saves memo not on Nano Network', (done) => {
            const memo = new NanoMemoTools.memo.Memo(
                '0000000000000000000000000000000000000000000000000000000000000000',
                message,
                accounts[0].address
            );
            memo.sign(accounts[0].private_key);

            chai.request(www)
                .post('/api/memo/new')
                .send({
                    message: memo.message,
                    hash: memo.hash,
                    signing_address: memo.signing_address,
                    signature: memo.signature,
                    version_sign: memo.version_sign,
                })
                .end((err, res) => {
                    expect(res.body.success).to.equal(false);
                    expect(res.body).to.have.property('dtg');
                    expect(res.body.error).to.equal('Block is not found on the Nano Network.');
                    done();
            });
        });

        it('Saves memo signed by wrong keys for block on Nano Network', (done) => {
            const memo = new NanoMemoTools.memo.Memo(
                hash,
                message,
                accounts[1].address
            );
            memo.sign(accounts[1].private_key);

            chai.request(www)
                .post('/api/memo/new')
                .send({
                    message: memo.message,
                    hash: memo.hash,
                    signing_address: memo.signing_address,
                    signature: memo.signature,
                    version_sign: memo.version_sign,
                })
                .end((err, res) => {
                    expect(res.body.success).to.equal(false);
                    expect(res.body).to.have.property('dtg');
                    expect(res.body.error).to.equal('Memo is not valid for block on the Nano Network, the wrong secret key may have been used for this block\'s account.');
                    done();
            });
        });

        it('Saves memo not with invalid signature', (done) => {
            const memo = new NanoMemoTools.memo.Memo(
                hash,
                message,
                accounts[0].address
            );
            memo.sign(accounts[1].private_key);

            chai.request(www)
                .post('/api/memo/new')
                .send({
                    message: memo.message,
                    hash: memo.hash,
                    signing_address: memo.signing_address,
                    signature: memo.signature,
                    version_sign: memo.version_sign,
                })
                .end((err, res) => {
                    expect(res.body.success).to.equal(false);
                    expect(res.body).to.have.property('dtg');
                    expect(res.body.error).to.equal('Invalid signature on memo');
                    done();
            });
        });

        it('Saves memo with too long of a message', (done) => {
            const too_long = Number(process.env.MESSAGE_LENGTH) + 10;
            const long_message = new Array(too_long + 1).join( '0' );
            const memo = new NanoMemoTools.memo.Memo(
                hash,
                message,
                accounts[0].address
            );
            memo.message = long_message;    // go around constructor because it error checks
            memo.sign(accounts[0].private_key);

            chai.request(www)
                .post('/api/memo/new')
                .send({
                    message: memo.message,
                    hash: memo.hash,
                    signing_address: memo.signing_address,
                    signature: memo.signature,
                    version_sign: memo.version_sign,
                })
                .end((err, res) => {
                    expect(res.body.success).to.equal(false);
                    expect(res.body).to.have.property('dtg');
                    expect(res.body.error).to.equal('Invalid message value');
                    done();
            });
        });

        it('Saves memo with missing version_sign', (done) => {
            const memo = new NanoMemoTools.memo.Memo(
                hash,
                message,
                accounts[0].address
            );
            memo.sign(accounts[0].private_key);

            chai.request(www)
                .post('/api/memo/new')
                .send({
                    message: memo.message,
                    hash: memo.hash,
                    signing_address: memo.signing_address,
                    signature: memo.signature,
                    // version_sign: memo.version_sign,
                })
                .end((err, res) => {
                    expect(res.body.success).to.equal(false);
                    expect(res.body).to.have.property('dtg');
                    expect(res.body.error).to.equal('Invalid version_sign value. Must use: 1');
                    done();
            });
        });

        it('Saves memo with invalid version_sign', (done) => {
            const memo = new NanoMemoTools.memo.Memo(
                hash,
                message,
                accounts[0].address
            );
            memo.sign(accounts[0].private_key);

            chai.request(www)
                .post('/api/memo/new')
                .send({
                    message: memo.message,
                    hash: memo.hash,
                    signing_address: memo.signing_address,
                    signature: memo.signature,
                    version_sign: 12345
                })
                .end((err, res) => {
                    expect(res.body.success).to.equal(false);
                    expect(res.body).to.have.property('dtg');
                    expect(res.body.error).to.equal('Invalid version_sign value. Must use: 1');
                    done();
            });
        });

        it('Saves a valid non-encrypted memo', (done) => {
            const memo = new NanoMemoTools.memo.Memo(
                hash,
                message,
                accounts[0].address
            );
            memo.sign(accounts[0].private_key);

            chai.request(www)
                .post('/api/memo/new')
                .send({
                    message: memo.message,
                    hash: memo.hash,
                    signing_address: memo.signing_address,
                    signature: memo.signature,
                    version_sign: memo.version_sign,
                })
                .end((err, res) => {
                    expect(res.body.success).to.equal(true);
                    expect(res.body).to.have.property('dtg');
                    expect(res.body).to.have.property('credits_balance');
                    expect(res.body).to.have.property('data');
                    expect(res.body.data).to.have.property('dtg');
                    expect(res.body.data.message).to.equal(memo.message);
                    expect(res.body.data.hash).to.equal(memo.hash);
                    expect(res.body.data.signature).to.equal(memo.signature);
                    expect(res.body.data.version_sign).to.equal(memo.version_sign);
                    expect(res.body.data.signing_address).to.equal(memo.signing_address);
                    done();
            });
        });

        it('Saves a valid non-encrypted memo twice', (done) => {
            const memo = new NanoMemoTools.memo.Memo(
                hash,
                message,
                accounts[0].address
            );
            memo.sign(accounts[0].private_key);

            chai.request(www)
                .post('/api/memo/new')
                .send({
                    message: memo.message,
                    hash: memo.hash,
                    signing_address: memo.signing_address,
                    signature: memo.signature,
                    version_sign: memo.version_sign,
                })
                .end((err, res) => {
                    expect(res.body.success).to.equal(true);
                    chai.request(www)
                        .post('/api/memo/new')
                        .send({
                            message: memo.message,
                            hash: memo.hash,
                            signing_address: memo.signing_address,
                            signature: memo.signature,
                            version_sign: memo.version_sign,
                        })
                        .end((err_two, res_two) => {
                            expect(res_two.body.success).to.equal(false);
                            expect(res_two.body).to.have.property('dtg');
                            expect(res_two.body.error).to.equal('A memo referencing this hash already exists');
                            done();
                        })
            });
        });

        it('Saves a valid encrypted memo', (done) => {
            const memo = new NanoMemoTools.memo.Memo(
                hash,
                message,
                accounts[0].address
            );
            const encrypted_memo = NanoMemoTools.memo.encrypt(memo, accounts[0].private_key, accounts[1].address);
            encrypted_memo.sign(accounts[0].private_key);

            chai.request(www)
                .post('/api/memo/new')
                .send({
                    message: encrypted_memo.message,
                    hash: encrypted_memo.hash,
                    signing_address: encrypted_memo.signing_address,
                    signature: encrypted_memo.signature,
                    version_sign: memo.version_sign,
                    decrypting_address: encrypted_memo.decrypting_address,
                    version_encrypt: memo.version_encrypt
                })
                .end((err, res) => {
                    expect(res.body.success).to.equal(true);
                    expect(res.body).to.have.property('dtg');
                    expect(res.body).to.have.property('credits_balance');
                    expect(res.body).to.have.property('data');
                    expect(res.body.data).to.have.property('dtg');
                    expect(res.body.data.message).to.equal(encrypted_memo.message);
                    expect(res.body.data.message).to.not.equal(memo.message);
                    expect(res.body.data.hash).to.equal(encrypted_memo.hash);
                    expect(res.body.data.signature).to.equal(encrypted_memo.signature);
                    expect(res.body.data.version_sign).to.equal(encrypted_memo.version_sign);
                    expect(res.body.data.signing_address).to.equal(encrypted_memo.signing_address);
                    done();
            });
        });

        it('Saves a encrypted memo with invalid version_encrypt', (done) => {
            const memo = new NanoMemoTools.memo.Memo(
                hash,
                message,
                accounts[0].address
            );
            const encrypted_memo = NanoMemoTools.memo.encrypt(memo, accounts[0].private_key, accounts[1].address);
            encrypted_memo.sign(accounts[0].private_key);

            chai.request(www)
                .post('/api/memo/new')
                .send({
                    message: encrypted_memo.message,
                    hash: encrypted_memo.hash,
                    signing_address: encrypted_memo.signing_address,
                    signature: encrypted_memo.signature,
                    version_sign: memo.version_sign,
                    decrypting_address: encrypted_memo.decrypting_address,
                    version_encrypt: 12345
                })
                .end((err, res) => {
                    expect(res.body.success).to.equal(false);
                    expect(res.body).to.have.property('dtg');
                    expect(res.body.error).to.equal('Invalid version_encrypt value. Must use: 1');
                    done();
            });
        });

    });


    describe("/api/memo/blocks", () => {

        it('Retrieve a non-existent hash', (done) => {
            chai.request(www)
                .post('/api/memo/blocks')
                .send({hashes: [hash]})
                .end((err, res) => {
                    expect(res).to.have.status(200);
                    expect(res.body.success).to.equal(true);
                    expect(res.body).to.have.property('dtg');
                    expect(res.body).to.have.property('data');
                    expect(Object.keys(res.body.data).length).to.equal(0);
                    done();
            });
        });

        it('Retrieve an existing memo', (done) => {
            const memo = new NanoMemoTools.memo.Memo(
                hash,
                message,
                accounts[0].address
            );
            memo.sign(accounts[0].private_key);

            // Save memo first
            chai.request(www)
                .post('/api/memo/new')
                .send({
                    message: memo.message,
                    hash: memo.hash,
                    signing_address: memo.signing_address,
                    signature: memo.signature,
                    version_sign: memo.version_sign,
                })
                .end((err, res) => {
                    expect(res.body.success).to.equal(true);

                    // Now check if memo can be retrieved
                    chai.request(www)
                        .post('/api/memo/blocks')
                        .send({hashes: [res.body.data.hash]})
                        .end((err_two, res_two) => {
                            expect(res_two).to.have.status(200);
                            expect(res_two.body.success).to.equal(true);
                            expect(res_two.body).to.have.property('dtg');
                            expect(res_two.body).to.have.property('data');
                            expect(res_two.body.data).to.have.property(memo.hash);
                            expect(res_two.body.data[memo.hash].hash).to.equal(memo.hash);
                            expect(res_two.body.data[memo.hash].message).to.equal(memo.message);
                            expect(res_two.body.data[memo.hash].signature).to.equal(memo.signature);
                            expect(res_two.body.data[memo.hash].signing_address).to.equal(memo.signing_address);
                            done();
                        })
            });
        });

    });
});