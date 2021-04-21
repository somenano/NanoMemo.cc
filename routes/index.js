const express = require('express');
const router = express.Router();
const axios = require('axios');
const memo = require('../models/memo');
const DB = require('../helpers/db_query');
const NanoMemoTools = require('nanomemotools');
const NanoCurrency = require('nanocurrency');
const www = require('../bin/www');


/* GET home page. */
router.get('/', async function(req, res, next) {
  let recent_memos = [];
  recent_memos = await DB.get_recent_memos(3).catch(function(e) {
    console.error('In index.js router.get /, error caught while running DB.get_recent_memos(3)');
    console.error(e);
  });

  return res.render('index', {
    title: 'NanoMemo.cc - Cryptographically secure memos for every Nano block',
    page: 'home',
    url: process.env.URL,
    recent_memos: recent_memos
  });
});

router.get('/docs', async function(req, res, next) {
  return res.render('docs', {
    title: 'Docs | NanoMemo.cc',
    page: 'docs',
    url: process.env.URL,
  });
});

router.get('/docs/api', async function(req, res, next) {
  return res.render('docs_api', {
    title: 'RESTful API Documentation | NanoMemo.cc',
    page: 'docs',
    url: process.env.URL,
    wss: process.env.WSS,
    message_max_length: process.env.MESSAGE_LENGTH,
    NanoMemoTools: NanoMemoTools
  });
});

router.get('/block/:hash', async function(req, res, next) {
  const hash = req.params.hash;

  let memo = undefined;
  let block = undefined;

  try {
    if (NanoMemoTools.memo.validateHash(hash)) {
      block = await NanoMemoTools.node.block_info(hash, process.env.NODE_RPC_PROXY, process.env.NODE_RPC_USER, process.env.NODE_RPC_PASSWORD);
      if (block.error) {
        block = undefined;
      } else {
        memo = await DB.get_memo_from_hash(hash);
      }
    }
  } catch(e) {
    console.error('In /block/:hash, caught error');
    console.error(e);
  }

  return res.render('block', {
    title: 'Block '+ hash + ' | NanoMemo.cc',
    page: 'block',
    hash: hash,
    block: block,
    memo: memo,
    NanoMemoTools: NanoMemoTools,
    NanoCurrency: NanoCurrency,
    url: process.env.URL,
  });
});

router.get('/write', async function(req, res, next) {
  const hash = req.query.hash;
  const message = req.query.message;
  const decrypting_address = req.query.decrypting_address;

  return res.render('write', {
    title: 'Write Memo | NanoMemo.cc',
    page: 'write',
    message_max_length: process.env.MESSAGE_LENGTH,
    url: process.env.URL,
    hash: hash,
    message: message,
    decrypting_address: decrypting_address,
    ip_credits: www.ipCredits(req.ip)
  });
});

router.get('/tos', async function(req, res, next) {
  return res.render('tos', {
    title: 'Terms of Service | NanoMemo.cc',
    page: 'tos',
  }); 
});

router.get('/contact', async function(req, res, next) {
  return res.render('contact', {
    title: 'Contact | NanoMemo.cc',
    page: 'contact',
  }); 
});

router.get('/api', async function(req, res, next) {
  return res.render('api', {
    title: 'API | NanoMemo.cc',
    page: 'api',
    user_daily_credits: process.env.USER_DAILY_CREDITS,
    ip_credits: www.ipCredits(req.ip)
  }); 
});

router.get('/api/request', async function(req, res, next) {
  return res.render('api_request', {
    title: 'API Request | NanoMemo.cc',
    page: 'api'
  });
});

router.get('/tools/memo-validator', async function(req, res, next) {
  const hash = req.query.hash;
  const message = req.query.message;
  const signing_address = req.query.signing_address;
  const signature = req.query.signature;

  return res.render('memo_validator', {
    title: 'Memo Validator | Tools | NanoMemo.cc',
    page: 'tools',
    message_max_length: process.env.MESSAGE_LENGTH,
    hash: hash,
    message: message,
    signing_address: signing_address,
    signature: signature
  });
});

router.get('/tools/key-derivations', async function(req, res, next) {

  return res.render('key_derivations', {
    title: 'Seed/Key/Address Derivations | Tools | NanoMemo.cc',
    page: 'tools',
  }); 
});

module.exports = router;
