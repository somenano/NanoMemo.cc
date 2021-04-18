(function(f){if(typeof exports==="object"&&typeof module!=="undefined"){module.exports=f()}else if(typeof define==="function"&&define.amd){define([],f)}else{var g;if(typeof window!=="undefined"){g=window}else if(typeof global!=="undefined"){g=global}else if(typeof self!=="undefined"){g=self}else{g=this}g.NanoMemoTools = f()}})(function(){var define,module,exports;return (function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
/**
 * NanoMemoTools module
 * @module NanoMemoTools
 * @see module:NanoMemoTools/version
 * @see module:NanoMemoTools/tools
 * @see module:NanoMemoTools/server
 * @see module:NanoMemoTools/node
 * @see module:NanoMemoTools/memo
 * @see module:NanoMemoTools/network
 */

const version = require('./src/version');
const tools = require('./src/tools');
const server = require('./src/server');
const node = require('./src/node');
const memo = require('./src/memo');
const network = require('./src/network');

module.exports = {
  version,
  tools,
  server,
  node,
  memo,
  network
};
},{"./src/memo":36,"./src/network":37,"./src/node":38,"./src/server":39,"./src/tools":40,"./src/version":41}],2:[function(require,module,exports){
/*
 * ed2curve: convert Ed25519 signing key pair into Curve25519
 * key pair suitable for Diffie-Hellman key exchange.
 *
 * Written by Dmitry Chestnykh in 2014. Public domain.
 */
/* jshint newcap: false */
(function(root, f) {
  'use strict';
  if (typeof module !== 'undefined' && module.exports) module.exports = f(require('tweetnacl-blake2b'));
  else root.ed2curve = f(root.nacl);
}(this, function(nacl) {
  'use strict';
  if (!nacl) throw new Error('tweetnacl not loaded');

  // -- Operations copied from TweetNaCl.js. --

  var gf = function(init) {
    var i, r = new Float64Array(16);
    if (init) for (i = 0; i < init.length; i++) r[i] = init[i];
    return r;
  };

  var gf0 = gf(),
      gf1 = gf([1]),
      D = gf([0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203]),
      I = gf([0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83]);

  function car25519(o) {
    var c;
    var i;
    for (i = 0; i < 16; i++) {
      o[i] += 65536;
      c = Math.floor(o[i] / 65536);
      o[(i+1)*(i<15?1:0)] += c - 1 + 37 * (c-1) * (i===15?1:0);
      o[i] -= (c * 65536);
    }
  }

  function sel25519(p, q, b) {
    var t, c = ~(b-1);
    for (var i = 0; i < 16; i++) {
      t = c & (p[i] ^ q[i]);
      p[i] ^= t;
      q[i] ^= t;
    }
  }

  function unpack25519(o, n) {
    var i;
    for (i = 0; i < 16; i++) o[i] = n[2*i] + (n[2*i+1] << 8);
    o[15] &= 0x7fff;
  }

  // addition
  function A(o, a, b) {
    var i;
    for (i = 0; i < 16; i++) o[i] = (a[i] + b[i])|0;
  }

  // subtraction
  function Z(o, a, b) {
    var i;
    for (i = 0; i < 16; i++) o[i] = (a[i] - b[i])|0;
  }

  // multiplication
  function M(o, a, b) {
    var i, j, t = new Float64Array(31);
    for (i = 0; i < 31; i++) t[i] = 0;
    for (i = 0; i < 16; i++) {
      for (j = 0; j < 16; j++) {
        t[i+j] += a[i] * b[j];
      }
    }
    for (i = 0; i < 15; i++) {
      t[i] += 38 * t[i+16];
    }
    for (i = 0; i < 16; i++) o[i] = t[i];
    car25519(o);
    car25519(o);
  }

  // squaring
  function S(o, a) {
    M(o, a, a);
  }

  // inversion
  function inv25519(o, i) {
    var c = gf();
    var a;
    for (a = 0; a < 16; a++) c[a] = i[a];
    for (a = 253; a >= 0; a--) {
      S(c, c);
      if(a !== 2 && a !== 4) M(c, c, i);
    }
    for (a = 0; a < 16; a++) o[a] = c[a];
  }

  function pack25519(o, n) {
    var i, j, b;
    var m = gf(), t = gf();
    for (i = 0; i < 16; i++) t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    for (j = 0; j < 2; j++) {
      m[0] = t[0] - 0xffed;
      for (i = 1; i < 15; i++) {
        m[i] = t[i] - 0xffff - ((m[i-1]>>16) & 1);
        m[i-1] &= 0xffff;
      }
      m[15] = t[15] - 0x7fff - ((m[14]>>16) & 1);
      b = (m[15]>>16) & 1;
      m[14] &= 0xffff;
      sel25519(t, m, 1-b);
    }
    for (i = 0; i < 16; i++) {
      o[2*i] = t[i] & 0xff;
      o[2*i+1] = t[i] >> 8;
    }
  }

  function par25519(a) {
    var d = new Uint8Array(32);
    pack25519(d, a);
    return d[0] & 1;
  }

  function vn(x, xi, y, yi, n) {
    var i, d = 0;
    for (i = 0; i < n; i++) d |= x[xi + i] ^ y[yi + i];
    return (1 & ((d - 1) >>> 8)) - 1;
  }

  function crypto_verify_32(x, xi, y, yi) {
    return vn(x, xi, y, yi, 32);
  }

  function neq25519(a, b) {
    var c = new Uint8Array(32), d = new Uint8Array(32);
    pack25519(c, a);
    pack25519(d, b);
    return crypto_verify_32(c, 0, d, 0);
  }

  function pow2523(o, i) {
    var c = gf();
    var a;
    for (a = 0; a < 16; a++) c[a] = i[a];
    for (a = 250; a >= 0; a--) {
      S(c, c);
      if (a !== 1) M(c, c, i);
    }
    for (a = 0; a < 16; a++) o[a] = c[a];
  }

  function set25519(r, a) {
    var i;
    for (i = 0; i < 16; i++) r[i] = a[i] | 0;
  }

  function unpackneg(r, p) {
    var t = gf(), chk = gf(), num = gf(),
      den = gf(), den2 = gf(), den4 = gf(),
      den6 = gf();

    set25519(r[2], gf1);
    unpack25519(r[1], p);
    S(num, r[1]);
    M(den, num, D);
    Z(num, num, r[2]);
    A(den, r[2], den);

    S(den2, den);
    S(den4, den2);
    M(den6, den4, den2);
    M(t, den6, num);
    M(t, t, den);

    pow2523(t, t);
    M(t, t, num);
    M(t, t, den);
    M(t, t, den);
    M(r[0], t, den);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) M(r[0], r[0], I);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num)) return -1;

    if (par25519(r[0]) === (p[31] >> 7)) Z(r[0], gf0, r[0]);

    M(r[3], r[0], r[1]);
    return 0;
  }

  // ----

  // Converts Ed25519 public key to Curve25519 public key.
  // montgomeryX = (edwardsY + 1)*inverse(1 - edwardsY) mod p
  function convertPublicKey(pk) {
    var z = new Uint8Array(32),
      q = [gf(), gf(), gf(), gf()],
      a = gf(), b = gf();

    if (unpackneg(q, pk)) return null; // reject invalid key

    var y = q[1];

    A(a, gf1, y);
    Z(b, gf1, y);
    inv25519(b, b);
    M(a, a, b);

    pack25519(z, a);
    return z;
  }

  // Converts Ed25519 secret key to Curve25519 secret key.
  function convertSecretKey(sk) {
    var d = new Uint8Array(64), o = new Uint8Array(32), i;
    nacl.lowlevel.crypto_hash(d, sk, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;
    for (i = 0; i < 32; i++) o[i] = d[i];
    for (i = 0; i < 64; i++) d[i] = 0;
    return o;
  }

  function convertKeyPair(edKeyPair) {
    var publicKey = convertPublicKey(edKeyPair.publicKey);
    if (!publicKey) return null;
    return {
      publicKey: publicKey,
      secretKey: convertSecretKey(edKeyPair.secretKey)
    };
  }

  return {
    convertPublicKey: convertPublicKey,
    convertSecretKey: convertSecretKey,
    convertKeyPair: convertKeyPair,
  };

}));

},{"tweetnacl-blake2b":34}],3:[function(require,module,exports){
module.exports = require('./lib/axios');
},{"./lib/axios":5}],4:[function(require,module,exports){
'use strict';

var utils = require('./../utils');
var settle = require('./../core/settle');
var cookies = require('./../helpers/cookies');
var buildURL = require('./../helpers/buildURL');
var buildFullPath = require('../core/buildFullPath');
var parseHeaders = require('./../helpers/parseHeaders');
var isURLSameOrigin = require('./../helpers/isURLSameOrigin');
var createError = require('../core/createError');

module.exports = function xhrAdapter(config) {
  return new Promise(function dispatchXhrRequest(resolve, reject) {
    var requestData = config.data;
    var requestHeaders = config.headers;

    if (utils.isFormData(requestData)) {
      delete requestHeaders['Content-Type']; // Let the browser set it
    }

    var request = new XMLHttpRequest();

    // HTTP basic authentication
    if (config.auth) {
      var username = config.auth.username || '';
      var password = config.auth.password ? unescape(encodeURIComponent(config.auth.password)) : '';
      requestHeaders.Authorization = 'Basic ' + btoa(username + ':' + password);
    }

    var fullPath = buildFullPath(config.baseURL, config.url);
    request.open(config.method.toUpperCase(), buildURL(fullPath, config.params, config.paramsSerializer), true);

    // Set the request timeout in MS
    request.timeout = config.timeout;

    // Listen for ready state
    request.onreadystatechange = function handleLoad() {
      if (!request || request.readyState !== 4) {
        return;
      }

      // The request errored out and we didn't get a response, this will be
      // handled by onerror instead
      // With one exception: request that using file: protocol, most browsers
      // will return status as 0 even though it's a successful request
      if (request.status === 0 && !(request.responseURL && request.responseURL.indexOf('file:') === 0)) {
        return;
      }

      // Prepare the response
      var responseHeaders = 'getAllResponseHeaders' in request ? parseHeaders(request.getAllResponseHeaders()) : null;
      var responseData = !config.responseType || config.responseType === 'text' ? request.responseText : request.response;
      var response = {
        data: responseData,
        status: request.status,
        statusText: request.statusText,
        headers: responseHeaders,
        config: config,
        request: request
      };

      settle(resolve, reject, response);

      // Clean up request
      request = null;
    };

    // Handle browser request cancellation (as opposed to a manual cancellation)
    request.onabort = function handleAbort() {
      if (!request) {
        return;
      }

      reject(createError('Request aborted', config, 'ECONNABORTED', request));

      // Clean up request
      request = null;
    };

    // Handle low level network errors
    request.onerror = function handleError() {
      // Real errors are hidden from us by the browser
      // onerror should only fire if it's a network error
      reject(createError('Network Error', config, null, request));

      // Clean up request
      request = null;
    };

    // Handle timeout
    request.ontimeout = function handleTimeout() {
      var timeoutErrorMessage = 'timeout of ' + config.timeout + 'ms exceeded';
      if (config.timeoutErrorMessage) {
        timeoutErrorMessage = config.timeoutErrorMessage;
      }
      reject(createError(timeoutErrorMessage, config, 'ECONNABORTED',
        request));

      // Clean up request
      request = null;
    };

    // Add xsrf header
    // This is only done if running in a standard browser environment.
    // Specifically not if we're in a web worker, or react-native.
    if (utils.isStandardBrowserEnv()) {
      // Add xsrf header
      var xsrfValue = (config.withCredentials || isURLSameOrigin(fullPath)) && config.xsrfCookieName ?
        cookies.read(config.xsrfCookieName) :
        undefined;

      if (xsrfValue) {
        requestHeaders[config.xsrfHeaderName] = xsrfValue;
      }
    }

    // Add headers to the request
    if ('setRequestHeader' in request) {
      utils.forEach(requestHeaders, function setRequestHeader(val, key) {
        if (typeof requestData === 'undefined' && key.toLowerCase() === 'content-type') {
          // Remove Content-Type if data is undefined
          delete requestHeaders[key];
        } else {
          // Otherwise add header to the request
          request.setRequestHeader(key, val);
        }
      });
    }

    // Add withCredentials to request if needed
    if (!utils.isUndefined(config.withCredentials)) {
      request.withCredentials = !!config.withCredentials;
    }

    // Add responseType to request if needed
    if (config.responseType) {
      try {
        request.responseType = config.responseType;
      } catch (e) {
        // Expected DOMException thrown by browsers not compatible XMLHttpRequest Level 2.
        // But, this can be suppressed for 'json' type as it can be parsed by default 'transformResponse' function.
        if (config.responseType !== 'json') {
          throw e;
        }
      }
    }

    // Handle progress if needed
    if (typeof config.onDownloadProgress === 'function') {
      request.addEventListener('progress', config.onDownloadProgress);
    }

    // Not all browsers support upload events
    if (typeof config.onUploadProgress === 'function' && request.upload) {
      request.upload.addEventListener('progress', config.onUploadProgress);
    }

    if (config.cancelToken) {
      // Handle cancellation
      config.cancelToken.promise.then(function onCanceled(cancel) {
        if (!request) {
          return;
        }

        request.abort();
        reject(cancel);
        // Clean up request
        request = null;
      });
    }

    if (!requestData) {
      requestData = null;
    }

    // Send the request
    request.send(requestData);
  });
};

},{"../core/buildFullPath":11,"../core/createError":12,"./../core/settle":16,"./../helpers/buildURL":20,"./../helpers/cookies":22,"./../helpers/isURLSameOrigin":25,"./../helpers/parseHeaders":27,"./../utils":29}],5:[function(require,module,exports){
'use strict';

var utils = require('./utils');
var bind = require('./helpers/bind');
var Axios = require('./core/Axios');
var mergeConfig = require('./core/mergeConfig');
var defaults = require('./defaults');

/**
 * Create an instance of Axios
 *
 * @param {Object} defaultConfig The default config for the instance
 * @return {Axios} A new instance of Axios
 */
function createInstance(defaultConfig) {
  var context = new Axios(defaultConfig);
  var instance = bind(Axios.prototype.request, context);

  // Copy axios.prototype to instance
  utils.extend(instance, Axios.prototype, context);

  // Copy context to instance
  utils.extend(instance, context);

  return instance;
}

// Create the default instance to be exported
var axios = createInstance(defaults);

// Expose Axios class to allow class inheritance
axios.Axios = Axios;

// Factory for creating new instances
axios.create = function create(instanceConfig) {
  return createInstance(mergeConfig(axios.defaults, instanceConfig));
};

// Expose Cancel & CancelToken
axios.Cancel = require('./cancel/Cancel');
axios.CancelToken = require('./cancel/CancelToken');
axios.isCancel = require('./cancel/isCancel');

// Expose all/spread
axios.all = function all(promises) {
  return Promise.all(promises);
};
axios.spread = require('./helpers/spread');

// Expose isAxiosError
axios.isAxiosError = require('./helpers/isAxiosError');

module.exports = axios;

// Allow use of default import syntax in TypeScript
module.exports.default = axios;

},{"./cancel/Cancel":6,"./cancel/CancelToken":7,"./cancel/isCancel":8,"./core/Axios":9,"./core/mergeConfig":15,"./defaults":18,"./helpers/bind":19,"./helpers/isAxiosError":24,"./helpers/spread":28,"./utils":29}],6:[function(require,module,exports){
'use strict';

/**
 * A `Cancel` is an object that is thrown when an operation is canceled.
 *
 * @class
 * @param {string=} message The message.
 */
function Cancel(message) {
  this.message = message;
}

Cancel.prototype.toString = function toString() {
  return 'Cancel' + (this.message ? ': ' + this.message : '');
};

Cancel.prototype.__CANCEL__ = true;

module.exports = Cancel;

},{}],7:[function(require,module,exports){
'use strict';

var Cancel = require('./Cancel');

/**
 * A `CancelToken` is an object that can be used to request cancellation of an operation.
 *
 * @class
 * @param {Function} executor The executor function.
 */
function CancelToken(executor) {
  if (typeof executor !== 'function') {
    throw new TypeError('executor must be a function.');
  }

  var resolvePromise;
  this.promise = new Promise(function promiseExecutor(resolve) {
    resolvePromise = resolve;
  });

  var token = this;
  executor(function cancel(message) {
    if (token.reason) {
      // Cancellation has already been requested
      return;
    }

    token.reason = new Cancel(message);
    resolvePromise(token.reason);
  });
}

/**
 * Throws a `Cancel` if cancellation has been requested.
 */
CancelToken.prototype.throwIfRequested = function throwIfRequested() {
  if (this.reason) {
    throw this.reason;
  }
};

/**
 * Returns an object that contains a new `CancelToken` and a function that, when called,
 * cancels the `CancelToken`.
 */
CancelToken.source = function source() {
  var cancel;
  var token = new CancelToken(function executor(c) {
    cancel = c;
  });
  return {
    token: token,
    cancel: cancel
  };
};

module.exports = CancelToken;

},{"./Cancel":6}],8:[function(require,module,exports){
'use strict';

module.exports = function isCancel(value) {
  return !!(value && value.__CANCEL__);
};

},{}],9:[function(require,module,exports){
'use strict';

var utils = require('./../utils');
var buildURL = require('../helpers/buildURL');
var InterceptorManager = require('./InterceptorManager');
var dispatchRequest = require('./dispatchRequest');
var mergeConfig = require('./mergeConfig');

/**
 * Create a new instance of Axios
 *
 * @param {Object} instanceConfig The default config for the instance
 */
function Axios(instanceConfig) {
  this.defaults = instanceConfig;
  this.interceptors = {
    request: new InterceptorManager(),
    response: new InterceptorManager()
  };
}

/**
 * Dispatch a request
 *
 * @param {Object} config The config specific for this request (merged with this.defaults)
 */
Axios.prototype.request = function request(config) {
  /*eslint no-param-reassign:0*/
  // Allow for axios('example/url'[, config]) a la fetch API
  if (typeof config === 'string') {
    config = arguments[1] || {};
    config.url = arguments[0];
  } else {
    config = config || {};
  }

  config = mergeConfig(this.defaults, config);

  // Set config.method
  if (config.method) {
    config.method = config.method.toLowerCase();
  } else if (this.defaults.method) {
    config.method = this.defaults.method.toLowerCase();
  } else {
    config.method = 'get';
  }

  // Hook up interceptors middleware
  var chain = [dispatchRequest, undefined];
  var promise = Promise.resolve(config);

  this.interceptors.request.forEach(function unshiftRequestInterceptors(interceptor) {
    chain.unshift(interceptor.fulfilled, interceptor.rejected);
  });

  this.interceptors.response.forEach(function pushResponseInterceptors(interceptor) {
    chain.push(interceptor.fulfilled, interceptor.rejected);
  });

  while (chain.length) {
    promise = promise.then(chain.shift(), chain.shift());
  }

  return promise;
};

Axios.prototype.getUri = function getUri(config) {
  config = mergeConfig(this.defaults, config);
  return buildURL(config.url, config.params, config.paramsSerializer).replace(/^\?/, '');
};

// Provide aliases for supported request methods
utils.forEach(['delete', 'get', 'head', 'options'], function forEachMethodNoData(method) {
  /*eslint func-names:0*/
  Axios.prototype[method] = function(url, config) {
    return this.request(mergeConfig(config || {}, {
      method: method,
      url: url,
      data: (config || {}).data
    }));
  };
});

utils.forEach(['post', 'put', 'patch'], function forEachMethodWithData(method) {
  /*eslint func-names:0*/
  Axios.prototype[method] = function(url, data, config) {
    return this.request(mergeConfig(config || {}, {
      method: method,
      url: url,
      data: data
    }));
  };
});

module.exports = Axios;

},{"../helpers/buildURL":20,"./../utils":29,"./InterceptorManager":10,"./dispatchRequest":13,"./mergeConfig":15}],10:[function(require,module,exports){
'use strict';

var utils = require('./../utils');

function InterceptorManager() {
  this.handlers = [];
}

/**
 * Add a new interceptor to the stack
 *
 * @param {Function} fulfilled The function to handle `then` for a `Promise`
 * @param {Function} rejected The function to handle `reject` for a `Promise`
 *
 * @return {Number} An ID used to remove interceptor later
 */
InterceptorManager.prototype.use = function use(fulfilled, rejected) {
  this.handlers.push({
    fulfilled: fulfilled,
    rejected: rejected
  });
  return this.handlers.length - 1;
};

/**
 * Remove an interceptor from the stack
 *
 * @param {Number} id The ID that was returned by `use`
 */
InterceptorManager.prototype.eject = function eject(id) {
  if (this.handlers[id]) {
    this.handlers[id] = null;
  }
};

/**
 * Iterate over all the registered interceptors
 *
 * This method is particularly useful for skipping over any
 * interceptors that may have become `null` calling `eject`.
 *
 * @param {Function} fn The function to call for each interceptor
 */
InterceptorManager.prototype.forEach = function forEach(fn) {
  utils.forEach(this.handlers, function forEachHandler(h) {
    if (h !== null) {
      fn(h);
    }
  });
};

module.exports = InterceptorManager;

},{"./../utils":29}],11:[function(require,module,exports){
'use strict';

var isAbsoluteURL = require('../helpers/isAbsoluteURL');
var combineURLs = require('../helpers/combineURLs');

/**
 * Creates a new URL by combining the baseURL with the requestedURL,
 * only when the requestedURL is not already an absolute URL.
 * If the requestURL is absolute, this function returns the requestedURL untouched.
 *
 * @param {string} baseURL The base URL
 * @param {string} requestedURL Absolute or relative URL to combine
 * @returns {string} The combined full path
 */
module.exports = function buildFullPath(baseURL, requestedURL) {
  if (baseURL && !isAbsoluteURL(requestedURL)) {
    return combineURLs(baseURL, requestedURL);
  }
  return requestedURL;
};

},{"../helpers/combineURLs":21,"../helpers/isAbsoluteURL":23}],12:[function(require,module,exports){
'use strict';

var enhanceError = require('./enhanceError');

/**
 * Create an Error with the specified message, config, error code, request and response.
 *
 * @param {string} message The error message.
 * @param {Object} config The config.
 * @param {string} [code] The error code (for example, 'ECONNABORTED').
 * @param {Object} [request] The request.
 * @param {Object} [response] The response.
 * @returns {Error} The created error.
 */
module.exports = function createError(message, config, code, request, response) {
  var error = new Error(message);
  return enhanceError(error, config, code, request, response);
};

},{"./enhanceError":14}],13:[function(require,module,exports){
'use strict';

var utils = require('./../utils');
var transformData = require('./transformData');
var isCancel = require('../cancel/isCancel');
var defaults = require('../defaults');

/**
 * Throws a `Cancel` if cancellation has been requested.
 */
function throwIfCancellationRequested(config) {
  if (config.cancelToken) {
    config.cancelToken.throwIfRequested();
  }
}

/**
 * Dispatch a request to the server using the configured adapter.
 *
 * @param {object} config The config that is to be used for the request
 * @returns {Promise} The Promise to be fulfilled
 */
module.exports = function dispatchRequest(config) {
  throwIfCancellationRequested(config);

  // Ensure headers exist
  config.headers = config.headers || {};

  // Transform request data
  config.data = transformData(
    config.data,
    config.headers,
    config.transformRequest
  );

  // Flatten headers
  config.headers = utils.merge(
    config.headers.common || {},
    config.headers[config.method] || {},
    config.headers
  );

  utils.forEach(
    ['delete', 'get', 'head', 'post', 'put', 'patch', 'common'],
    function cleanHeaderConfig(method) {
      delete config.headers[method];
    }
  );

  var adapter = config.adapter || defaults.adapter;

  return adapter(config).then(function onAdapterResolution(response) {
    throwIfCancellationRequested(config);

    // Transform response data
    response.data = transformData(
      response.data,
      response.headers,
      config.transformResponse
    );

    return response;
  }, function onAdapterRejection(reason) {
    if (!isCancel(reason)) {
      throwIfCancellationRequested(config);

      // Transform response data
      if (reason && reason.response) {
        reason.response.data = transformData(
          reason.response.data,
          reason.response.headers,
          config.transformResponse
        );
      }
    }

    return Promise.reject(reason);
  });
};

},{"../cancel/isCancel":8,"../defaults":18,"./../utils":29,"./transformData":17}],14:[function(require,module,exports){
'use strict';

/**
 * Update an Error with the specified config, error code, and response.
 *
 * @param {Error} error The error to update.
 * @param {Object} config The config.
 * @param {string} [code] The error code (for example, 'ECONNABORTED').
 * @param {Object} [request] The request.
 * @param {Object} [response] The response.
 * @returns {Error} The error.
 */
module.exports = function enhanceError(error, config, code, request, response) {
  error.config = config;
  if (code) {
    error.code = code;
  }

  error.request = request;
  error.response = response;
  error.isAxiosError = true;

  error.toJSON = function toJSON() {
    return {
      // Standard
      message: this.message,
      name: this.name,
      // Microsoft
      description: this.description,
      number: this.number,
      // Mozilla
      fileName: this.fileName,
      lineNumber: this.lineNumber,
      columnNumber: this.columnNumber,
      stack: this.stack,
      // Axios
      config: this.config,
      code: this.code
    };
  };
  return error;
};

},{}],15:[function(require,module,exports){
'use strict';

var utils = require('../utils');

/**
 * Config-specific merge-function which creates a new config-object
 * by merging two configuration objects together.
 *
 * @param {Object} config1
 * @param {Object} config2
 * @returns {Object} New object resulting from merging config2 to config1
 */
module.exports = function mergeConfig(config1, config2) {
  // eslint-disable-next-line no-param-reassign
  config2 = config2 || {};
  var config = {};

  var valueFromConfig2Keys = ['url', 'method', 'data'];
  var mergeDeepPropertiesKeys = ['headers', 'auth', 'proxy', 'params'];
  var defaultToConfig2Keys = [
    'baseURL', 'transformRequest', 'transformResponse', 'paramsSerializer',
    'timeout', 'timeoutMessage', 'withCredentials', 'adapter', 'responseType', 'xsrfCookieName',
    'xsrfHeaderName', 'onUploadProgress', 'onDownloadProgress', 'decompress',
    'maxContentLength', 'maxBodyLength', 'maxRedirects', 'transport', 'httpAgent',
    'httpsAgent', 'cancelToken', 'socketPath', 'responseEncoding'
  ];
  var directMergeKeys = ['validateStatus'];

  function getMergedValue(target, source) {
    if (utils.isPlainObject(target) && utils.isPlainObject(source)) {
      return utils.merge(target, source);
    } else if (utils.isPlainObject(source)) {
      return utils.merge({}, source);
    } else if (utils.isArray(source)) {
      return source.slice();
    }
    return source;
  }

  function mergeDeepProperties(prop) {
    if (!utils.isUndefined(config2[prop])) {
      config[prop] = getMergedValue(config1[prop], config2[prop]);
    } else if (!utils.isUndefined(config1[prop])) {
      config[prop] = getMergedValue(undefined, config1[prop]);
    }
  }

  utils.forEach(valueFromConfig2Keys, function valueFromConfig2(prop) {
    if (!utils.isUndefined(config2[prop])) {
      config[prop] = getMergedValue(undefined, config2[prop]);
    }
  });

  utils.forEach(mergeDeepPropertiesKeys, mergeDeepProperties);

  utils.forEach(defaultToConfig2Keys, function defaultToConfig2(prop) {
    if (!utils.isUndefined(config2[prop])) {
      config[prop] = getMergedValue(undefined, config2[prop]);
    } else if (!utils.isUndefined(config1[prop])) {
      config[prop] = getMergedValue(undefined, config1[prop]);
    }
  });

  utils.forEach(directMergeKeys, function merge(prop) {
    if (prop in config2) {
      config[prop] = getMergedValue(config1[prop], config2[prop]);
    } else if (prop in config1) {
      config[prop] = getMergedValue(undefined, config1[prop]);
    }
  });

  var axiosKeys = valueFromConfig2Keys
    .concat(mergeDeepPropertiesKeys)
    .concat(defaultToConfig2Keys)
    .concat(directMergeKeys);

  var otherKeys = Object
    .keys(config1)
    .concat(Object.keys(config2))
    .filter(function filterAxiosKeys(key) {
      return axiosKeys.indexOf(key) === -1;
    });

  utils.forEach(otherKeys, mergeDeepProperties);

  return config;
};

},{"../utils":29}],16:[function(require,module,exports){
'use strict';

var createError = require('./createError');

/**
 * Resolve or reject a Promise based on response status.
 *
 * @param {Function} resolve A function that resolves the promise.
 * @param {Function} reject A function that rejects the promise.
 * @param {object} response The response.
 */
module.exports = function settle(resolve, reject, response) {
  var validateStatus = response.config.validateStatus;
  if (!response.status || !validateStatus || validateStatus(response.status)) {
    resolve(response);
  } else {
    reject(createError(
      'Request failed with status code ' + response.status,
      response.config,
      null,
      response.request,
      response
    ));
  }
};

},{"./createError":12}],17:[function(require,module,exports){
'use strict';

var utils = require('./../utils');

/**
 * Transform the data for a request or a response
 *
 * @param {Object|String} data The data to be transformed
 * @param {Array} headers The headers for the request or response
 * @param {Array|Function} fns A single function or Array of functions
 * @returns {*} The resulting transformed data
 */
module.exports = function transformData(data, headers, fns) {
  /*eslint no-param-reassign:0*/
  utils.forEach(fns, function transform(fn) {
    data = fn(data, headers);
  });

  return data;
};

},{"./../utils":29}],18:[function(require,module,exports){
(function (process){(function (){
'use strict';

var utils = require('./utils');
var normalizeHeaderName = require('./helpers/normalizeHeaderName');

var DEFAULT_CONTENT_TYPE = {
  'Content-Type': 'application/x-www-form-urlencoded'
};

function setContentTypeIfUnset(headers, value) {
  if (!utils.isUndefined(headers) && utils.isUndefined(headers['Content-Type'])) {
    headers['Content-Type'] = value;
  }
}

function getDefaultAdapter() {
  var adapter;
  if (typeof XMLHttpRequest !== 'undefined') {
    // For browsers use XHR adapter
    adapter = require('./adapters/xhr');
  } else if (typeof process !== 'undefined' && Object.prototype.toString.call(process) === '[object process]') {
    // For node use HTTP adapter
    adapter = require('./adapters/http');
  }
  return adapter;
}

var defaults = {
  adapter: getDefaultAdapter(),

  transformRequest: [function transformRequest(data, headers) {
    normalizeHeaderName(headers, 'Accept');
    normalizeHeaderName(headers, 'Content-Type');
    if (utils.isFormData(data) ||
      utils.isArrayBuffer(data) ||
      utils.isBuffer(data) ||
      utils.isStream(data) ||
      utils.isFile(data) ||
      utils.isBlob(data)
    ) {
      return data;
    }
    if (utils.isArrayBufferView(data)) {
      return data.buffer;
    }
    if (utils.isURLSearchParams(data)) {
      setContentTypeIfUnset(headers, 'application/x-www-form-urlencoded;charset=utf-8');
      return data.toString();
    }
    if (utils.isObject(data)) {
      setContentTypeIfUnset(headers, 'application/json;charset=utf-8');
      return JSON.stringify(data);
    }
    return data;
  }],

  transformResponse: [function transformResponse(data) {
    /*eslint no-param-reassign:0*/
    if (typeof data === 'string') {
      try {
        data = JSON.parse(data);
      } catch (e) { /* Ignore */ }
    }
    return data;
  }],

  /**
   * A timeout in milliseconds to abort a request. If set to 0 (default) a
   * timeout is not created.
   */
  timeout: 0,

  xsrfCookieName: 'XSRF-TOKEN',
  xsrfHeaderName: 'X-XSRF-TOKEN',

  maxContentLength: -1,
  maxBodyLength: -1,

  validateStatus: function validateStatus(status) {
    return status >= 200 && status < 300;
  }
};

defaults.headers = {
  common: {
    'Accept': 'application/json, text/plain, */*'
  }
};

utils.forEach(['delete', 'get', 'head'], function forEachMethodNoData(method) {
  defaults.headers[method] = {};
});

utils.forEach(['post', 'put', 'patch'], function forEachMethodWithData(method) {
  defaults.headers[method] = utils.merge(DEFAULT_CONTENT_TYPE);
});

module.exports = defaults;

}).call(this)}).call(this,require('_process'))
},{"./adapters/http":4,"./adapters/xhr":4,"./helpers/normalizeHeaderName":26,"./utils":29,"_process":46}],19:[function(require,module,exports){
'use strict';

module.exports = function bind(fn, thisArg) {
  return function wrap() {
    var args = new Array(arguments.length);
    for (var i = 0; i < args.length; i++) {
      args[i] = arguments[i];
    }
    return fn.apply(thisArg, args);
  };
};

},{}],20:[function(require,module,exports){
'use strict';

var utils = require('./../utils');

function encode(val) {
  return encodeURIComponent(val).
    replace(/%3A/gi, ':').
    replace(/%24/g, '$').
    replace(/%2C/gi, ',').
    replace(/%20/g, '+').
    replace(/%5B/gi, '[').
    replace(/%5D/gi, ']');
}

/**
 * Build a URL by appending params to the end
 *
 * @param {string} url The base of the url (e.g., http://www.google.com)
 * @param {object} [params] The params to be appended
 * @returns {string} The formatted url
 */
module.exports = function buildURL(url, params, paramsSerializer) {
  /*eslint no-param-reassign:0*/
  if (!params) {
    return url;
  }

  var serializedParams;
  if (paramsSerializer) {
    serializedParams = paramsSerializer(params);
  } else if (utils.isURLSearchParams(params)) {
    serializedParams = params.toString();
  } else {
    var parts = [];

    utils.forEach(params, function serialize(val, key) {
      if (val === null || typeof val === 'undefined') {
        return;
      }

      if (utils.isArray(val)) {
        key = key + '[]';
      } else {
        val = [val];
      }

      utils.forEach(val, function parseValue(v) {
        if (utils.isDate(v)) {
          v = v.toISOString();
        } else if (utils.isObject(v)) {
          v = JSON.stringify(v);
        }
        parts.push(encode(key) + '=' + encode(v));
      });
    });

    serializedParams = parts.join('&');
  }

  if (serializedParams) {
    var hashmarkIndex = url.indexOf('#');
    if (hashmarkIndex !== -1) {
      url = url.slice(0, hashmarkIndex);
    }

    url += (url.indexOf('?') === -1 ? '?' : '&') + serializedParams;
  }

  return url;
};

},{"./../utils":29}],21:[function(require,module,exports){
'use strict';

/**
 * Creates a new URL by combining the specified URLs
 *
 * @param {string} baseURL The base URL
 * @param {string} relativeURL The relative URL
 * @returns {string} The combined URL
 */
module.exports = function combineURLs(baseURL, relativeURL) {
  return relativeURL
    ? baseURL.replace(/\/+$/, '') + '/' + relativeURL.replace(/^\/+/, '')
    : baseURL;
};

},{}],22:[function(require,module,exports){
'use strict';

var utils = require('./../utils');

module.exports = (
  utils.isStandardBrowserEnv() ?

  // Standard browser envs support document.cookie
    (function standardBrowserEnv() {
      return {
        write: function write(name, value, expires, path, domain, secure) {
          var cookie = [];
          cookie.push(name + '=' + encodeURIComponent(value));

          if (utils.isNumber(expires)) {
            cookie.push('expires=' + new Date(expires).toGMTString());
          }

          if (utils.isString(path)) {
            cookie.push('path=' + path);
          }

          if (utils.isString(domain)) {
            cookie.push('domain=' + domain);
          }

          if (secure === true) {
            cookie.push('secure');
          }

          document.cookie = cookie.join('; ');
        },

        read: function read(name) {
          var match = document.cookie.match(new RegExp('(^|;\\s*)(' + name + ')=([^;]*)'));
          return (match ? decodeURIComponent(match[3]) : null);
        },

        remove: function remove(name) {
          this.write(name, '', Date.now() - 86400000);
        }
      };
    })() :

  // Non standard browser env (web workers, react-native) lack needed support.
    (function nonStandardBrowserEnv() {
      return {
        write: function write() {},
        read: function read() { return null; },
        remove: function remove() {}
      };
    })()
);

},{"./../utils":29}],23:[function(require,module,exports){
'use strict';

/**
 * Determines whether the specified URL is absolute
 *
 * @param {string} url The URL to test
 * @returns {boolean} True if the specified URL is absolute, otherwise false
 */
module.exports = function isAbsoluteURL(url) {
  // A URL is considered absolute if it begins with "<scheme>://" or "//" (protocol-relative URL).
  // RFC 3986 defines scheme name as a sequence of characters beginning with a letter and followed
  // by any combination of letters, digits, plus, period, or hyphen.
  return /^([a-z][a-z\d\+\-\.]*:)?\/\//i.test(url);
};

},{}],24:[function(require,module,exports){
'use strict';

/**
 * Determines whether the payload is an error thrown by Axios
 *
 * @param {*} payload The value to test
 * @returns {boolean} True if the payload is an error thrown by Axios, otherwise false
 */
module.exports = function isAxiosError(payload) {
  return (typeof payload === 'object') && (payload.isAxiosError === true);
};

},{}],25:[function(require,module,exports){
'use strict';

var utils = require('./../utils');

module.exports = (
  utils.isStandardBrowserEnv() ?

  // Standard browser envs have full support of the APIs needed to test
  // whether the request URL is of the same origin as current location.
    (function standardBrowserEnv() {
      var msie = /(msie|trident)/i.test(navigator.userAgent);
      var urlParsingNode = document.createElement('a');
      var originURL;

      /**
    * Parse a URL to discover it's components
    *
    * @param {String} url The URL to be parsed
    * @returns {Object}
    */
      function resolveURL(url) {
        var href = url;

        if (msie) {
        // IE needs attribute set twice to normalize properties
          urlParsingNode.setAttribute('href', href);
          href = urlParsingNode.href;
        }

        urlParsingNode.setAttribute('href', href);

        // urlParsingNode provides the UrlUtils interface - http://url.spec.whatwg.org/#urlutils
        return {
          href: urlParsingNode.href,
          protocol: urlParsingNode.protocol ? urlParsingNode.protocol.replace(/:$/, '') : '',
          host: urlParsingNode.host,
          search: urlParsingNode.search ? urlParsingNode.search.replace(/^\?/, '') : '',
          hash: urlParsingNode.hash ? urlParsingNode.hash.replace(/^#/, '') : '',
          hostname: urlParsingNode.hostname,
          port: urlParsingNode.port,
          pathname: (urlParsingNode.pathname.charAt(0) === '/') ?
            urlParsingNode.pathname :
            '/' + urlParsingNode.pathname
        };
      }

      originURL = resolveURL(window.location.href);

      /**
    * Determine if a URL shares the same origin as the current location
    *
    * @param {String} requestURL The URL to test
    * @returns {boolean} True if URL shares the same origin, otherwise false
    */
      return function isURLSameOrigin(requestURL) {
        var parsed = (utils.isString(requestURL)) ? resolveURL(requestURL) : requestURL;
        return (parsed.protocol === originURL.protocol &&
            parsed.host === originURL.host);
      };
    })() :

  // Non standard browser envs (web workers, react-native) lack needed support.
    (function nonStandardBrowserEnv() {
      return function isURLSameOrigin() {
        return true;
      };
    })()
);

},{"./../utils":29}],26:[function(require,module,exports){
'use strict';

var utils = require('../utils');

module.exports = function normalizeHeaderName(headers, normalizedName) {
  utils.forEach(headers, function processHeader(value, name) {
    if (name !== normalizedName && name.toUpperCase() === normalizedName.toUpperCase()) {
      headers[normalizedName] = value;
      delete headers[name];
    }
  });
};

},{"../utils":29}],27:[function(require,module,exports){
'use strict';

var utils = require('./../utils');

// Headers whose duplicates are ignored by node
// c.f. https://nodejs.org/api/http.html#http_message_headers
var ignoreDuplicateOf = [
  'age', 'authorization', 'content-length', 'content-type', 'etag',
  'expires', 'from', 'host', 'if-modified-since', 'if-unmodified-since',
  'last-modified', 'location', 'max-forwards', 'proxy-authorization',
  'referer', 'retry-after', 'user-agent'
];

/**
 * Parse headers into an object
 *
 * ```
 * Date: Wed, 27 Aug 2014 08:58:49 GMT
 * Content-Type: application/json
 * Connection: keep-alive
 * Transfer-Encoding: chunked
 * ```
 *
 * @param {String} headers Headers needing to be parsed
 * @returns {Object} Headers parsed into an object
 */
module.exports = function parseHeaders(headers) {
  var parsed = {};
  var key;
  var val;
  var i;

  if (!headers) { return parsed; }

  utils.forEach(headers.split('\n'), function parser(line) {
    i = line.indexOf(':');
    key = utils.trim(line.substr(0, i)).toLowerCase();
    val = utils.trim(line.substr(i + 1));

    if (key) {
      if (parsed[key] && ignoreDuplicateOf.indexOf(key) >= 0) {
        return;
      }
      if (key === 'set-cookie') {
        parsed[key] = (parsed[key] ? parsed[key] : []).concat([val]);
      } else {
        parsed[key] = parsed[key] ? parsed[key] + ', ' + val : val;
      }
    }
  });

  return parsed;
};

},{"./../utils":29}],28:[function(require,module,exports){
'use strict';

/**
 * Syntactic sugar for invoking a function and expanding an array for arguments.
 *
 * Common use case would be to use `Function.prototype.apply`.
 *
 *  ```js
 *  function f(x, y, z) {}
 *  var args = [1, 2, 3];
 *  f.apply(null, args);
 *  ```
 *
 * With `spread` this example can be re-written.
 *
 *  ```js
 *  spread(function(x, y, z) {})([1, 2, 3]);
 *  ```
 *
 * @param {Function} callback
 * @returns {Function}
 */
module.exports = function spread(callback) {
  return function wrap(arr) {
    return callback.apply(null, arr);
  };
};

},{}],29:[function(require,module,exports){
'use strict';

var bind = require('./helpers/bind');

/*global toString:true*/

// utils is a library of generic helper functions non-specific to axios

var toString = Object.prototype.toString;

/**
 * Determine if a value is an Array
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is an Array, otherwise false
 */
function isArray(val) {
  return toString.call(val) === '[object Array]';
}

/**
 * Determine if a value is undefined
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if the value is undefined, otherwise false
 */
function isUndefined(val) {
  return typeof val === 'undefined';
}

/**
 * Determine if a value is a Buffer
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is a Buffer, otherwise false
 */
function isBuffer(val) {
  return val !== null && !isUndefined(val) && val.constructor !== null && !isUndefined(val.constructor)
    && typeof val.constructor.isBuffer === 'function' && val.constructor.isBuffer(val);
}

/**
 * Determine if a value is an ArrayBuffer
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is an ArrayBuffer, otherwise false
 */
function isArrayBuffer(val) {
  return toString.call(val) === '[object ArrayBuffer]';
}

/**
 * Determine if a value is a FormData
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is an FormData, otherwise false
 */
function isFormData(val) {
  return (typeof FormData !== 'undefined') && (val instanceof FormData);
}

/**
 * Determine if a value is a view on an ArrayBuffer
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is a view on an ArrayBuffer, otherwise false
 */
function isArrayBufferView(val) {
  var result;
  if ((typeof ArrayBuffer !== 'undefined') && (ArrayBuffer.isView)) {
    result = ArrayBuffer.isView(val);
  } else {
    result = (val) && (val.buffer) && (val.buffer instanceof ArrayBuffer);
  }
  return result;
}

/**
 * Determine if a value is a String
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is a String, otherwise false
 */
function isString(val) {
  return typeof val === 'string';
}

/**
 * Determine if a value is a Number
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is a Number, otherwise false
 */
function isNumber(val) {
  return typeof val === 'number';
}

/**
 * Determine if a value is an Object
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is an Object, otherwise false
 */
function isObject(val) {
  return val !== null && typeof val === 'object';
}

/**
 * Determine if a value is a plain Object
 *
 * @param {Object} val The value to test
 * @return {boolean} True if value is a plain Object, otherwise false
 */
function isPlainObject(val) {
  if (toString.call(val) !== '[object Object]') {
    return false;
  }

  var prototype = Object.getPrototypeOf(val);
  return prototype === null || prototype === Object.prototype;
}

/**
 * Determine if a value is a Date
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is a Date, otherwise false
 */
function isDate(val) {
  return toString.call(val) === '[object Date]';
}

/**
 * Determine if a value is a File
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is a File, otherwise false
 */
function isFile(val) {
  return toString.call(val) === '[object File]';
}

/**
 * Determine if a value is a Blob
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is a Blob, otherwise false
 */
function isBlob(val) {
  return toString.call(val) === '[object Blob]';
}

/**
 * Determine if a value is a Function
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is a Function, otherwise false
 */
function isFunction(val) {
  return toString.call(val) === '[object Function]';
}

/**
 * Determine if a value is a Stream
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is a Stream, otherwise false
 */
function isStream(val) {
  return isObject(val) && isFunction(val.pipe);
}

/**
 * Determine if a value is a URLSearchParams object
 *
 * @param {Object} val The value to test
 * @returns {boolean} True if value is a URLSearchParams object, otherwise false
 */
function isURLSearchParams(val) {
  return typeof URLSearchParams !== 'undefined' && val instanceof URLSearchParams;
}

/**
 * Trim excess whitespace off the beginning and end of a string
 *
 * @param {String} str The String to trim
 * @returns {String} The String freed of excess whitespace
 */
function trim(str) {
  return str.replace(/^\s*/, '').replace(/\s*$/, '');
}

/**
 * Determine if we're running in a standard browser environment
 *
 * This allows axios to run in a web worker, and react-native.
 * Both environments support XMLHttpRequest, but not fully standard globals.
 *
 * web workers:
 *  typeof window -> undefined
 *  typeof document -> undefined
 *
 * react-native:
 *  navigator.product -> 'ReactNative'
 * nativescript
 *  navigator.product -> 'NativeScript' or 'NS'
 */
function isStandardBrowserEnv() {
  if (typeof navigator !== 'undefined' && (navigator.product === 'ReactNative' ||
                                           navigator.product === 'NativeScript' ||
                                           navigator.product === 'NS')) {
    return false;
  }
  return (
    typeof window !== 'undefined' &&
    typeof document !== 'undefined'
  );
}

/**
 * Iterate over an Array or an Object invoking a function for each item.
 *
 * If `obj` is an Array callback will be called passing
 * the value, index, and complete array for each item.
 *
 * If 'obj' is an Object callback will be called passing
 * the value, key, and complete object for each property.
 *
 * @param {Object|Array} obj The object to iterate
 * @param {Function} fn The callback to invoke for each item
 */
function forEach(obj, fn) {
  // Don't bother if no value provided
  if (obj === null || typeof obj === 'undefined') {
    return;
  }

  // Force an array if not already something iterable
  if (typeof obj !== 'object') {
    /*eslint no-param-reassign:0*/
    obj = [obj];
  }

  if (isArray(obj)) {
    // Iterate over array values
    for (var i = 0, l = obj.length; i < l; i++) {
      fn.call(null, obj[i], i, obj);
    }
  } else {
    // Iterate over object keys
    for (var key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        fn.call(null, obj[key], key, obj);
      }
    }
  }
}

/**
 * Accepts varargs expecting each argument to be an object, then
 * immutably merges the properties of each object and returns result.
 *
 * When multiple objects contain the same key the later object in
 * the arguments list will take precedence.
 *
 * Example:
 *
 * ```js
 * var result = merge({foo: 123}, {foo: 456});
 * console.log(result.foo); // outputs 456
 * ```
 *
 * @param {Object} obj1 Object to merge
 * @returns {Object} Result of all merge properties
 */
function merge(/* obj1, obj2, obj3, ... */) {
  var result = {};
  function assignValue(val, key) {
    if (isPlainObject(result[key]) && isPlainObject(val)) {
      result[key] = merge(result[key], val);
    } else if (isPlainObject(val)) {
      result[key] = merge({}, val);
    } else if (isArray(val)) {
      result[key] = val.slice();
    } else {
      result[key] = val;
    }
  }

  for (var i = 0, l = arguments.length; i < l; i++) {
    forEach(arguments[i], assignValue);
  }
  return result;
}

/**
 * Extends object a by mutably adding to it the properties of object b.
 *
 * @param {Object} a The object to be extended
 * @param {Object} b The object to copy properties from
 * @param {Object} thisArg The object to bind function to
 * @return {Object} The resulting value of object a
 */
function extend(a, b, thisArg) {
  forEach(b, function assignValue(val, key) {
    if (thisArg && typeof val === 'function') {
      a[key] = bind(val, thisArg);
    } else {
      a[key] = val;
    }
  });
  return a;
}

/**
 * Remove byte order marker. This catches EF BB BF (the UTF-8 BOM)
 *
 * @param {string} content with BOM
 * @return {string} content value without BOM
 */
function stripBOM(content) {
  if (content.charCodeAt(0) === 0xFEFF) {
    content = content.slice(1);
  }
  return content;
}

module.exports = {
  isArray: isArray,
  isArrayBuffer: isArrayBuffer,
  isBuffer: isBuffer,
  isFormData: isFormData,
  isArrayBufferView: isArrayBufferView,
  isString: isString,
  isNumber: isNumber,
  isObject: isObject,
  isPlainObject: isPlainObject,
  isUndefined: isUndefined,
  isDate: isDate,
  isFile: isFile,
  isBlob: isBlob,
  isFunction: isFunction,
  isStream: isStream,
  isURLSearchParams: isURLSearchParams,
  isStandardBrowserEnv: isStandardBrowserEnv,
  forEach: forEach,
  merge: merge,
  extend: extend,
  trim: trim,
  stripBOM: stripBOM
};

},{"./helpers/bind":19}],30:[function(require,module,exports){
// Blake2B in pure Javascript
// Adapted from the reference implementation in RFC7693
// Ported to Javascript by DC - https://github.com/dcposch

var util = require('./util')

// 64-bit unsigned addition
// Sets v[a,a+1] += v[b,b+1]
// v should be a Uint32Array
function ADD64AA (v, a, b) {
  var o0 = v[a] + v[b]
  var o1 = v[a + 1] + v[b + 1]
  if (o0 >= 0x100000000) {
    o1++
  }
  v[a] = o0
  v[a + 1] = o1
}

// 64-bit unsigned addition
// Sets v[a,a+1] += b
// b0 is the low 32 bits of b, b1 represents the high 32 bits
function ADD64AC (v, a, b0, b1) {
  var o0 = v[a] + b0
  if (b0 < 0) {
    o0 += 0x100000000
  }
  var o1 = v[a + 1] + b1
  if (o0 >= 0x100000000) {
    o1++
  }
  v[a] = o0
  v[a + 1] = o1
}

// Little-endian byte access
function B2B_GET32 (arr, i) {
  return (arr[i] ^
  (arr[i + 1] << 8) ^
  (arr[i + 2] << 16) ^
  (arr[i + 3] << 24))
}

// G Mixing function
// The ROTRs are inlined for speed
function B2B_G (a, b, c, d, ix, iy) {
  var x0 = m[ix]
  var x1 = m[ix + 1]
  var y0 = m[iy]
  var y1 = m[iy + 1]

  ADD64AA(v, a, b) // v[a,a+1] += v[b,b+1] ... in JS we must store a uint64 as two uint32s
  ADD64AC(v, a, x0, x1) // v[a, a+1] += x ... x0 is the low 32 bits of x, x1 is the high 32 bits

  // v[d,d+1] = (v[d,d+1] xor v[a,a+1]) rotated to the right by 32 bits
  var xor0 = v[d] ^ v[a]
  var xor1 = v[d + 1] ^ v[a + 1]
  v[d] = xor1
  v[d + 1] = xor0

  ADD64AA(v, c, d)

  // v[b,b+1] = (v[b,b+1] xor v[c,c+1]) rotated right by 24 bits
  xor0 = v[b] ^ v[c]
  xor1 = v[b + 1] ^ v[c + 1]
  v[b] = (xor0 >>> 24) ^ (xor1 << 8)
  v[b + 1] = (xor1 >>> 24) ^ (xor0 << 8)

  ADD64AA(v, a, b)
  ADD64AC(v, a, y0, y1)

  // v[d,d+1] = (v[d,d+1] xor v[a,a+1]) rotated right by 16 bits
  xor0 = v[d] ^ v[a]
  xor1 = v[d + 1] ^ v[a + 1]
  v[d] = (xor0 >>> 16) ^ (xor1 << 16)
  v[d + 1] = (xor1 >>> 16) ^ (xor0 << 16)

  ADD64AA(v, c, d)

  // v[b,b+1] = (v[b,b+1] xor v[c,c+1]) rotated right by 63 bits
  xor0 = v[b] ^ v[c]
  xor1 = v[b + 1] ^ v[c + 1]
  v[b] = (xor1 >>> 31) ^ (xor0 << 1)
  v[b + 1] = (xor0 >>> 31) ^ (xor1 << 1)
}

// Initialization Vector
var BLAKE2B_IV32 = new Uint32Array([
  0xF3BCC908, 0x6A09E667, 0x84CAA73B, 0xBB67AE85,
  0xFE94F82B, 0x3C6EF372, 0x5F1D36F1, 0xA54FF53A,
  0xADE682D1, 0x510E527F, 0x2B3E6C1F, 0x9B05688C,
  0xFB41BD6B, 0x1F83D9AB, 0x137E2179, 0x5BE0CD19
])

var SIGMA8 = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
  11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
  7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
  9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
  2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
  12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
  13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
  6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
  10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3
]

// These are offsets into a uint64 buffer.
// Multiply them all by 2 to make them offsets into a uint32 buffer,
// because this is Javascript and we don't have uint64s
var SIGMA82 = new Uint8Array(SIGMA8.map(function (x) { return x * 2 }))

// Compression function. 'last' flag indicates last block.
// Note we're representing 16 uint64s as 32 uint32s
var v = new Uint32Array(32)
var m = new Uint32Array(32)
function blake2bCompress (ctx, last) {
  var i = 0

  // init work variables
  for (i = 0; i < 16; i++) {
    v[i] = ctx.h[i]
    v[i + 16] = BLAKE2B_IV32[i]
  }

  // low 64 bits of offset
  v[24] = v[24] ^ ctx.t
  v[25] = v[25] ^ (ctx.t / 0x100000000)
  // high 64 bits not supported, offset may not be higher than 2**53-1

  // last block flag set ?
  if (last) {
    v[28] = ~v[28]
    v[29] = ~v[29]
  }

  // get little-endian words
  for (i = 0; i < 32; i++) {
    m[i] = B2B_GET32(ctx.b, 4 * i)
  }

  // twelve rounds of mixing
  // uncomment the DebugPrint calls to log the computation
  // and match the RFC sample documentation
  // util.debugPrint('          m[16]', m, 64)
  for (i = 0; i < 12; i++) {
    // util.debugPrint('   (i=' + (i < 10 ? ' ' : '') + i + ') v[16]', v, 64)
    B2B_G(0, 8, 16, 24, SIGMA82[i * 16 + 0], SIGMA82[i * 16 + 1])
    B2B_G(2, 10, 18, 26, SIGMA82[i * 16 + 2], SIGMA82[i * 16 + 3])
    B2B_G(4, 12, 20, 28, SIGMA82[i * 16 + 4], SIGMA82[i * 16 + 5])
    B2B_G(6, 14, 22, 30, SIGMA82[i * 16 + 6], SIGMA82[i * 16 + 7])
    B2B_G(0, 10, 20, 30, SIGMA82[i * 16 + 8], SIGMA82[i * 16 + 9])
    B2B_G(2, 12, 22, 24, SIGMA82[i * 16 + 10], SIGMA82[i * 16 + 11])
    B2B_G(4, 14, 16, 26, SIGMA82[i * 16 + 12], SIGMA82[i * 16 + 13])
    B2B_G(6, 8, 18, 28, SIGMA82[i * 16 + 14], SIGMA82[i * 16 + 15])
  }
  // util.debugPrint('   (i=12) v[16]', v, 64)

  for (i = 0; i < 16; i++) {
    ctx.h[i] = ctx.h[i] ^ v[i] ^ v[i + 16]
  }
  // util.debugPrint('h[8]', ctx.h, 64)
}

// Creates a BLAKE2b hashing context
// Requires an output length between 1 and 64 bytes
// Takes an optional Uint8Array key
function blake2bInit (outlen, key) {
  if (outlen === 0 || outlen > 64) {
    throw new Error('Illegal output length, expected 0 < length <= 64')
  }
  if (key && key.length > 64) {
    throw new Error('Illegal key, expected Uint8Array with 0 < length <= 64')
  }

  // state, 'param block'
  var ctx = {
    b: new Uint8Array(128),
    h: new Uint32Array(16),
    t: 0, // input count
    c: 0, // pointer within buffer
    outlen: outlen // output length in bytes
  }

  // initialize hash state
  for (var i = 0; i < 16; i++) {
    ctx.h[i] = BLAKE2B_IV32[i]
  }
  var keylen = key ? key.length : 0
  ctx.h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen

  // key the hash, if applicable
  if (key) {
    blake2bUpdate(ctx, key)
    // at the end
    ctx.c = 128
  }

  return ctx
}

// Updates a BLAKE2b streaming hash
// Requires hash context and Uint8Array (byte array)
function blake2bUpdate (ctx, input) {
  for (var i = 0; i < input.length; i++) {
    if (ctx.c === 128) { // buffer full ?
      ctx.t += ctx.c // add counters
      blake2bCompress(ctx, false) // compress (not last)
      ctx.c = 0 // counter to zero
    }
    ctx.b[ctx.c++] = input[i]
  }
}

// Completes a BLAKE2b streaming hash
// Returns a Uint8Array containing the message digest
function blake2bFinal (ctx) {
  ctx.t += ctx.c // mark last block offset

  while (ctx.c < 128) { // fill up with zeros
    ctx.b[ctx.c++] = 0
  }
  blake2bCompress(ctx, true) // final block flag = 1

  // little endian convert and store
  var out = new Uint8Array(ctx.outlen)
  for (var i = 0; i < ctx.outlen; i++) {
    out[i] = ctx.h[i >> 2] >> (8 * (i & 3))
  }
  return out
}

// Computes the BLAKE2B hash of a string or byte array, and returns a Uint8Array
//
// Returns a n-byte Uint8Array
//
// Parameters:
// - input - the input bytes, as a string, Buffer or Uint8Array
// - key - optional key Uint8Array, up to 64 bytes
// - outlen - optional output length in bytes, default 64
function blake2b (input, key, outlen) {
  // preprocess inputs
  outlen = outlen || 64
  input = util.normalizeInput(input)

  // do the math
  var ctx = blake2bInit(outlen, key)
  blake2bUpdate(ctx, input)
  return blake2bFinal(ctx)
}

// Computes the BLAKE2B hash of a string or byte array
//
// Returns an n-byte hash in hex, all lowercase
//
// Parameters:
// - input - the input bytes, as a string, Buffer, or Uint8Array
// - key - optional key Uint8Array, up to 64 bytes
// - outlen - optional output length in bytes, default 64
function blake2bHex (input, key, outlen) {
  var output = blake2b(input, key, outlen)
  return util.toHex(output)
}

module.exports = {
  blake2b: blake2b,
  blake2bHex: blake2bHex,
  blake2bInit: blake2bInit,
  blake2bUpdate: blake2bUpdate,
  blake2bFinal: blake2bFinal
}

},{"./util":31}],31:[function(require,module,exports){
(function (Buffer){(function (){
var ERROR_MSG_INPUT = 'Input must be an string, Buffer or Uint8Array'

// For convenience, let people hash a string, not just a Uint8Array
function normalizeInput (input) {
  var ret
  if (input instanceof Uint8Array) {
    ret = input
  } else if (input instanceof Buffer) {
    ret = new Uint8Array(input)
  } else if (typeof (input) === 'string') {
    ret = new Uint8Array(Buffer.from(input, 'utf8'))
  } else {
    throw new Error(ERROR_MSG_INPUT)
  }
  return ret
}

// Converts a Uint8Array to a hexadecimal string
// For example, toHex([255, 0, 255]) returns "ff00ff"
function toHex (bytes) {
  return Array.prototype.map.call(bytes, function (n) {
    return (n < 16 ? '0' : '') + n.toString(16)
  }).join('')
}

// Converts any value in [0...2^32-1] to an 8-character hex string
function uint32ToHex (val) {
  return (0x100000000 + val).toString(16).substring(1)
}

// For debugging: prints out hash state in the same format as the RFC
// sample computation exactly, so that you can diff
function debugPrint (label, arr, size) {
  var msg = '\n' + label + ' = '
  for (var i = 0; i < arr.length; i += 2) {
    if (size === 32) {
      msg += uint32ToHex(arr[i]).toUpperCase()
      msg += ' '
      msg += uint32ToHex(arr[i + 1]).toUpperCase()
    } else if (size === 64) {
      msg += uint32ToHex(arr[i + 1]).toUpperCase()
      msg += uint32ToHex(arr[i]).toUpperCase()
    } else throw new Error('Invalid size ' + size)
    if (i % 6 === 4) {
      msg += '\n' + new Array(label.length + 4).join(' ')
    } else if (i < arr.length - 2) {
      msg += ' '
    }
  }
  console.log(msg)
}

// For performance testing: generates N bytes of input, hashes M times
// Measures and prints MB/second hash performance each time
function testSpeed (hashFn, N, M) {
  var startMs = new Date().getTime()

  var input = new Uint8Array(N)
  for (var i = 0; i < N; i++) {
    input[i] = i % 256
  }
  var genMs = new Date().getTime()
  console.log('Generated random input in ' + (genMs - startMs) + 'ms')
  startMs = genMs

  for (i = 0; i < M; i++) {
    var hashHex = hashFn(input)
    var hashMs = new Date().getTime()
    var ms = hashMs - startMs
    startMs = hashMs
    console.log('Hashed in ' + ms + 'ms: ' + hashHex.substring(0, 20) + '...')
    console.log(Math.round(N / (1 << 20) / (ms / 1000) * 100) / 100 + ' MB PER SECOND')
  }
}

module.exports = {
  normalizeInput: normalizeInput,
  toHex: toHex,
  debugPrint: debugPrint,
  testSpeed: testSpeed
}

}).call(this)}).call(this,require("buffer").Buffer)
},{"buffer":44}],32:[function(require,module,exports){
(function (process,Buffer,__dirname){(function (){
/*!
* nanocurrency-js v2.5.0: A toolkit for the Nano cryptocurrency.
* Copyright (c) 2020 Marvin ROGER <dev at marvinroger dot fr>
* Licensed under GPL-3.0 (https://git.io/vAZsK)
*/
!function(A,I){"object"==typeof exports&&"undefined"!=typeof module?I(exports,require("fs"),require("path")):"function"==typeof define&&define.amd?define(["exports","fs","path"],I):I((A=A||self).NanoCurrency={},A.fs,A.path)}(this,(function(A,I,i){"use strict";
/*! *****************************************************************************
    Copyright (c) Microsoft Corporation. All rights reserved.
    Licensed under the Apache License, Version 2.0 (the "License"); you may not use
    this file except in compliance with the License. You may obtain a copy of the
    License at http://www.apache.org/licenses/LICENSE-2.0

    THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION ANY IMPLIED
    WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE,
    MERCHANTABLITY OR NON-INFRINGEMENT.

    See the Apache Version 2.0 License for specific language governing permissions
    and limitations under the License.
    ***************************************************************************** */
function e(A,I,i,e){return new(i||(i=Promise))((function(r,n){function g(A){try{o(e.next(A))}catch(A){n(A)}}function t(A){try{o(e.throw(A))}catch(A){n(A)}}function o(A){var I;A.done?r(A.value):(I=A.value,I instanceof i?I:new i((function(A){A(I)}))).then(g,t)}o((e=e.apply(A,I||[])).next())}))}function r(A,I){var i,e,r,n,g={label:0,sent:function(){if(1&r[0])throw r[1];return r[1]},trys:[],ops:[]};return n={next:t(0),throw:t(1),return:t(2)},"function"==typeof Symbol&&(n[Symbol.iterator]=function(){return this}),n;function t(n){return function(t){return function(n){if(i)throw new TypeError("Generator is already executing.");for(;g;)try{if(i=1,e&&(r=2&n[0]?e.return:n[0]?e.throw||((r=e.return)&&r.call(e),0):e.next)&&!(r=r.call(e,n[1])).done)return r;switch(e=0,r&&(n=[2&n[0],r.value]),n[0]){case 0:case 1:r=n;break;case 4:return g.label++,{value:n[1],done:!1};case 5:g.label++,e=n[1],n=[0];continue;case 7:n=g.ops.pop(),g.trys.pop();continue;default:if(!(r=(r=g.trys).length>0&&r[r.length-1])&&(6===n[0]||2===n[0])){g=0;continue}if(3===n[0]&&(!r||n[1]>r[0]&&n[1]<r[3])){g.label=n[1];break}if(6===n[0]&&g.label<r[1]){g.label=r[1],r=n;break}if(r&&g.label<r[2]){g.label=r[2],g.ops.push(n);break}r[2]&&g.ops.pop(),g.trys.pop();continue}n=I.call(A,g)}catch(A){n=[6,A],e=0}finally{i=r=0}if(5&n[0])throw n[1];return{value:n[0]?n[1]:void 0,done:!0}}([n,t])}}}I=I&&I.hasOwnProperty("default")?I.default:I,i=i&&i.hasOwnProperty("default")?i.default:i;var n=function(A,I){return A(I={exports:{}},I.exports),I.exports}((function(A,e){var r,n=(r="undefined"!=typeof document&&document.currentScript?document.currentScript.src:void 0,function(A){var e;A=A||{},e||(e=void 0!==A?A:{});var n,g={};for(n in e)e.hasOwnProperty(n)&&(g[n]=e[n]);e.arguments=[],e.thisProgram="./this.program",e.quit=function(A,I){throw I},e.preRun=[],e.postRun=[];var t=!1,o=!1,C=!1,a=!1;t="object"==typeof window,o="function"==typeof importScripts,C="object"==typeof process&&!t&&!o,a=!t&&!C&&!o;var h,f,u="";C?(u=__dirname+"/",e.read=function(A,e){var r=T(A);return r||(h||(h=I),f||(f=i),A=f.normalize(A),r=h.readFileSync(A)),e?r:r.toString()},e.readBinary=function(A){return(A=e.read(A,!0)).buffer||(A=new Uint8Array(A)),l(A.buffer),A},1<process.argv.length&&(e.thisProgram=process.argv[1].replace(/\\/g,"/")),e.arguments=process.argv.slice(2),process.on("uncaughtException",(function(A){if(!(A instanceof _))throw A})),process.on("unhandledRejection",$),e.quit=function(A){process.exit(A)},e.inspect=function(){return"[Emscripten Module object]"}):a?("undefined"!=typeof read&&(e.read=function(A){var I=T(A);return I?J(I):read(A)}),e.readBinary=function(A){var I;return(I=T(A))?I:"function"==typeof readbuffer?new Uint8Array(readbuffer(A)):(l("object"==typeof(I=read(A,"binary"))),I)},"undefined"!=typeof scriptArgs?e.arguments=scriptArgs:void 0!==arguments&&(e.arguments=arguments),"function"==typeof quit&&(e.quit=function(A){quit(A)})):(t||o)&&(o?u=self.location.href:document.currentScript&&(u=document.currentScript.src),r&&(u=r),u=0!==u.indexOf("blob:")?u.substr(0,u.lastIndexOf("/")+1):"",e.read=function(A){try{var I=new XMLHttpRequest;return I.open("GET",A,!1),I.send(null),I.responseText}catch(I){if(A=T(A))return J(A);throw I}},o&&(e.readBinary=function(A){try{var I=new XMLHttpRequest;return I.open("GET",A,!1),I.responseType="arraybuffer",I.send(null),new Uint8Array(I.response)}catch(I){if(A=T(A))return A;throw I}}),e.readAsync=function(A,I,i){var e=new XMLHttpRequest;e.open("GET",A,!0),e.responseType="arraybuffer",e.onload=function(){if(200==e.status||0==e.status&&e.response)I(e.response);else{var r=T(A);r?I(r.buffer):i()}},e.onerror=i,e.send(null)},e.setWindowTitle=function(A){document.title=A});var s=e.print||("undefined"!=typeof console?console.log.bind(console):"undefined"!=typeof print?print:null),Q=e.printErr||("undefined"!=typeof printErr?printErr:"undefined"!=typeof console&&console.warn.bind(console)||s);for(n in g)g.hasOwnProperty(n)&&(e[n]=g[n]);g=void 0;var B={"f64-rem":function(A,I){return A%I},debugger:function(){}};"object"!=typeof WebAssembly&&Q("no native wasm support detected");var E,c=!1;function l(A,I){A||$("Assertion failed: "+I)}function w(A){var I=e["_"+A];return l(I,"Cannot call unknown function "+A+", make sure it is exported"),I}function U(A,I,i,e){var r={string:function(A){var I=0;if(null!=A&&0!==A){var i=1+(A.length<<2),e=I=q(i),r=d;if(0<i){i=e+i-1;for(var n=0;n<A.length;++n){var g=A.charCodeAt(n);if(55296<=g&&57343>=g&&(g=65536+((1023&g)<<10)|1023&A.charCodeAt(++n)),127>=g){if(e>=i)break;r[e++]=g}else{if(2047>=g){if(e+1>=i)break;r[e++]=192|g>>6}else{if(65535>=g){if(e+2>=i)break;r[e++]=224|g>>12}else{if(e+3>=i)break;r[e++]=240|g>>18,r[e++]=128|g>>12&63}r[e++]=128|g>>6&63}r[e++]=128|63&g}}r[e]=0}}return I},array:function(A){var I=q(A.length);return y.set(A,I),I}},n=w(A),g=[];if(A=0,e)for(var t=0;t<e.length;t++){var o=r[i[t]];o?(0===A&&(A=W()),g[t]=o(e[t])):g[t]=e[t]}return i=function(A){if("string"===I)if(A){for(var i=d,e=A+void 0,r=A;i[r]&&!(r>=e);)++r;if(16<r-A&&i.subarray&&S)A=S.decode(i.subarray(A,r));else{for(e="";A<r;){var n=i[A++];if(128&n){var g=63&i[A++];if(192==(224&n))e+=String.fromCharCode((31&n)<<6|g);else{var t=63&i[A++];65536>(n=224==(240&n)?(15&n)<<12|g<<6|t:(7&n)<<18|g<<12|t<<6|63&i[A++])?e+=String.fromCharCode(n):(n-=65536,e+=String.fromCharCode(55296|n>>10,56320|1023&n))}}else e+=String.fromCharCode(n)}A=e}}else A="";else A="boolean"===I?!!A:A;return A}(i=n.apply(null,g)),0!==A&&Z(A),i}var S="undefined"!=typeof TextDecoder?new TextDecoder("utf8"):void 0;"undefined"!=typeof TextDecoder&&new TextDecoder("utf-16le");var F,y,d,p,G=e.TOTAL_MEMORY||16777216;function D(A){for(;0<A.length;){var I=A.shift();if("function"==typeof I)I();else{var i=I.h;"number"==typeof i?void 0===I.g?e.dynCall_v(i):e.dynCall_vi(i,I.g):i(void 0===I.g?null:I.g)}}}5242880>G&&Q("TOTAL_MEMORY should be larger than TOTAL_STACK, was "+G+"! (TOTAL_STACK=5242880)"),e.buffer?F=e.buffer:(F="object"==typeof WebAssembly&&"function"==typeof WebAssembly.Memory?(E=new WebAssembly.Memory({initial:G/65536,maximum:G/65536})).buffer:new ArrayBuffer(G),e.buffer=F),e.HEAP8=y=new Int8Array(F),e.HEAP16=new Int16Array(F),e.HEAP32=p=new Int32Array(F),e.HEAPU8=d=new Uint8Array(F),e.HEAPU16=new Uint16Array(F),e.HEAPU32=new Uint32Array(F),e.HEAPF32=new Float32Array(F),e.HEAPF64=new Float64Array(F),p[724]=5246032;var v=[],k=[],b=[],H=[],m=!1;function M(){var A=e.preRun.shift();v.unshift(A)}var Y=0,N=null;e.preloadedImages={},e.preloadedAudios={};var x="data:application/octet-stream;base64,";function K(A){return String.prototype.startsWith?A.startsWith(x):0===A.indexOf(x)}var R="data:application/octet-stream;base64,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NCAAIAM2AjggACADNgI8IABBQGshAAwBCwsDQCAAIAVIBEAgACADNgIAIABBBGohAAwBCwsLA0AgACAESARAIAAgAToAACAAQQFqIQAMAQsLIAQgAmsLxgMBA38gAkGAwABOBEAgACABIAIQABogAA8LIAAhBCAAIAJqIQMgAEEDcSABQQNxRgRAA0AgAEEDcQRAIAJFBEAgBA8LIAAgASwAADoAACAAQQFqIQAgAUEBaiEBIAJBAWshAgwBCwsgA0F8cSICQUBqIQUDQCAAIAVMBEAgACABKAIANgIAIAAgASgCBDYCBCAAIAEoAgg2AgggACABKAIMNgIMIAAgASgCEDYCECAAIAEoAhQ2AhQgACABKAIYNgIYIAAgASgCHDYCHCAAIAEoAiA2AiAgACABKAIkNgIkIAAgASgCKDYCKCAAIAEoAiw2AiwgACABKAIwNgIwIAAgASgCNDYCNCAAIAEoAjg2AjggACABKAI8NgI8IABBQGshACABQUBrIQEMAQsLA0AgACACSARAIAAgASgCADYCACAAQQRqIQAgAUEEaiEBDAELCwUgA0EEayECA0AgACACSARAIAAgASwAADoAACAAIAEsAAE6AAEgACABLAACOgACIAAgASwAAzoAAyAAQQRqIQAgAUEEaiEBDAELCwsDQCAAIANIBEAgACABLAAAOgAAIABBAWohACABQQFqIQEMAQsLIAQLBwAgABAMpwuNAQEDfwJAAkAgACICQQNxRQ0AIAIiASEAAkADQCABLAAARQ0BIAFBAWoiASIAQQNxDQALIAEhAAwBCwwBCwNAIABBBGohASAAKAIAIgNB//37d2ogA0GAgYKEeHFBgIGChHhzcUUEQCABIQAMAQsLIANB/wFxBEADQCAAQQFqIgAsAAANAAsLCyAAIAJrC+wFAgR/AX4DQCAAKAIEIgEgACgCZEkEfyAAIAFBAWo2AgQgAS0AAAUgABACCyIBIgNBIEYgA0F3akEFSXINAAsCQAJAIAFBK2sOAwABAAELIAFBLUZBH3RBH3UhBCAAKAIEIgEgACgCZEkEfyAAIAFBAWo2AgQgAS0AAAUgABACCyEBCwJ+An8CQAJAIAFBMEYEfiAAKAIEIgEgACgCZEkEfyAAIAFBAWo2AgQgAS0AAAUgABACCyIBQSByQfgARwRAIAFBkQhqLAAAIgNB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aiwAADoAAEG2CiABQf8BcUEEdkGACGosAAA6AABBtwogAUEPcUGACGosAAA6AABBuAogAkH/AXFBBHZBgAhqLAAAOgAAQbkKIAJBD3FBgAhqLAAAOgAAQboKIANB/wFxQQR2QYAIaiwAADoAAEG7CiADQQ9xQYAIaiwAADoAAEG8CiAJQf8BcUEEdkGACGosAAA6AABBvQogCUEPcUGACGosAAA6AABBvgogBUH/AXFBBHZBgAhqLAAAOgAAQb8KIAVBD3FBgAhqLAAAOgAAQcAKIAhB/wFxQQR2QYAIaiwAADoAAEHBCiAIQQ9xQYAIaiwAADoAAEHCCkEAOgAAIAckAUGwCgsGACAAJAELCABBABABQQALcAIBfwJ+IwEhASMBQYABaiQBIAFBADYCACABIAA2AgQgASAANgIsIAFBfyAAQf////8HaiAAQQBIGzYCCCABQX82AkwgAUEANgJoIAEgASgCCCIAIAEoAgRrNgJsIAEgADYCZCABEAghAyABJAEgAwuLAQECfyAAIAAsAEoiASABQf8BanI6AEogACgCFCAAKAIcSwRAIAAoAiQhASAAQQBBACABQQFxEQAAGgsgAEEANgIQIABBADYCHCAAQQA2AhQgACgCACIBQQRxBH8gACABQSByNgIAQX8FIAAgACgCLCAAKAIwaiICNgIIIAAgAjYCBCABQRt0QR91CwtEAQN/IwEhASMBQRBqJAEgABANBH9BfwUgACgCICECIAAgAUEBIAJBAXERAABBAUYEfyABLQAABUF/CwshAyABJAEgAwsEACMBCxsBAn8jASECIAAjAWokASMBQQ9qQXBxJAEgAgsLoAICAEGACAuRAjAxMjM0NTY3ODlhYmNkZWb/////////////////////////////////////////////////////////////////AAECAwQFBgcICf////////8KCwwNDg8QERITFBUWFxgZGhscHR4fICEiI////////woLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIj/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////wBBoAoLAQE=";if(!K(R)){var L=R;R=e.locateFile?e.locateFile(L,u):u+L}function O(){try{if(e.wasmBinary)return new Uint8Array(e.wasmBinary);var A=T(R);if(A)return A;if(e.readBinary)return e.readBinary(R);throw"both async and sync fetching of the wasm failed"}catch(A){$(A)}}function P(){return e.wasmBinary||!t&&!o||"function"!=typeof fetch?new Promise((function(A){A(O())})):fetch(R,{credentials:"same-origin"}).then((function(A){if(!A.ok)throw"failed to load wasm binary file at '"+R+"'";return A.arrayBuffer()})).catch((function(){return O()}))}function j(A){function I(A){e.asm=A.exports,Y--,e.monitorRunDependencies&&e.monitorRunDependencies(Y),0==Y&&N&&(A=N,N=null,A())}function i(A){I(A.instance)}function r(A){P().then((function(A){return WebAssembly.instantiate(A,n)})).then(A,(function(A){Q("failed to asynchronously prepare wasm: "+A),$(A)}))}var n={env:A,global:{NaN:NaN,Infinity:1/0},"global.Math":Math,asm2wasm:B};if(Y++,e.monitorRunDependencies&&e.monitorRunDependencies(Y),e.instantiateWasm)try{return e.instantiateWasm(n,I)}catch(A){return Q("Module.instantiateWasm callback failed with error: "+A),!1}return e.wasmBinary||"function"!=typeof WebAssembly.instantiateStreaming||K(R)||"function"!=typeof fetch?r(i):WebAssembly.instantiateStreaming(fetch(R,{credentials:"same-origin"}),n).then(i,(function(A){Q("wasm streaming compile failed: "+A),Q("falling back to ArrayBuffer instantiation"),r(i)})),{}}function J(A){for(var I=[],i=0;i<A.length;i++){var e=A[i];255<e&&(e&=255),I.push(String.fromCharCode(e))}return I.join("")}e.asm=function(A,I){return I.memory=E,I.table=new WebAssembly.Table({initial:2,maximum:2,element:"anyfunc"}),I.__memory_base=1024,I.__table_base=0,j(I)};var X="function"==typeof atob?atob:function(A){var I="",i=0;A=A.replace(/[^A-Za-z0-9\+\/=]/g,"");do{var e="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".indexOf(A.charAt(i++)),r="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".indexOf(A.charAt(i++)),n="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".indexOf(A.charAt(i++)),g="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".indexOf(A.charAt(i++));e=e<<2|r>>4,r=(15&r)<<4|n>>2;var t=(3&n)<<6|g;I+=String.fromCharCode(e),64!==n&&(I+=String.fromCharCode(r)),64!==g&&(I+=String.fromCharCode(t))}while(i<A.length);return I};function T(A){if(K(A)){if(A=A.slice(x.length),"boolean"==typeof C&&C){try{var I=Buffer.from(A,"base64")}catch(i){I=new Buffer(A,"base64")}var i=new Uint8Array(I.buffer,I.byteOffset,I.byteLength)}else try{var e=X(A),r=new Uint8Array(e.length);for(I=0;I<e.length;++I)r[I]=e.charCodeAt(I);i=r}catch(A){throw Error("Converting base64 string to bytes failed.")}return i}}var V=e.asm({},{b:$,a:function(A,I,i){d.set(d.subarray(I,I+i),A)}},F);e.asm=V,e._emscripten_work=function(){return e.asm.c.apply(null,arguments)};var q=e.stackAlloc=function(){return e.asm.d.apply(null,arguments)},Z=e.stackRestore=function(){return e.asm.e.apply(null,arguments)},W=e.stackSave=function(){return e.asm.f.apply(null,arguments)};function _(A){this.name="ExitStatus",this.message="Program terminated with exit("+A+")",this.status=A}function z(){function A(){if(!e.calledRun&&(e.calledRun=!0,!c)){if(m||(m=!0,D(k)),D(b),e.onRuntimeInitialized&&e.onRuntimeInitialized(),e.postRun)for("function"==typeof e.postRun&&(e.postRun=[e.postRun]);e.postRun.length;){var A=e.postRun.shift();H.unshift(A)}D(H)}}if(!(0<Y)){if(e.preRun)for("function"==typeof e.preRun&&(e.preRun=[e.preRun]);e.preRun.length;)M();D(v),0<Y||e.calledRun||(e.setStatus?(e.setStatus("Running..."),setTimeout((function(){setTimeout((function(){e.setStatus("")}),1),A()}),1)):A())}}function $(A){throw e.onAbort&&e.onAbort(A),void 0!==A?(s(A),Q(A),A=JSON.stringify(A)):A="",c=!0,"abort("+A+"). Build with -s ASSERTIONS=1 for more info."}if(e.asm=V,e.cwrap=function(A,I,i,e){var r=(i=i||[]).every((function(A){return"number"===A}));return"string"!==I&&r&&!e?w(A):function(){return U(A,I,i,arguments)}},e.then=function(A){if(e.calledRun)A(e);else{var I=e.onRuntimeInitialized;e.onRuntimeInitialized=function(){I&&I(),A(e)}}return e},_.prototype=Error(),_.prototype.constructor=_,N=function A(){e.calledRun||z(),e.calledRun||(N=A)},e.run=z,e.abort=$,e.preInit)for("function"==typeof e.preInit&&(e.preInit=[e.preInit]);0<e.preInit.length;)e.preInit.pop()();return e.noExitRuntime=!0,z(),A});A.exports=n})),g=/^-?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?$/i,t=Math.ceil,o=Math.floor,C="[BigNumber Error] ",a=C+"Number primitive has more than 15 significant digits: ",h=[1,10,100,1e3,1e4,1e5,1e6,1e7,1e8,1e9,1e10,1e11,1e12,1e13];function f(A){var I=0|A;return A>0||A===I?I:I-1}function u(A){for(var I,i,e=1,r=A.length,n=A[0]+"";e<r;){for(i=14-(I=A[e++]+"").length;i--;I="0"+I);n+=I}for(r=n.length;48===n.charCodeAt(--r););return n.slice(0,r+1||1)}function s(A,I){var i,e,r=A.c,n=I.c,g=A.s,t=I.s,o=A.e,C=I.e;if(!g||!t)return null;if(i=r&&!r[0],e=n&&!n[0],i||e)return i?e?0:-t:g;if(g!=t)return g;if(i=g<0,e=o==C,!r||!n)return e?0:!r^i?1:-1;if(!e)return o>C^i?1:-1;for(t=(o=r.length)<(C=n.length)?o:C,g=0;g<t;g++)if(r[g]!=n[g])return r[g]>n[g]^i?1:-1;return o==C?0:o>C^i?1:-1}function Q(A,I,i,e){if(A<I||A>i||A!==o(A))throw Error(C+(e||"Argument")+("number"==typeof A?A<I||A>i?" out of range: ":" not an integer: ":" not a primitive number: ")+String(A))}function B(A){var I=A.c.length-1;return f(A.e/14)==I&&A.c[I]%2!=0}function E(A,I){return(A.length>1?A.charAt(0)+"."+A.slice(1):A)+(I<0?"e":"e+")+I}function c(A,I,i){var e,r;if(I<0){for(r=i+".";++I;r+=i);A=r+A}else if(++I>(e=A.length)){for(r=i,I-=e;--I;r+=i);A+=r}else I<e&&(A=A.slice(0,I)+"."+A.slice(I));return A}var l=function A(I){var i,e,r,n,l,w,U,S,F,y=x.prototype={constructor:x,toString:null,valueOf:null},d=new x(1),p=20,G=4,D=-7,v=21,k=-1e7,b=1e7,H=!1,m=1,M=0,Y={prefix:"",groupSize:3,secondaryGroupSize:0,groupSeparator:",",decimalSeparator:".",fractionGroupSize:0,fractionGroupSeparator:" ",suffix:""},N="0123456789abcdefghijklmnopqrstuvwxyz";function x(A,I){var i,n,t,C,h,f,u,s,B=this;if(!(B instanceof x))return new x(A,I);if(null==I){if(A&&!0===A._isBigNumber)return B.s=A.s,void(!A.c||A.e>b?B.c=B.e=null:A.e<k?B.c=[B.e=0]:(B.e=A.e,B.c=A.c.slice()));if((f="number"==typeof A)&&0*A==0){if(B.s=1/A<0?(A=-A,-1):1,A===~~A){for(C=0,h=A;h>=10;h/=10,C++);return void(C>b?B.c=B.e=null:(B.e=C,B.c=[A]))}s=String(A)}else{if(!g.test(s=String(A)))return r(B,s,f);B.s=45==s.charCodeAt(0)?(s=s.slice(1),-1):1}(C=s.indexOf("."))>-1&&(s=s.replace(".","")),(h=s.search(/e/i))>0?(C<0&&(C=h),C+=+s.slice(h+1),s=s.substring(0,h)):C<0&&(C=s.length)}else{if(Q(I,2,N.length,"Base"),10==I)return O(B=new x(A),p+B.e+1,G);if(s=String(A),f="number"==typeof A){if(0*A!=0)return r(B,s,f,I);if(B.s=1/A<0?(s=s.slice(1),-1):1,x.DEBUG&&s.replace(/^0\.0*|\./,"").length>15)throw Error(a+A)}else B.s=45===s.charCodeAt(0)?(s=s.slice(1),-1):1;for(i=N.slice(0,I),C=h=0,u=s.length;h<u;h++)if(i.indexOf(n=s.charAt(h))<0){if("."==n){if(h>C){C=u;continue}}else if(!t&&(s==s.toUpperCase()&&(s=s.toLowerCase())||s==s.toLowerCase()&&(s=s.toUpperCase()))){t=!0,h=-1,C=0;continue}return r(B,String(A),f,I)}f=!1,(C=(s=e(s,I,10,B.s)).indexOf("."))>-1?s=s.replace(".",""):C=s.length}for(h=0;48===s.charCodeAt(h);h++);for(u=s.length;48===s.charCodeAt(--u););if(s=s.slice(h,++u)){if(u-=h,f&&x.DEBUG&&u>15&&(A>9007199254740991||A!==o(A)))throw Error(a+B.s*A);if((C=C-h-1)>b)B.c=B.e=null;else if(C<k)B.c=[B.e=0];else{if(B.e=C,B.c=[],h=(C+1)%14,C<0&&(h+=14),h<u){for(h&&B.c.push(+s.slice(0,h)),u-=14;h<u;)B.c.push(+s.slice(h,h+=14));h=14-(s=s.slice(h)).length}else h-=u;for(;h--;s+="0");B.c.push(+s)}}else B.c=[B.e=0]}function K(A,I,i,e){var r,n,g,t,o;if(null==i?i=G:Q(i,0,8),!A.c)return A.toString();if(r=A.c[0],g=A.e,null==I)o=u(A.c),o=1==e||2==e&&(g<=D||g>=v)?E(o,g):c(o,g,"0");else if(n=(A=O(new x(A),I,i)).e,t=(o=u(A.c)).length,1==e||2==e&&(I<=n||n<=D)){for(;t<I;o+="0",t++);o=E(o,n)}else if(I-=g,o=c(o,n,"0"),n+1>t){if(--I>0)for(o+=".";I--;o+="0");}else if((I+=n-t)>0)for(n+1==t&&(o+=".");I--;o+="0");return A.s<0&&r?"-"+o:o}function R(A,I){for(var i,e=1,r=new x(A[0]);e<A.length;e++){if(!(i=new x(A[e])).s){r=i;break}I.call(r,i)&&(r=i)}return r}function L(A,I,i){for(var e=1,r=I.length;!I[--r];I.pop());for(r=I[0];r>=10;r/=10,e++);return(i=e+14*i-1)>b?A.c=A.e=null:i<k?A.c=[A.e=0]:(A.e=i,A.c=I),A}function O(A,I,i,e){var r,n,g,C,a,f,u,s=A.c,Q=h;if(s){A:{for(r=1,C=s[0];C>=10;C/=10,r++);if((n=I-r)<0)n+=14,g=I,u=(a=s[f=0])/Q[r-g-1]%10|0;else if((f=t((n+1)/14))>=s.length){if(!e)break A;for(;s.length<=f;s.push(0));a=u=0,r=1,g=(n%=14)-14+1}else{for(a=C=s[f],r=1;C>=10;C/=10,r++);u=(g=(n%=14)-14+r)<0?0:a/Q[r-g-1]%10|0}if(e=e||I<0||null!=s[f+1]||(g<0?a:a%Q[r-g-1]),e=i<4?(u||e)&&(0==i||i==(A.s<0?3:2)):u>5||5==u&&(4==i||e||6==i&&(n>0?g>0?a/Q[r-g]:0:s[f-1])%10&1||i==(A.s<0?8:7)),I<1||!s[0])return s.length=0,e?(I-=A.e+1,s[0]=Q[(14-I%14)%14],A.e=-I||0):s[0]=A.e=0,A;if(0==n?(s.length=f,C=1,f--):(s.length=f+1,C=Q[14-n],s[f]=g>0?o(a/Q[r-g]%Q[g])*C:0),e)for(;;){if(0==f){for(n=1,g=s[0];g>=10;g/=10,n++);for(g=s[0]+=C,C=1;g>=10;g/=10,C++);n!=C&&(A.e++,1e14==s[0]&&(s[0]=1));break}if(s[f]+=C,1e14!=s[f])break;s[f--]=0,C=1}for(n=s.length;0===s[--n];s.pop());}A.e>b?A.c=A.e=null:A.e<k&&(A.c=[A.e=0])}return A}function P(A){var I,i=A.e;return null===i?A.toString():(I=u(A.c),I=i<=D||i>=v?E(I,i):c(I,i,"0"),A.s<0?"-"+I:I)}return x.clone=A,x.ROUND_UP=0,x.ROUND_DOWN=1,x.ROUND_CEIL=2,x.ROUND_FLOOR=3,x.ROUND_HALF_UP=4,x.ROUND_HALF_DOWN=5,x.ROUND_HALF_EVEN=6,x.ROUND_HALF_CEIL=7,x.ROUND_HALF_FLOOR=8,x.EUCLID=9,x.config=x.set=function(A){var I,i;if(null!=A){if("object"!=typeof A)throw Error(C+"Object expected: "+A);if(A.hasOwnProperty(I="DECIMAL_PLACES")&&(Q(i=A[I],0,1e9,I),p=i),A.hasOwnProperty(I="ROUNDING_MODE")&&(Q(i=A[I],0,8,I),G=i),A.hasOwnProperty(I="EXPONENTIAL_AT")&&((i=A[I])&&i.pop?(Q(i[0],-1e9,0,I),Q(i[1],0,1e9,I),D=i[0],v=i[1]):(Q(i,-1e9,1e9,I),D=-(v=i<0?-i:i))),A.hasOwnProperty(I="RANGE"))if((i=A[I])&&i.pop)Q(i[0],-1e9,-1,I),Q(i[1],1,1e9,I),k=i[0],b=i[1];else{if(Q(i,-1e9,1e9,I),!i)throw Error(C+I+" cannot be zero: "+i);k=-(b=i<0?-i:i)}if(A.hasOwnProperty(I="CRYPTO")){if((i=A[I])!==!!i)throw Error(C+I+" not true or false: "+i);if(i){if("undefined"==typeof crypto||!crypto||!crypto.getRandomValues&&!crypto.randomBytes)throw H=!i,Error(C+"crypto unavailable");H=i}else H=i}if(A.hasOwnProperty(I="MODULO_MODE")&&(Q(i=A[I],0,9,I),m=i),A.hasOwnProperty(I="POW_PRECISION")&&(Q(i=A[I],0,1e9,I),M=i),A.hasOwnProperty(I="FORMAT")){if("object"!=typeof(i=A[I]))throw Error(C+I+" not an object: "+i);Y=i}if(A.hasOwnProperty(I="ALPHABET")){if("string"!=typeof(i=A[I])||/^.$|[+-.\s]|(.).*\1/.test(i))throw Error(C+I+" invalid: "+i);N=i}}return{DECIMAL_PLACES:p,ROUNDING_MODE:G,EXPONENTIAL_AT:[D,v],RANGE:[k,b],CRYPTO:H,MODULO_MODE:m,POW_PRECISION:M,FORMAT:Y,ALPHABET:N}},x.isBigNumber=function(A){if(!A||!0!==A._isBigNumber)return!1;if(!x.DEBUG)return!0;var I,i,e=A.c,r=A.e,n=A.s;A:if("[object Array]"=={}.toString.call(e)){if((1===n||-1===n)&&r>=-1e9&&r<=1e9&&r===o(r)){if(0===e[0]){if(0===r&&1===e.length)return!0;break A}if((I=(r+1)%14)<1&&(I+=14),String(e[0]).length==I){for(I=0;I<e.length;I++)if((i=e[I])<0||i>=1e14||i!==o(i))break A;if(0!==i)return!0}}}else if(null===e&&null===r&&(null===n||1===n||-1===n))return!0;throw Error(C+"Invalid BigNumber: "+A)},x.maximum=x.max=function(){return R(arguments,y.lt)},x.minimum=x.min=function(){return R(arguments,y.gt)},x.random=(n=9007199254740992*Math.random()&2097151?function(){return o(9007199254740992*Math.random())}:function(){return 8388608*(1073741824*Math.random()|0)+(8388608*Math.random()|0)},function(A){var I,i,e,r,g,a=0,f=[],u=new x(d);if(null==A?A=p:Q(A,0,1e9),r=t(A/14),H)if(crypto.getRandomValues){for(I=crypto.getRandomValues(new Uint32Array(r*=2));a<r;)(g=131072*I[a]+(I[a+1]>>>11))>=9e15?(i=crypto.getRandomValues(new Uint32Array(2)),I[a]=i[0],I[a+1]=i[1]):(f.push(g%1e14),a+=2);a=r/2}else{if(!crypto.randomBytes)throw H=!1,Error(C+"crypto unavailable");for(I=crypto.randomBytes(r*=7);a<r;)(g=281474976710656*(31&I[a])+1099511627776*I[a+1]+4294967296*I[a+2]+16777216*I[a+3]+(I[a+4]<<16)+(I[a+5]<<8)+I[a+6])>=9e15?crypto.randomBytes(7).copy(I,a):(f.push(g%1e14),a+=7);a=r/7}if(!H)for(;a<r;)(g=n())<9e15&&(f[a++]=g%1e14);for(A%=14,(r=f[--a])&&A&&(g=h[14-A],f[a]=o(r/g)*g);0===f[a];f.pop(),a--);if(a<0)f=[e=0];else{for(e=-1;0===f[0];f.splice(0,1),e-=14);for(a=1,g=f[0];g>=10;g/=10,a++);a<14&&(e-=14-a)}return u.e=e,u.c=f,u}),x.sum=function(){for(var A=1,I=arguments,i=new x(I[0]);A<I.length;)i=i.plus(I[A++]);return i},e=function(){function A(A,I,i,e){for(var r,n,g=[0],t=0,o=A.length;t<o;){for(n=g.length;n--;g[n]*=I);for(g[0]+=e.indexOf(A.charAt(t++)),r=0;r<g.length;r++)g[r]>i-1&&(null==g[r+1]&&(g[r+1]=0),g[r+1]+=g[r]/i|0,g[r]%=i)}return g.reverse()}return function(I,e,r,n,g){var t,o,C,a,h,f,s,Q,B=I.indexOf("."),E=p,l=G;for(B>=0&&(a=M,M=0,I=I.replace(".",""),f=(Q=new x(e)).pow(I.length-B),M=a,Q.c=A(c(u(f.c),f.e,"0"),10,r,"0123456789"),Q.e=Q.c.length),C=a=(s=A(I,e,r,g?(t=N,"0123456789"):(t="0123456789",N))).length;0==s[--a];s.pop());if(!s[0])return t.charAt(0);if(B<0?--C:(f.c=s,f.e=C,f.s=n,s=(f=i(f,Q,E,l,r)).c,h=f.r,C=f.e),B=s[o=C+E+1],a=r/2,h=h||o<0||null!=s[o+1],h=l<4?(null!=B||h)&&(0==l||l==(f.s<0?3:2)):B>a||B==a&&(4==l||h||6==l&&1&s[o-1]||l==(f.s<0?8:7)),o<1||!s[0])I=h?c(t.charAt(1),-E,t.charAt(0)):t.charAt(0);else{if(s.length=o,h)for(--r;++s[--o]>r;)s[o]=0,o||(++C,s=[1].concat(s));for(a=s.length;!s[--a];);for(B=0,I="";B<=a;I+=t.charAt(s[B++]));I=c(I,C,t.charAt(0))}return I}}(),i=function(){function A(A,I,i){var e,r,n,g,t=0,o=A.length,C=I%1e7,a=I/1e7|0;for(A=A.slice();o--;)t=((r=C*(n=A[o]%1e7)+(e=a*n+(g=A[o]/1e7|0)*C)%1e7*1e7+t)/i|0)+(e/1e7|0)+a*g,A[o]=r%i;return t&&(A=[t].concat(A)),A}function I(A,I,i,e){var r,n;if(i!=e)n=i>e?1:-1;else for(r=n=0;r<i;r++)if(A[r]!=I[r]){n=A[r]>I[r]?1:-1;break}return n}function i(A,I,i,e){for(var r=0;i--;)A[i]-=r,r=A[i]<I[i]?1:0,A[i]=r*e+A[i]-I[i];for(;!A[0]&&A.length>1;A.splice(0,1));}return function(e,r,n,g,t){var C,a,h,u,s,Q,B,E,c,l,w,U,S,F,y,d,p,G=e.s==r.s?1:-1,D=e.c,v=r.c;if(!(D&&D[0]&&v&&v[0]))return new x(e.s&&r.s&&(D?!v||D[0]!=v[0]:v)?D&&0==D[0]||!v?0*G:G/0:NaN);for(c=(E=new x(G)).c=[],G=n+(a=e.e-r.e)+1,t||(t=1e14,a=f(e.e/14)-f(r.e/14),G=G/14|0),h=0;v[h]==(D[h]||0);h++);if(v[h]>(D[h]||0)&&a--,G<0)c.push(1),u=!0;else{for(F=D.length,d=v.length,h=0,G+=2,(s=o(t/(v[0]+1)))>1&&(v=A(v,s,t),D=A(D,s,t),d=v.length,F=D.length),S=d,w=(l=D.slice(0,d)).length;w<d;l[w++]=0);p=v.slice(),p=[0].concat(p),y=v[0],v[1]>=t/2&&y++;do{if(s=0,(C=I(v,l,d,w))<0){if(U=l[0],d!=w&&(U=U*t+(l[1]||0)),(s=o(U/y))>1)for(s>=t&&(s=t-1),B=(Q=A(v,s,t)).length,w=l.length;1==I(Q,l,B,w);)s--,i(Q,d<B?p:v,B,t),B=Q.length,C=1;else 0==s&&(C=s=1),B=(Q=v.slice()).length;if(B<w&&(Q=[0].concat(Q)),i(l,Q,w,t),w=l.length,-1==C)for(;I(v,l,d,w)<1;)s++,i(l,d<w?p:v,w,t),w=l.length}else 0===C&&(s++,l=[0]);c[h++]=s,l[0]?l[w++]=D[S]||0:(l=[D[S]],w=1)}while((S++<F||null!=l[0])&&G--);u=null!=l[0],c[0]||c.splice(0,1)}if(1e14==t){for(h=1,G=c[0];G>=10;G/=10,h++);O(E,n+(E.e=h+14*a-1)+1,g,u)}else E.e=a,E.r=+u;return E}}(),l=/^(-?)0([xbo])(?=\w[\w.]*$)/i,w=/^([^.]+)\.$/,U=/^\.([^.]+)$/,S=/^-?(Infinity|NaN)$/,F=/^\s*\+(?=[\w.])|^\s+|\s+$/g,r=function(A,I,i,e){var r,n=i?I:I.replace(F,"");if(S.test(n))A.s=isNaN(n)?null:n<0?-1:1;else{if(!i&&(n=n.replace(l,(function(A,I,i){return r="x"==(i=i.toLowerCase())?16:"b"==i?2:8,e&&e!=r?A:I})),e&&(r=e,n=n.replace(w,"$1").replace(U,"0.$1")),I!=n))return new x(n,r);if(x.DEBUG)throw Error(C+"Not a"+(e?" base "+e:"")+" number: "+I);A.s=null}A.c=A.e=null},y.absoluteValue=y.abs=function(){var A=new x(this);return A.s<0&&(A.s=1),A},y.comparedTo=function(A,I){return s(this,new x(A,I))},y.decimalPlaces=y.dp=function(A,I){var i,e,r,n=this;if(null!=A)return Q(A,0,1e9),null==I?I=G:Q(I,0,8),O(new x(n),A+n.e+1,I);if(!(i=n.c))return null;if(e=14*((r=i.length-1)-f(this.e/14)),r=i[r])for(;r%10==0;r/=10,e--);return e<0&&(e=0),e},y.dividedBy=y.div=function(A,I){return i(this,new x(A,I),p,G)},y.dividedToIntegerBy=y.idiv=function(A,I){return i(this,new x(A,I),0,1)},y.exponentiatedBy=y.pow=function(A,I){var i,e,r,n,g,a,h,f,u=this;if((A=new x(A)).c&&!A.isInteger())throw Error(C+"Exponent not an integer: "+P(A));if(null!=I&&(I=new x(I)),g=A.e>14,!u.c||!u.c[0]||1==u.c[0]&&!u.e&&1==u.c.length||!A.c||!A.c[0])return f=new x(Math.pow(+P(u),g?2-B(A):+P(A))),I?f.mod(I):f;if(a=A.s<0,I){if(I.c?!I.c[0]:!I.s)return new x(NaN);(e=!a&&u.isInteger()&&I.isInteger())&&(u=u.mod(I))}else{if(A.e>9&&(u.e>0||u.e<-1||(0==u.e?u.c[0]>1||g&&u.c[1]>=24e7:u.c[0]<8e13||g&&u.c[0]<=9999975e7)))return n=u.s<0&&B(A)?-0:0,u.e>-1&&(n=1/n),new x(a?1/n:n);M&&(n=t(M/14+2))}for(g?(i=new x(.5),a&&(A.s=1),h=B(A)):h=(r=Math.abs(+P(A)))%2,f=new x(d);;){if(h){if(!(f=f.times(u)).c)break;n?f.c.length>n&&(f.c.length=n):e&&(f=f.mod(I))}if(r){if(0===(r=o(r/2)))break;h=r%2}else if(O(A=A.times(i),A.e+1,1),A.e>14)h=B(A);else{if(0===(r=+P(A)))break;h=r%2}u=u.times(u),n?u.c&&u.c.length>n&&(u.c.length=n):e&&(u=u.mod(I))}return e?f:(a&&(f=d.div(f)),I?f.mod(I):n?O(f,M,G,void 0):f)},y.integerValue=function(A){var I=new x(this);return null==A?A=G:Q(A,0,8),O(I,I.e+1,A)},y.isEqualTo=y.eq=function(A,I){return 0===s(this,new x(A,I))},y.isFinite=function(){return!!this.c},y.isGreaterThan=y.gt=function(A,I){return s(this,new x(A,I))>0},y.isGreaterThanOrEqualTo=y.gte=function(A,I){return 1===(I=s(this,new x(A,I)))||0===I},y.isInteger=function(){return!!this.c&&f(this.e/14)>this.c.length-2},y.isLessThan=y.lt=function(A,I){return s(this,new x(A,I))<0},y.isLessThanOrEqualTo=y.lte=function(A,I){return-1===(I=s(this,new x(A,I)))||0===I},y.isNaN=function(){return!this.s},y.isNegative=function(){return this.s<0},y.isPositive=function(){return this.s>0},y.isZero=function(){return!!this.c&&0==this.c[0]},y.minus=function(A,I){var i,e,r,n,g=this,t=g.s;if(I=(A=new x(A,I)).s,!t||!I)return new x(NaN);if(t!=I)return A.s=-I,g.plus(A);var o=g.e/14,C=A.e/14,a=g.c,h=A.c;if(!o||!C){if(!a||!h)return a?(A.s=-I,A):new x(h?g:NaN);if(!a[0]||!h[0])return h[0]?(A.s=-I,A):new x(a[0]?g:3==G?-0:0)}if(o=f(o),C=f(C),a=a.slice(),t=o-C){for((n=t<0)?(t=-t,r=a):(C=o,r=h),r.reverse(),I=t;I--;r.push(0));r.reverse()}else for(e=(n=(t=a.length)<(I=h.length))?t:I,t=I=0;I<e;I++)if(a[I]!=h[I]){n=a[I]<h[I];break}if(n&&(r=a,a=h,h=r,A.s=-A.s),(I=(e=h.length)-(i=a.length))>0)for(;I--;a[i++]=0);for(I=1e14-1;e>t;){if(a[--e]<h[e]){for(i=e;i&&!a[--i];a[i]=I);--a[i],a[e]+=1e14}a[e]-=h[e]}for(;0==a[0];a.splice(0,1),--C);return a[0]?L(A,a,C):(A.s=3==G?-1:1,A.c=[A.e=0],A)},y.modulo=y.mod=function(A,I){var e,r,n=this;return A=new x(A,I),!n.c||!A.s||A.c&&!A.c[0]?new x(NaN):!A.c||n.c&&!n.c[0]?new x(n):(9==m?(r=A.s,A.s=1,e=i(n,A,0,3),A.s=r,e.s*=r):e=i(n,A,0,m),(A=n.minus(e.times(A))).c[0]||1!=m||(A.s=n.s),A)},y.multipliedBy=y.times=function(A,I){var i,e,r,n,g,t,o,C,a,h,u,s,Q,B=this,E=B.c,c=(A=new x(A,I)).c;if(!(E&&c&&E[0]&&c[0]))return!B.s||!A.s||E&&!E[0]&&!c||c&&!c[0]&&!E?A.c=A.e=A.s=null:(A.s*=B.s,E&&c?(A.c=[0],A.e=0):A.c=A.e=null),A;for(e=f(B.e/14)+f(A.e/14),A.s*=B.s,(o=E.length)<(h=c.length)&&(Q=E,E=c,c=Q,r=o,o=h,h=r),r=o+h,Q=[];r--;Q.push(0));for(1e14,1e7,r=h;--r>=0;){for(i=0,u=c[r]%1e7,s=c[r]/1e7|0,n=r+(g=o);n>r;)i=((C=u*(C=E[--g]%1e7)+(t=s*C+(a=E[g]/1e7|0)*u)%1e7*1e7+Q[n]+i)/1e14|0)+(t/1e7|0)+s*a,Q[n--]=C%1e14;Q[n]=i}return i?++e:Q.splice(0,1),L(A,Q,e)},y.negated=function(){var A=new x(this);return A.s=-A.s||null,A},y.plus=function(A,I){var i,e=this,r=e.s;if(I=(A=new x(A,I)).s,!r||!I)return new x(NaN);if(r!=I)return A.s=-I,e.minus(A);var n=e.e/14,g=A.e/14,t=e.c,o=A.c;if(!n||!g){if(!t||!o)return new x(r/0);if(!t[0]||!o[0])return o[0]?A:new x(t[0]?e:0*r)}if(n=f(n),g=f(g),t=t.slice(),r=n-g){for(r>0?(g=n,i=o):(r=-r,i=t),i.reverse();r--;i.push(0));i.reverse()}for((r=t.length)-(I=o.length)<0&&(i=o,o=t,t=i,I=r),r=0;I;)r=(t[--I]=t[I]+o[I]+r)/1e14|0,t[I]=1e14===t[I]?0:t[I]%1e14;return r&&(t=[r].concat(t),++g),L(A,t,g)},y.precision=y.sd=function(A,I){var i,e,r,n=this;if(null!=A&&A!==!!A)return Q(A,1,1e9),null==I?I=G:Q(I,0,8),O(new x(n),A,I);if(!(i=n.c))return null;if(e=14*(r=i.length-1)+1,r=i[r]){for(;r%10==0;r/=10,e--);for(r=i[0];r>=10;r/=10,e++);}return A&&n.e+1>e&&(e=n.e+1),e},y.shiftedBy=function(A){return Q(A,-9007199254740991,9007199254740991),this.times("1e"+A)},y.squareRoot=y.sqrt=function(){var A,I,e,r,n,g=this,t=g.c,o=g.s,C=g.e,a=p+4,h=new x("0.5");if(1!==o||!t||!t[0])return new x(!o||o<0&&(!t||t[0])?NaN:t?g:1/0);if(0==(o=Math.sqrt(+P(g)))||o==1/0?(((I=u(t)).length+C)%2==0&&(I+="0"),o=Math.sqrt(+I),C=f((C+1)/2)-(C<0||C%2),e=new x(I=o==1/0?"1e"+C:(I=o.toExponential()).slice(0,I.indexOf("e")+1)+C)):e=new x(o+""),e.c[0])for((o=(C=e.e)+a)<3&&(o=0);;)if(n=e,e=h.times(n.plus(i(g,n,a,1))),u(n.c).slice(0,o)===(I=u(e.c)).slice(0,o)){if(e.e<C&&--o,"9999"!=(I=I.slice(o-3,o+1))&&(r||"4999"!=I)){+I&&(+I.slice(1)||"5"!=I.charAt(0))||(O(e,e.e+p+2,1),A=!e.times(e).eq(g));break}if(!r&&(O(n,n.e+p+2,0),n.times(n).eq(g))){e=n;break}a+=4,o+=4,r=1}return O(e,e.e+p+1,G,A)},y.toExponential=function(A,I){return null!=A&&(Q(A,0,1e9),A++),K(this,A,I,1)},y.toFixed=function(A,I){return null!=A&&(Q(A,0,1e9),A=A+this.e+1),K(this,A,I)},y.toFormat=function(A,I,i){var e,r=this;if(null==i)null!=A&&I&&"object"==typeof I?(i=I,I=null):A&&"object"==typeof A?(i=A,A=I=null):i=Y;else if("object"!=typeof i)throw Error(C+"Argument not an object: "+i);if(e=r.toFixed(A,I),r.c){var n,g=e.split("."),t=+i.groupSize,o=+i.secondaryGroupSize,a=i.groupSeparator||"",h=g[0],f=g[1],u=r.s<0,s=u?h.slice(1):h,Q=s.length;if(o&&(n=t,t=o,o=n,Q-=n),t>0&&Q>0){for(n=Q%t||t,h=s.substr(0,n);n<Q;n+=t)h+=a+s.substr(n,t);o>0&&(h+=a+s.slice(n)),u&&(h="-"+h)}e=f?h+(i.decimalSeparator||"")+((o=+i.fractionGroupSize)?f.replace(new RegExp("\\d{"+o+"}\\B","g"),"$&"+(i.fractionGroupSeparator||"")):f):h}return(i.prefix||"")+e+(i.suffix||"")},y.toFraction=function(A){var I,e,r,n,g,t,o,a,f,s,Q,B,E=this,c=E.c;if(null!=A&&(!(o=new x(A)).isInteger()&&(o.c||1!==o.s)||o.lt(d)))throw Error(C+"Argument "+(o.isInteger()?"out of range: ":"not an integer: ")+P(o));if(!c)return new x(E);for(I=new x(d),f=e=new x(d),r=a=new x(d),B=u(c),g=I.e=B.length-E.e-1,I.c[0]=h[(t=g%14)<0?14+t:t],A=!A||o.comparedTo(I)>0?g>0?I:f:o,t=b,b=1/0,o=new x(B),a.c[0]=0;s=i(o,I,0,1),1!=(n=e.plus(s.times(r))).comparedTo(A);)e=r,r=n,f=a.plus(s.times(n=f)),a=n,I=o.minus(s.times(n=I)),o=n;return n=i(A.minus(e),r,0,1),a=a.plus(n.times(f)),e=e.plus(n.times(r)),a.s=f.s=E.s,Q=i(f,r,g*=2,G).minus(E).abs().comparedTo(i(a,e,g,G).minus(E).abs())<1?[f,r]:[a,e],b=t,Q},y.toNumber=function(){return+P(this)},y.toPrecision=function(A,I){return null!=A&&Q(A,1,1e9),K(this,A,I,2)},y.toString=function(A){var I,i=this,r=i.s,n=i.e;return null===n?r?(I="Infinity",r<0&&(I="-"+I)):I="NaN":(null==A?I=n<=D||n>=v?E(u(i.c),n):c(u(i.c),n,"0"):10===A?I=c(u((i=O(new x(i),p+n+1,G)).c),i.e,"0"):(Q(A,2,N.length,"Base"),I=e(c(u(i.c),n,"0"),10,A,r,!0)),r<0&&i.c[0]&&(I="-"+I)),I},y.valueOf=y.toJSON=function(){return P(this)},y._isBigNumber=!0,y[Symbol.toStringTag]="BigNumber",y[Symbol.for("nodejs.util.inspect.custom")]=y.valueOf,null!=I&&x.set(I),x}();function w(A){return(4294967296+A).toString(16).substring(1)}var U={normalizeInput:function(A){var I;if(A instanceof Uint8Array)I=A;else if(A instanceof Buffer)I=new Uint8Array(A);else{if("string"!=typeof A)throw new Error("Input must be an string, Buffer or Uint8Array");I=new Uint8Array(Buffer.from(A,"utf8"))}return I},toHex:function(A){return Array.prototype.map.call(A,(function(A){return(A<16?"0":"")+A.toString(16)})).join("")},debugPrint:function(A,I,i){for(var e="\n"+A+" = ",r=0;r<I.length;r+=2){if(32===i)e+=w(I[r]).toUpperCase(),e+=" ",e+=w(I[r+1]).toUpperCase();else{if(64!==i)throw new Error("Invalid size "+i);e+=w(I[r+1]).toUpperCase(),e+=w(I[r]).toUpperCase()}r%6==4?e+="\n"+new Array(A.length+4).join(" "):r<I.length-2&&(e+=" ")}console.log(e)},testSpeed:function(A,I,i){for(var e=(new Date).getTime(),r=new Uint8Array(I),n=0;n<I;n++)r[n]=n%256;var g=(new Date).getTime();for(console.log("Generated random input in "+(g-e)+"ms"),e=g,n=0;n<i;n++){var t=A(r),o=(new Date).getTime(),C=o-e;e=o,console.log("Hashed in "+C+"ms: "+t.substring(0,20)+"..."),console.log(Math.round(I/(1<<20)/(C/1e3)*100)/100+" MB PER SECOND")}}};function S(A,I,i){var e=A[I]+A[i],r=A[I+1]+A[i+1];e>=4294967296&&r++,A[I]=e,A[I+1]=r}function F(A,I,i,e){var r=A[I]+i;i<0&&(r+=4294967296);var n=A[I+1]+e;r>=4294967296&&n++,A[I]=r,A[I+1]=n}function y(A,I){return A[I]^A[I+1]<<8^A[I+2]<<16^A[I+3]<<24}function d(A,I,i,e,r,n){var g=v[r],t=v[r+1],o=v[n],C=v[n+1];S(D,A,I),F(D,A,g,t);var a=D[e]^D[A],h=D[e+1]^D[A+1];D[e]=h,D[e+1]=a,S(D,i,e),a=D[I]^D[i],h=D[I+1]^D[i+1],D[I]=a>>>24^h<<8,D[I+1]=h>>>24^a<<8,S(D,A,I),F(D,A,o,C),a=D[e]^D[A],h=D[e+1]^D[A+1],D[e]=a>>>16^h<<16,D[e+1]=h>>>16^a<<16,S(D,i,e),a=D[I]^D[i],h=D[I+1]^D[i+1],D[I]=h>>>31^a<<1,D[I+1]=a>>>31^h<<1}var p=new Uint32Array([4089235720,1779033703,2227873595,3144134277,4271175723,1013904242,1595750129,2773480762,2917565137,1359893119,725511199,2600822924,4215389547,528734635,327033209,1541459225]),G=new Uint8Array([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3,11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4,7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8,9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13,2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9,12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11,13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10,6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5,10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3].map((function(A){return 2*A}))),D=new Uint32Array(32),v=new Uint32Array(32);function k(A,I){var i=0;for(i=0;i<16;i++)D[i]=A.h[i],D[i+16]=p[i];for(D[24]=D[24]^A.t,D[25]=D[25]^A.t/4294967296,I&&(D[28]=~D[28],D[29]=~D[29]),i=0;i<32;i++)v[i]=y(A.b,4*i);for(i=0;i<12;i++)d(0,8,16,24,G[16*i+0],G[16*i+1]),d(2,10,18,26,G[16*i+2],G[16*i+3]),d(4,12,20,28,G[16*i+4],G[16*i+5]),d(6,14,22,30,G[16*i+6],G[16*i+7]),d(0,10,20,30,G[16*i+8],G[16*i+9]),d(2,12,22,24,G[16*i+10],G[16*i+11]),d(4,14,16,26,G[16*i+12],G[16*i+13]),d(6,8,18,28,G[16*i+14],G[16*i+15]);for(i=0;i<16;i++)A.h[i]=A.h[i]^D[i]^D[i+16]}function b(A,I){if(0===A||A>64)throw new Error("Illegal output length, expected 0 < length <= 64");if(I&&I.length>64)throw new Error("Illegal key, expected Uint8Array with 0 < length <= 64");for(var i={b:new Uint8Array(128),h:new Uint32Array(16),t:0,c:0,outlen:A},e=0;e<16;e++)i.h[e]=p[e];var r=I?I.length:0;return i.h[0]^=16842752^r<<8^A,I&&(H(i,I),i.c=128),i}function H(A,I){for(var i=0;i<I.length;i++)128===A.c&&(A.t+=A.c,k(A,!1),A.c=0),A.b[A.c++]=I[i]}function m(A){for(A.t+=A.c;A.c<128;)A.b[A.c++]=0;k(A,!0);for(var I=new Uint8Array(A.outlen),i=0;i<A.outlen;i++)I[i]=A.h[i>>2]>>8*(3&i);return I}function M(A,I,i){i=i||64,A=U.normalizeInput(A);var e=b(i,I);return H(e,A),m(e)}var Y={blake2b:M,blake2bHex:function(A,I,i){var e=M(A,I,i);return U.toHex(e)},blake2bInit:b,blake2bUpdate:H,blake2bFinal:m};function N(A,I){return A[I]^A[I+1]<<8^A[I+2]<<16^A[I+3]<<24}function x(A,I,i,e,r,n){O[A]=O[A]+O[I]+r,O[e]=K(O[e]^O[A],16),O[i]=O[i]+O[e],O[I]=K(O[I]^O[i],12),O[A]=O[A]+O[I]+n,O[e]=K(O[e]^O[A],8),O[i]=O[i]+O[e],O[I]=K(O[I]^O[i],7)}function K(A,I){return A>>>I^A<<32-I}var R=new Uint32Array([1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225]),L=new Uint8Array([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3,11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4,7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8,9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13,2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9,12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11,13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10,6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5,10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0]),O=new Uint32Array(16),P=new Uint32Array(16);function j(A,I){var i=0;for(i=0;i<8;i++)O[i]=A.h[i],O[i+8]=R[i];for(O[12]^=A.t,O[13]^=A.t/4294967296,I&&(O[14]=~O[14]),i=0;i<16;i++)P[i]=N(A.b,4*i);for(i=0;i<10;i++)x(0,4,8,12,P[L[16*i+0]],P[L[16*i+1]]),x(1,5,9,13,P[L[16*i+2]],P[L[16*i+3]]),x(2,6,10,14,P[L[16*i+4]],P[L[16*i+5]]),x(3,7,11,15,P[L[16*i+6]],P[L[16*i+7]]),x(0,5,10,15,P[L[16*i+8]],P[L[16*i+9]]),x(1,6,11,12,P[L[16*i+10]],P[L[16*i+11]]),x(2,7,8,13,P[L[16*i+12]],P[L[16*i+13]]),x(3,4,9,14,P[L[16*i+14]],P[L[16*i+15]]);for(i=0;i<8;i++)A.h[i]^=O[i]^O[i+8]}function J(A,I){if(!(A>0&&A<=32))throw new Error("Incorrect output length, should be in [1, 32]");var i=I?I.length:0;if(I&&!(i>0&&i<=32))throw new Error("Incorrect key length, should be in [1, 32]");var e={h:new Uint32Array(R),b:new Uint32Array(64),c:0,t:0,outlen:A};return e.h[0]^=16842752^i<<8^A,i>0&&(X(e,I),e.c=64),e}function X(A,I){for(var i=0;i<I.length;i++)64===A.c&&(A.t+=A.c,j(A,!1),A.c=0),A.b[A.c++]=I[i]}function T(A){for(A.t+=A.c;A.c<64;)A.b[A.c++]=0;j(A,!0);for(var I=new Uint8Array(A.outlen),i=0;i<A.outlen;i++)I[i]=A.h[i>>2]>>8*(3&i)&255;return I}function V(A,I,i){i=i||32,A=U.normalizeInput(A);var e=J(i,I);return X(e,A),T(e)}var q,Z={blake2s:V,blake2sHex:function(A,I,i){var e=V(A,I,i);return U.toHex(e)},blake2sInit:J,blake2sUpdate:X,blake2sFinal:T},W={blake2b:Y.blake2b,blake2bHex:Y.blake2bHex,blake2bInit:Y.blake2bInit,blake2bUpdate:Y.blake2bUpdate,blake2bFinal:Y.blake2bFinal,blake2s:Z.blake2s,blake2sHex:Z.blake2sHex,blake2sInit:Z.blake2sInit,blake2sUpdate:Z.blake2sUpdate,blake2sFinal:Z.blake2sFinal},_=W.blake2b,z=W.blake2bInit,$=W.blake2bUpdate,AA=W.blake2bFinal;if("[object process]"===Object.prototype.toString.call("undefined"!=typeof process?process:0)){var IA=require("util").promisify;q=IA(require("crypto").randomFill)}else q=function(A){return new Promise((function(I){crypto.getRandomValues(A),I()}))};function iA(A){if(!A)return"";for(var I="",i=0;i<A.length;i++){var e=(255&A[i]).toString(16);I+=e=1===e.length?"0"+e:e}return I.toUpperCase()}function eA(A){if(!A)return new Uint8Array;for(var I=[],i=0;i<A.length;i+=2)I.push(parseInt(A.substr(i,2),16));return new Uint8Array(I)}var rA="13456789abcdefghijkmnopqrstuwxyz";function nA(A){for(var I=A.length,i=8*I%5,e=0===i?0:5-i,r=0,n="",g=0,t=0;t<I;t++)for(r=r<<8|A[t],g+=8;g>=5;)n+=rA[r>>>g+e-5&31],g-=5;return g>0&&(n+=rA[r<<5-(g+e)&31]),n}function gA(A){var I=rA.indexOf(A);if(-1===I)throw new Error("Invalid character found: "+A);return I}function tA(A){for(var I=A.length,i=5*I%8,e=0===i?0:8-i,r=0,n=0,g=0,t=new Uint8Array(Math.ceil(5*I/8)),o=0;o<I;o++)n=n<<5|gA(A[o]),(r+=5)>=8&&(t[g++]=n>>>r+e-8&255,r-=8);return r>0&&(t[g++]=n<<r+e-8&255),0!==i&&(t=t.slice(1)),t}
/*!
     * nanocurrency-js: A toolkit for the Nano cryptocurrency.
     * Copyright (c) 2019 Marvin ROGER <dev at marvinroger dot fr>
     * Licensed under GPL-3.0 (https://git.io/vAZsK)
     */function oA(A){var I,i={valid:!1,publicKeyBytes:null};if(!hA(A)||!/^(xrb_|nano_)[13][13-9a-km-uw-z]{59}$/.test(A))return i;I=A.startsWith("xrb_")?4:5;var e=tA(A.substr(I,52));return function(A,I){for(var i=0;i<A.length;i++)if(A[i]!==I[i])return!1;return!0}(tA(A.substr(I+52)),_(e,null,5).reverse())?{publicKeyBytes:e,valid:!0}:i}
/*!
     * nanocurrency-js: A toolkit for the Nano cryptocurrency.
     * Copyright (c) 2019 Marvin ROGER <dev at marvinroger dot fr>
     * Licensed under GPL-3.0 (https://git.io/vAZsK)
     */var CA=Math.pow(2,32)-1,aA=new l("0xffffffffffffffffffffffffffffffff");function hA(A){return"string"==typeof A}function fA(A){return"0"===A||!(!hA(A)||!/^[1-9]{1}[0-9]{0,38}$/.test(A))&&new l(A).isLessThanOrEqualTo(aA)}function uA(A){return hA(A)&&/^[0-9a-fA-F]{64}$/.test(A)}function sA(A){return hA(A)&&/^[0-9a-fA-F]{16}$/.test(A)}function QA(A){return Number.isInteger(A)&&A>=0&&A<=CA}function BA(A){return uA(A)}function EA(A){return uA(A)}function cA(A){return oA(A).valid}function lA(A){return hA(A)&&/^[0-9a-fA-F]{16}$/.test(A)}function wA(A){return hA(A)&&/^[0-9a-fA-F]{128}$/.test(A)}
/*!
     * nanocurrency-js: A toolkit for the Nano cryptocurrency.
     * Copyright (c) 2019 Marvin ROGER <dev at marvinroger dot fr>
     * Licensed under GPL-3.0 (https://git.io/vAZsK)
     */var UA={loaded:!1,work:null};function SA(){return new Promise((function(A,I){if(UA.loaded)return A(UA);try{n().then((function(I){var i=Object.assign(UA,{loaded:!0,work:I.cwrap("emscripten_work","string",["string","string","number","number"])});A(i)}))}catch(A){I(A)}}))}
/*!
     * nanocurrency-js: A toolkit for the Nano cryptocurrency.
     * Copyright (c) 2019 Marvin ROGER <dev at marvinroger dot fr>
     * Licensed under GPL-3.0 (https://git.io/vAZsK)
     */
var FA=function(A){var I=new Float64Array(16);if(A)for(var i=0;i<A.length;i++)I[i]=A[i];return I};new Uint8Array(32)[0]=9;var yA=FA(),dA=FA([1]),pA=FA([30883,4953,19914,30187,55467,16705,2637,112,59544,30585,16505,36039,65139,11119,27886,20995]),GA=FA([61785,9906,39828,60374,45398,33411,5274,224,53552,61171,33010,6542,64743,22239,55772,9222]),DA=FA([54554,36645,11616,51542,42930,38181,51040,26924,56412,64982,57905,49316,21502,52590,14035,8553]),vA=FA([26200,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214]),kA=FA([41136,18958,6951,50414,58488,44335,6150,12099,55207,15867,153,11085,57099,20417,9344,11139]);function bA(A,I,i,e){return function(A,I,i,e,r){for(var n=0,g=0;g<r;g++)n|=A[I+g]^i[e+g];return(1&n-1>>>8)-1}(A,I,i,e,32)}function HA(A,I){var i;for(i=0;i<16;i++)A[i]=0|I[i]}function mA(A){for(var I,i=1,e=0;e<16;e++)I=A[e]+i+65535,i=Math.floor(I/65536),A[e]=I-65536*i;A[0]+=i-1+37*(i-1)}function MA(A,I,i){for(var e,r=~(i-1),n=0;n<16;n++)e=r&(A[n]^I[n]),A[n]^=e,I[n]^=e}function YA(A,I){for(var i,e=FA(),r=FA(),n=0;n<16;n++)r[n]=I[n];mA(r),mA(r),mA(r);for(var g=0;g<2;g++){e[0]=r[0]-65517;for(n=1;n<15;n++)e[n]=r[n]-65535-(e[n-1]>>16&1),e[n-1]&=65535;e[15]=r[15]-32767-(e[14]>>16&1),i=e[15]>>16&1,e[14]&=65535,MA(r,e,1-i)}for(n=0;n<16;n++)A[2*n]=255&r[n],A[2*n+1]=r[n]>>8}function NA(A,I){var i=new Uint8Array(32),e=new Uint8Array(32);return YA(i,A),YA(e,I),bA(i,0,e,0)}function xA(A){var I=new Uint8Array(32);return YA(I,A),1&I[0]}function KA(A,I,i){for(var e=0;e<16;e++)A[e]=I[e]+i[e]}function RA(A,I,i){for(var e=0;e<16;e++)A[e]=I[e]-i[e]}function LA(A,I,i){var e,r,n=0,g=0,t=0,o=0,C=0,a=0,h=0,f=0,u=0,s=0,Q=0,B=0,E=0,c=0,l=0,w=0,U=0,S=0,F=0,y=0,d=0,p=0,G=0,D=0,v=0,k=0,b=0,H=0,m=0,M=0,Y=0,N=i[0],x=i[1],K=i[2],R=i[3],L=i[4],O=i[5],P=i[6],j=i[7],J=i[8],X=i[9],T=i[10],V=i[11],q=i[12],Z=i[13],W=i[14],_=i[15];n+=(e=I[0])*N,g+=e*x,t+=e*K,o+=e*R,C+=e*L,a+=e*O,h+=e*P,f+=e*j,u+=e*J,s+=e*X,Q+=e*T,B+=e*V,E+=e*q,c+=e*Z,l+=e*W,w+=e*_,g+=(e=I[1])*N,t+=e*x,o+=e*K,C+=e*R,a+=e*L,h+=e*O,f+=e*P,u+=e*j,s+=e*J,Q+=e*X,B+=e*T,E+=e*V,c+=e*q,l+=e*Z,w+=e*W,U+=e*_,t+=(e=I[2])*N,o+=e*x,C+=e*K,a+=e*R,h+=e*L,f+=e*O,u+=e*P,s+=e*j,Q+=e*J,B+=e*X,E+=e*T,c+=e*V,l+=e*q,w+=e*Z,U+=e*W,S+=e*_,o+=(e=I[3])*N,C+=e*x,a+=e*K,h+=e*R,f+=e*L,u+=e*O,s+=e*P,Q+=e*j,B+=e*J,E+=e*X,c+=e*T,l+=e*V,w+=e*q,U+=e*Z,S+=e*W,F+=e*_,C+=(e=I[4])*N,a+=e*x,h+=e*K,f+=e*R,u+=e*L,s+=e*O,Q+=e*P,B+=e*j,E+=e*J,c+=e*X,l+=e*T,w+=e*V,U+=e*q,S+=e*Z,F+=e*W,y+=e*_,a+=(e=I[5])*N,h+=e*x,f+=e*K,u+=e*R,s+=e*L,Q+=e*O,B+=e*P,E+=e*j,c+=e*J,l+=e*X,w+=e*T,U+=e*V,S+=e*q,F+=e*Z,y+=e*W,d+=e*_,h+=(e=I[6])*N,f+=e*x,u+=e*K,s+=e*R,Q+=e*L,B+=e*O,E+=e*P,c+=e*j,l+=e*J,w+=e*X,U+=e*T,S+=e*V,F+=e*q,y+=e*Z,d+=e*W,p+=e*_,f+=(e=I[7])*N,u+=e*x,s+=e*K,Q+=e*R,B+=e*L,E+=e*O,c+=e*P,l+=e*j,w+=e*J,U+=e*X,S+=e*T,F+=e*V,y+=e*q,d+=e*Z,p+=e*W,G+=e*_,u+=(e=I[8])*N,s+=e*x,Q+=e*K,B+=e*R,E+=e*L,c+=e*O,l+=e*P,w+=e*j,U+=e*J,S+=e*X,F+=e*T,y+=e*V,d+=e*q,p+=e*Z,G+=e*W,D+=e*_,s+=(e=I[9])*N,Q+=e*x,B+=e*K,E+=e*R,c+=e*L,l+=e*O,w+=e*P,U+=e*j,S+=e*J,F+=e*X,y+=e*T,d+=e*V,p+=e*q,G+=e*Z,D+=e*W,v+=e*_,Q+=(e=I[10])*N,B+=e*x,E+=e*K,c+=e*R,l+=e*L,w+=e*O,U+=e*P,S+=e*j,F+=e*J,y+=e*X,d+=e*T,p+=e*V,G+=e*q,D+=e*Z,v+=e*W,k+=e*_,B+=(e=I[11])*N,E+=e*x,c+=e*K,l+=e*R,w+=e*L,U+=e*O,S+=e*P,F+=e*j,y+=e*J,d+=e*X,p+=e*T,G+=e*V,D+=e*q,v+=e*Z,k+=e*W,b+=e*_,E+=(e=I[12])*N,c+=e*x,l+=e*K,w+=e*R,U+=e*L,S+=e*O,F+=e*P,y+=e*j,d+=e*J,p+=e*X,G+=e*T,D+=e*V,v+=e*q,k+=e*Z,b+=e*W,H+=e*_,c+=(e=I[13])*N,l+=e*x,w+=e*K,U+=e*R,S+=e*L,F+=e*O,y+=e*P,d+=e*j,p+=e*J,G+=e*X,D+=e*T,v+=e*V,k+=e*q,b+=e*Z,H+=e*W,m+=e*_,l+=(e=I[14])*N,w+=e*x,U+=e*K,S+=e*R,F+=e*L,y+=e*O,d+=e*P,p+=e*j,G+=e*J,D+=e*X,v+=e*T,k+=e*V,b+=e*q,H+=e*Z,m+=e*W,M+=e*_,w+=(e=I[15])*N,g+=38*(S+=e*K),t+=38*(F+=e*R),o+=38*(y+=e*L),C+=38*(d+=e*O),a+=38*(p+=e*P),h+=38*(G+=e*j),f+=38*(D+=e*J),u+=38*(v+=e*X),s+=38*(k+=e*T),Q+=38*(b+=e*V),B+=38*(H+=e*q),E+=38*(m+=e*Z),c+=38*(M+=e*W),l+=38*(Y+=e*_),n=(e=(n+=38*(U+=e*x))+(r=1)+65535)-65536*(r=Math.floor(e/65536)),g=(e=g+r+65535)-65536*(r=Math.floor(e/65536)),t=(e=t+r+65535)-65536*(r=Math.floor(e/65536)),o=(e=o+r+65535)-65536*(r=Math.floor(e/65536)),C=(e=C+r+65535)-65536*(r=Math.floor(e/65536)),a=(e=a+r+65535)-65536*(r=Math.floor(e/65536)),h=(e=h+r+65535)-65536*(r=Math.floor(e/65536)),f=(e=f+r+65535)-65536*(r=Math.floor(e/65536)),u=(e=u+r+65535)-65536*(r=Math.floor(e/65536)),s=(e=s+r+65535)-65536*(r=Math.floor(e/65536)),Q=(e=Q+r+65535)-65536*(r=Math.floor(e/65536)),B=(e=B+r+65535)-65536*(r=Math.floor(e/65536)),E=(e=E+r+65535)-65536*(r=Math.floor(e/65536)),c=(e=c+r+65535)-65536*(r=Math.floor(e/65536)),l=(e=l+r+65535)-65536*(r=Math.floor(e/65536)),w=(e=w+r+65535)-65536*(r=Math.floor(e/65536)),n=(e=(n+=r-1+37*(r-1))+(r=1)+65535)-65536*(r=Math.floor(e/65536)),g=(e=g+r+65535)-65536*(r=Math.floor(e/65536)),t=(e=t+r+65535)-65536*(r=Math.floor(e/65536)),o=(e=o+r+65535)-65536*(r=Math.floor(e/65536)),C=(e=C+r+65535)-65536*(r=Math.floor(e/65536)),a=(e=a+r+65535)-65536*(r=Math.floor(e/65536)),h=(e=h+r+65535)-65536*(r=Math.floor(e/65536)),f=(e=f+r+65535)-65536*(r=Math.floor(e/65536)),u=(e=u+r+65535)-65536*(r=Math.floor(e/65536)),s=(e=s+r+65535)-65536*(r=Math.floor(e/65536)),Q=(e=Q+r+65535)-65536*(r=Math.floor(e/65536)),B=(e=B+r+65535)-65536*(r=Math.floor(e/65536)),E=(e=E+r+65535)-65536*(r=Math.floor(e/65536)),c=(e=c+r+65535)-65536*(r=Math.floor(e/65536)),l=(e=l+r+65535)-65536*(r=Math.floor(e/65536)),w=(e=w+r+65535)-65536*(r=Math.floor(e/65536)),n+=r-1+37*(r-1),A[0]=n,A[1]=g,A[2]=t,A[3]=o,A[4]=C,A[5]=a,A[6]=h,A[7]=f,A[8]=u,A[9]=s,A[10]=Q,A[11]=B,A[12]=E,A[13]=c,A[14]=l,A[15]=w}function OA(A,I){LA(A,I,I)}function PA(A,I,i){for(var e=new Uint8Array(i),r=0;r<i;++r)e[r]=I[r];var n=W.blake2b(e);for(r=0;r<64;++r)A[r]=n[r];return 0}function jA(A,I){var i=FA(),e=FA(),r=FA(),n=FA(),g=FA(),t=FA(),o=FA(),C=FA(),a=FA();RA(i,A[1],A[0]),RA(a,I[1],I[0]),LA(i,i,a),KA(e,A[0],A[1]),KA(a,I[0],I[1]),LA(e,e,a),LA(r,A[3],I[3]),LA(r,r,GA),LA(n,A[2],I[2]),KA(n,n,n),RA(g,e,i),RA(t,n,r),KA(o,n,r),KA(C,e,i),LA(A[0],g,t),LA(A[1],C,o),LA(A[2],o,t),LA(A[3],g,C)}function JA(A,I,i){var e;for(e=0;e<4;e++)MA(A[e],I[e],i)}function XA(A,I){var i=FA(),e=FA(),r=FA();!function(A,I){var i,e=FA();for(i=0;i<16;i++)e[i]=I[i];for(i=253;i>=0;i--)OA(e,e),2!==i&&4!==i&&LA(e,e,I);for(i=0;i<16;i++)A[i]=e[i]}(r,I[2]),LA(i,I[0],r),LA(e,I[1],r),YA(A,e),A[31]^=xA(i)<<7}function TA(A,I,i){var e,r;for(HA(A[0],yA),HA(A[1],dA),HA(A[2],dA),HA(A[3],yA),r=255;r>=0;--r)JA(A,I,e=i[r/8|0]>>(7&r)&1),jA(I,A),jA(A,A),JA(A,I,e)}function VA(A,I){var i=[FA(),FA(),FA(),FA()];HA(i[0],DA),HA(i[1],vA),HA(i[2],dA),LA(i[3],DA,vA),TA(A,i,I)}var qA,ZA=new Float64Array([237,211,245,92,26,99,18,88,214,156,247,162,222,249,222,20,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,16]);function WA(A,I){var i,e,r,n;for(e=63;e>=32;--e){for(i=0,r=e-32,n=e-12;r<n;++r)I[r]+=i-16*I[e]*ZA[r-(e-32)],i=I[r]+128>>8,I[r]-=256*i;I[r]+=i,I[e]=0}for(i=0,r=0;r<32;r++)I[r]+=i-(I[31]>>4)*ZA[r],i=I[r]>>8,I[r]&=255;for(r=0;r<32;r++)I[r]-=i*ZA[r];for(e=0;e<32;e++)I[e+1]+=I[e]>>8,A[e]=255&I[e]}function _A(A){for(var I=new Float64Array(64),i=0;i<64;i++)I[i]=A[i];for(i=0;i<64;i++)A[i]=0;WA(A,I)}function zA(A){var I=new Uint8Array(64),i=[FA(),FA(),FA(),FA()],e=new Uint8Array(32),r=W.blake2bInit(64);return W.blake2bUpdate(r,A),(I=W.blake2bFinal(r))[0]&=248,I[31]&=127,I[31]|=64,VA(i,I),XA(e,i),e}function $A(A,I){var i=FA(),e=FA(),r=FA(),n=FA(),g=FA(),t=FA(),o=FA();return HA(A[2],dA),function(A,I){var i;for(i=0;i<16;i++)A[i]=I[2*i]+(I[2*i+1]<<8);A[15]&=32767}(A[1],I),OA(r,A[1]),LA(n,r,pA),RA(r,r,A[2]),KA(n,A[2],n),OA(g,n),OA(t,g),LA(o,t,g),LA(i,o,r),LA(i,i,n),function(A,I){var i,e=FA();for(i=0;i<16;i++)e[i]=I[i];for(i=250;i>=0;i--)OA(e,e),1!==i&&LA(e,e,I);for(i=0;i<16;i++)A[i]=e[i]}(i,i),LA(i,i,r),LA(i,i,n),LA(i,i,n),LA(A[0],i,n),OA(e,A[0]),LA(e,e,n),NA(e,r)&&LA(A[0],A[0],kA),OA(e,A[0]),LA(e,e,n),NA(e,r)?-1:(xA(A[0])===I[31]>>7&&RA(A[0],yA,A[0]),LA(A[3],A[0],A[1]),0)}function AI(A,I){if(32!==I.length)throw new Error("bad secret key size");var i=new Uint8Array(64+A.length);return function(A,I,i,e){var r,n,g=new Uint8Array(64),t=new Uint8Array(64),o=new Uint8Array(64),C=new Float64Array(64),a=[FA(),FA(),FA(),FA()],h=zA(e);PA(g,e,32),g[0]&=248,g[31]&=127,g[31]|=64;var f=i+64;for(r=0;r<i;r++)A[64+r]=I[r];for(r=0;r<32;r++)A[32+r]=g[32+r];for(PA(o,A.subarray(32),i+32),_A(o),VA(a,o),XA(A,a),r=32;r<64;r++)A[r]=h[r-32];for(PA(t,A,i+64),_A(t),r=0;r<64;r++)C[r]=0;for(r=0;r<32;r++)C[r]=o[r];for(r=0;r<32;r++)for(n=0;n<32;n++)C[r+n]+=t[r]*g[n];WA(A.subarray(32),C)}(i,A,A.length,I),i}function II(A,I,i){if(64!==I.length)throw new Error("bad signature size");if(32!==i.length)throw new Error("bad public key size");var e,r=new Uint8Array(64+A.length),n=new Uint8Array(64+A.length);for(e=0;e<64;e++)r[e]=I[e];for(e=0;e<A.length;e++)r[e+64]=A[e];return function(A,I,i,e){var r,n=new Uint8Array(32),g=new Uint8Array(64),t=[FA(),FA(),FA(),FA()],o=[FA(),FA(),FA(),FA()];if(-1,i<64)return-1;if($A(o,e))return-1;for(r=0;r<i;r++)A[r]=I[r];for(r=0;r<32;r++)A[r+32]=e[r];if(PA(g,A,i),_A(g),TA(t,o,g),VA(o,I.subarray(32)),jA(t,o),XA(n,t),i-=64,bA(I,0,n,0)){for(r=0;r<i;r++)A[r]=0;return-1}for(r=0;r<i;r++)A[r]=I[r+64];return i}(n,r,r.length,i)>=0}
/*!
     * nanocurrency-js: A toolkit for the Nano cryptocurrency.
     * Copyright (c) 2019 Marvin ROGER <dev at marvinroger dot fr>
     * Licensed under GPL-3.0 (https://git.io/vAZsK)
     */function iI(A){var I,i=EA(A),e=oA(A),r=e.valid;if(!i&&!r)throw new Error("Secret key or address is not valid");i?I=zA(eA(A)):I=e.publicKeyBytes;return iA(I)}function eI(A,I){if(void 0===I&&(I={}),!EA(A))throw new Error("Public key is not valid");var i=eA(A),e=eA(A),r="xrb_";return!0===I.useNanoPrefix&&(r="nano_"),r+nA(e)+nA(_(i,null,5).reverse())}
/*!
     * nanocurrency-js: A toolkit for the Nano cryptocurrency.
     * Copyright (c) 2019 Marvin ROGER <dev at marvinroger dot fr>
     * Licensed under GPL-3.0 (https://git.io/vAZsK)
     */(qA=A.Unit||(A.Unit={})).hex="hex",qA.raw="raw",qA.nano="nano",qA.knano="knano",qA.Nano="Nano",qA.NANO="NANO",qA.KNano="KNano",qA.MNano="MNano";var rI={hex:0,raw:0,nano:24,knano:27,Nano:30,NANO:30,KNano:33,MNano:36},nI=l.clone({EXPONENTIAL_AT:1e9,DECIMAL_PLACES:rI.MNano});function gI(A,I){var i=new Error("From or to is not valid");if(!I)throw i;var e=rI[I.from],r=rI[I.to];if(void 0===e||void 0===r)throw new Error("From or to is not valid");var n=new Error("Value is not valid");if("hex"===I.from){if(!/^[0-9a-fA-F]{32}$/.test(A))throw n}else if(!function(A){if(!hA(A))return!1;if(A.startsWith(".")||A.endsWith("."))return!1;var I=A.replace(".","");if(A.length-I.length>1)return!1;for(var i=0,e=I;i<e.length;i++){var r=e[i];if(r<"0"||r>"9")return!1}return!0}(A))throw n;var g,t=e-r;if(g="hex"===I.from?new nI("0x"+A):new nI(A),t<0)for(var o=0;o<-t;o++)g=g.dividedBy(10);else if(t>0)for(o=0;o<t;o++)g=g.multipliedBy(10);return"hex"===I.to?g.toString(16).padStart(32,"0"):g.toString()}
/*!
     * nanocurrency-js: A toolkit for the Nano cryptocurrency.
     * Copyright (c) 2019 Marvin ROGER <dev at marvinroger dot fr>
     * Licensed under GPL-3.0 (https://git.io/vAZsK)
     */var tI=new Uint8Array(32);function oI(I){var i,e=eA(iI(I.account)),r=eA(I.previous),n=eA(iI(I.representative)),g=eA(gI(I.balance,{from:A.Unit.raw,to:A.Unit.hex}));i=cA(I.link)?eA(iI(I.link)):eA(I.link);var t=z(32);return $(t,tI),$(t,e),$(t,r),$(t,n),$(t,g),$(t,i),iA(AA(t))}
/*!
     * nanocurrency-js: A toolkit for the Nano cryptocurrency.
     * Copyright (c) 2019 Marvin ROGER <dev at marvinroger dot fr>
     * Licensed under GPL-3.0 (https://git.io/vAZsK)
     */
function CI(A){if(!BA(A.hash))throw new Error("Hash is not valid");if(!EA(A.secretKey))throw new Error("Secret key is not valid");return iA(function(A,I){for(var i=AI(A,I),e=new Uint8Array(64),r=0;r<e.length;r++)e[r]=i[r];return e}(eA(A.hash),eA(A.secretKey)))}tI[31]=6;
/*!
     * nanocurrency-js: A toolkit for the Nano cryptocurrency.
     * Copyright (c) 2019 Marvin ROGER <dev at marvinroger dot fr>
     * Licensed under GPL-3.0 (https://git.io/vAZsK)
     */
var aI="0000000000000000000000000000000000000000000000000000000000000000";A.checkAddress=cA,A.checkAmount=fA,A.checkHash=BA,A.checkIndex=QA,A.checkKey=EA,A.checkSeed=uA,A.checkSignature=wA,A.checkThreshold=sA,A.checkWork=lA,A.computeWork=function(A,I){return void 0===I&&(I={}),e(this,void 0,void 0,(function(){var i,e,n,g,t,o,C,a;return r(this,(function(r){switch(r.label){case 0:return i=I.workerIndex,e=void 0===i?0:i,n=I.workerCount,g=void 0===n?1:n,t=I.workThreshold,o=void 0===t?"ffffffc000000000":t,[4,SA()];case 1:if(C=r.sent(),!BA(A))throw new Error("Hash is not valid");if(!sA(o))throw new Error("Threshold is not valid");if(!Number.isInteger(e)||!Number.isInteger(g)||e<0||g<1||e>g-1)throw new Error("Worker parameters are not valid");return a=C.work(A,o,e,g),"1"===a[1]?[2,a.substr(2)]:[2,null]}}))}))},A.convert=gI,A.createBlock=function(A,I){if(!EA(A))throw new Error("Secret key is not valid");if(void 0===I.work)throw new Error("Work is not set");if(!cA(I.representative))throw new Error("Representative is not valid");if(!fA(I.balance))throw new Error("Balance is not valid");var i;if(null===I.previous)i=aI;else if(!BA(i=I.previous))throw new Error("Previous is not valid");var e,r=!1;if(null===I.link)e=aI;else if(cA(e=I.link))r=!0;else if(!BA(e))throw new Error("Link is not valid");if(i===aI&&(r||e===aI))throw new Error("Block is impossible");var n,g,t=eI(iI(A)),o=oI({account:t,previous:i,representative:I.representative,balance:I.balance,link:e}),C=CI({hash:o,secretKey:A});return r?n=iI(g=e):g=eI(n=e),{hash:o,block:{type:"state",account:t,previous:i,representative:I.representative,balance:I.balance,link:n,link_as_account:g,work:I.work,signature:C}}},A.deriveAddress=eI,A.derivePublicKey=iI,A.deriveSecretKey=function(A,I){if(!uA(A))throw new Error("Seed is not valid");if(!QA(I))throw new Error("Index is not valid");var i=eA(A),e=new ArrayBuffer(4);new DataView(e).setUint32(0,I);var r=new Uint8Array(e),n=z(32);return $(n,i),$(n,r),iA(AA(n))},A.generateSeed=function(){return new Promise((function(A,I){var i;(i=32,new Promise((function(A,I){var e=new Uint8Array(i);q(e).then((function(){return A(e)})).catch(I)}))).then((function(I){var i=I.reduce((function(A,I){return""+A+("0"+I.toString(16)).slice(-2)}),"");return A(i)})).catch(I)}))},A.hashBlock=function(A){if(!cA(A.account))throw new Error("Account is not valid");if(!BA(A.previous))throw new Error("Previous is not valid");if(!cA(A.representative))throw new Error("Representative is not valid");if(!fA(A.balance))throw new Error("Balance is not valid");if(!cA(A.link)&&!BA(A.link))throw new Error("Link is not valid");return oI(A)},A.signBlock=CI,A.validateWork=function(A){var I,i=null!==(I=A.threshold)&&void 0!==I?I:"ffffffc000000000";if(!BA(A.blockHash))throw new Error("Hash is not valid");if(!lA(A.work))throw new Error("Work is not valid");if(!sA(i))throw new Error("Threshold is not valid");var e=new l("0x"+i),r=eA(A.blockHash),n=eA(A.work).reverse(),g=z(8);$(g,n),$(g,r);var t=iA(AA(g).reverse());return new l("0x"+t).isGreaterThanOrEqualTo(e)},A.verifyBlock=function(A){if(!BA(A.hash))throw new Error("Hash is not valid");if(!wA(A.signature))throw new Error("Signature is not valid");if(!EA(A.publicKey))throw new Error("Public key is not valid");return II(eA(A.hash),eA(A.signature),eA(A.publicKey))},Object.defineProperty(A,"__esModule",{value:!0})}));

}).call(this)}).call(this,require('_process'),require("buffer").Buffer,"/node_modules/nanocurrency/dist")
},{"_process":46,"buffer":44,"crypto":43,"fs":43,"path":43,"util":43}],33:[function(require,module,exports){
'use strict';

/*! *****************************************************************************
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION ANY IMPLIED
WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE,
MERCHANTABLITY OR NON-INFRINGEMENT.

See the Apache Version 2.0 License for specific language governing permissions
and limitations under the License.
***************************************************************************** */
/* global Reflect, Promise */

var extendStatics = function(d, b) {
    extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return extendStatics(d, b);
};

function __extends(d, b) {
    extendStatics(d, b);
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
}

function __values(o) {
    var m = typeof Symbol === "function" && o[Symbol.iterator], i = 0;
    if (m) return m.call(o);
    return {
        next: function () {
            if (o && i >= o.length) o = void 0;
            return { value: o && o[i++], done: !o };
        }
    };
}

function __read(o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o), r, ar = [], e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
    }
    catch (error) { e = { error: error }; }
    finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        }
        finally { if (e) throw e.error; }
    }
    return ar;
}

function __spread() {
    for (var ar = [], i = 0; i < arguments.length; i++)
        ar = ar.concat(__read(arguments[i]));
    return ar;
}

var Event = /** @class */ (function () {
    function Event(type, target) {
        this.target = target;
        this.type = type;
    }
    return Event;
}());
var ErrorEvent = /** @class */ (function (_super) {
    __extends(ErrorEvent, _super);
    function ErrorEvent(error, target) {
        var _this = _super.call(this, 'error', target) || this;
        _this.message = error.message;
        _this.error = error;
        return _this;
    }
    return ErrorEvent;
}(Event));
var CloseEvent = /** @class */ (function (_super) {
    __extends(CloseEvent, _super);
    function CloseEvent(code, reason, target) {
        if (code === void 0) { code = 1000; }
        if (reason === void 0) { reason = ''; }
        var _this = _super.call(this, 'close', target) || this;
        _this.wasClean = true;
        _this.code = code;
        _this.reason = reason;
        return _this;
    }
    return CloseEvent;
}(Event));

/*!
 * Reconnecting WebSocket
 * by Pedro Ladaria <pedro.ladaria@gmail.com>
 * https://github.com/pladaria/reconnecting-websocket
 * License MIT
 */
var getGlobalWebSocket = function () {
    if (typeof WebSocket !== 'undefined') {
        // @ts-ignore
        return WebSocket;
    }
};
/**
 * Returns true if given argument looks like a WebSocket class
 */
var isWebSocket = function (w) { return typeof w !== 'undefined' && !!w && w.CLOSING === 2; };
var DEFAULT = {
    maxReconnectionDelay: 10000,
    minReconnectionDelay: 1000 + Math.random() * 4000,
    minUptime: 5000,
    reconnectionDelayGrowFactor: 1.3,
    connectionTimeout: 4000,
    maxRetries: Infinity,
    maxEnqueuedMessages: Infinity,
    startClosed: false,
    debug: false,
};
var ReconnectingWebSocket = /** @class */ (function () {
    function ReconnectingWebSocket(url, protocols, options) {
        var _this = this;
        if (options === void 0) { options = {}; }
        this._listeners = {
            error: [],
            message: [],
            open: [],
            close: [],
        };
        this._retryCount = -1;
        this._shouldReconnect = true;
        this._connectLock = false;
        this._binaryType = 'blob';
        this._closeCalled = false;
        this._messageQueue = [];
        /**
         * An event listener to be called when the WebSocket connection's readyState changes to CLOSED
         */
        this.onclose = null;
        /**
         * An event listener to be called when an error occurs
         */
        this.onerror = null;
        /**
         * An event listener to be called when a message is received from the server
         */
        this.onmessage = null;
        /**
         * An event listener to be called when the WebSocket connection's readyState changes to OPEN;
         * this indicates that the connection is ready to send and receive data
         */
        this.onopen = null;
        this._handleOpen = function (event) {
            _this._debug('open event');
            var _a = _this._options.minUptime, minUptime = _a === void 0 ? DEFAULT.minUptime : _a;
            clearTimeout(_this._connectTimeout);
            _this._uptimeTimeout = setTimeout(function () { return _this._acceptOpen(); }, minUptime);
            _this._ws.binaryType = _this._binaryType;
            // send enqueued messages (messages sent before websocket open event)
            _this._messageQueue.forEach(function (message) { return _this._ws.send(message); });
            _this._messageQueue = [];
            if (_this.onopen) {
                _this.onopen(event);
            }
            _this._listeners.open.forEach(function (listener) { return _this._callEventListener(event, listener); });
        };
        this._handleMessage = function (event) {
            _this._debug('message event');
            if (_this.onmessage) {
                _this.onmessage(event);
            }
            _this._listeners.message.forEach(function (listener) { return _this._callEventListener(event, listener); });
        };
        this._handleError = function (event) {
            _this._debug('error event', event.message);
            _this._disconnect(undefined, event.message === 'TIMEOUT' ? 'timeout' : undefined);
            if (_this.onerror) {
                _this.onerror(event);
            }
            _this._debug('exec error listeners');
            _this._listeners.error.forEach(function (listener) { return _this._callEventListener(event, listener); });
            _this._connect();
        };
        this._handleClose = function (event) {
            _this._debug('close event');
            _this._clearTimeouts();
            if (_this._shouldReconnect) {
                _this._connect();
            }
            if (_this.onclose) {
                _this.onclose(event);
            }
            _this._listeners.close.forEach(function (listener) { return _this._callEventListener(event, listener); });
        };
        this._url = url;
        this._protocols = protocols;
        this._options = options;
        if (this._options.startClosed) {
            this._shouldReconnect = false;
        }
        this._connect();
    }
    Object.defineProperty(ReconnectingWebSocket, "CONNECTING", {
        get: function () {
            return 0;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(ReconnectingWebSocket, "OPEN", {
        get: function () {
            return 1;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(ReconnectingWebSocket, "CLOSING", {
        get: function () {
            return 2;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(ReconnectingWebSocket, "CLOSED", {
        get: function () {
            return 3;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(ReconnectingWebSocket.prototype, "CONNECTING", {
        get: function () {
            return ReconnectingWebSocket.CONNECTING;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(ReconnectingWebSocket.prototype, "OPEN", {
        get: function () {
            return ReconnectingWebSocket.OPEN;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(ReconnectingWebSocket.prototype, "CLOSING", {
        get: function () {
            return ReconnectingWebSocket.CLOSING;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(ReconnectingWebSocket.prototype, "CLOSED", {
        get: function () {
            return ReconnectingWebSocket.CLOSED;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(ReconnectingWebSocket.prototype, "binaryType", {
        get: function () {
            return this._ws ? this._ws.binaryType : this._binaryType;
        },
        set: function (value) {
            this._binaryType = value;
            if (this._ws) {
                this._ws.binaryType = value;
            }
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(ReconnectingWebSocket.prototype, "retryCount", {
        /**
         * Returns the number or connection retries
         */
        get: function () {
            return Math.max(this._retryCount, 0);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(ReconnectingWebSocket.prototype, "bufferedAmount", {
        /**
         * The number of bytes of data that have been queued using calls to send() but not yet
         * transmitted to the network. This value resets to zero once all queued data has been sent.
         * This value does not reset to zero when the connection is closed; if you keep calling send(),
         * this will continue to climb. Read only
         */
        get: function () {
            var bytes = this._messageQueue.reduce(function (acc, message) {
                if (typeof message === 'string') {
                    acc += message.length; // not byte size
                }
                else if (message instanceof Blob) {
                    acc += message.size;
                }
                else {
                    acc += message.byteLength;
                }
                return acc;
            }, 0);
            return bytes + (this._ws ? this._ws.bufferedAmount : 0);
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(ReconnectingWebSocket.prototype, "extensions", {
        /**
         * The extensions selected by the server. This is currently only the empty string or a list of
         * extensions as negotiated by the connection
         */
        get: function () {
            return this._ws ? this._ws.extensions : '';
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(ReconnectingWebSocket.prototype, "protocol", {
        /**
         * A string indicating the name of the sub-protocol the server selected;
         * this will be one of the strings specified in the protocols parameter when creating the
         * WebSocket object
         */
        get: function () {
            return this._ws ? this._ws.protocol : '';
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(ReconnectingWebSocket.prototype, "readyState", {
        /**
         * The current state of the connection; this is one of the Ready state constants
         */
        get: function () {
            if (this._ws) {
                return this._ws.readyState;
            }
            return this._options.startClosed
                ? ReconnectingWebSocket.CLOSED
                : ReconnectingWebSocket.CONNECTING;
        },
        enumerable: true,
        configurable: true
    });
    Object.defineProperty(ReconnectingWebSocket.prototype, "url", {
        /**
         * The URL as resolved by the constructor
         */
        get: function () {
            return this._ws ? this._ws.url : '';
        },
        enumerable: true,
        configurable: true
    });
    /**
     * Closes the WebSocket connection or connection attempt, if any. If the connection is already
     * CLOSED, this method does nothing
     */
    ReconnectingWebSocket.prototype.close = function (code, reason) {
        if (code === void 0) { code = 1000; }
        this._closeCalled = true;
        this._shouldReconnect = false;
        this._clearTimeouts();
        if (!this._ws) {
            this._debug('close enqueued: no ws instance');
            return;
        }
        if (this._ws.readyState === this.CLOSED) {
            this._debug('close: already closed');
            return;
        }
        this._ws.close(code, reason);
    };
    /**
     * Closes the WebSocket connection or connection attempt and connects again.
     * Resets retry counter;
     */
    ReconnectingWebSocket.prototype.reconnect = function (code, reason) {
        this._shouldReconnect = true;
        this._closeCalled = false;
        this._retryCount = -1;
        if (!this._ws || this._ws.readyState === this.CLOSED) {
            this._connect();
        }
        else {
            this._disconnect(code, reason);
            this._connect();
        }
    };
    /**
     * Enqueue specified data to be transmitted to the server over the WebSocket connection
     */
    ReconnectingWebSocket.prototype.send = function (data) {
        if (this._ws && this._ws.readyState === this.OPEN) {
            this._debug('send', data);
            this._ws.send(data);
        }
        else {
            var _a = this._options.maxEnqueuedMessages, maxEnqueuedMessages = _a === void 0 ? DEFAULT.maxEnqueuedMessages : _a;
            if (this._messageQueue.length < maxEnqueuedMessages) {
                this._debug('enqueue', data);
                this._messageQueue.push(data);
            }
        }
    };
    /**
     * Register an event handler of a specific event type
     */
    ReconnectingWebSocket.prototype.addEventListener = function (type, listener) {
        if (this._listeners[type]) {
            // @ts-ignore
            this._listeners[type].push(listener);
        }
    };
    ReconnectingWebSocket.prototype.dispatchEvent = function (event) {
        var e_1, _a;
        var listeners = this._listeners[event.type];
        if (listeners) {
            try {
                for (var listeners_1 = __values(listeners), listeners_1_1 = listeners_1.next(); !listeners_1_1.done; listeners_1_1 = listeners_1.next()) {
                    var listener = listeners_1_1.value;
                    this._callEventListener(event, listener);
                }
            }
            catch (e_1_1) { e_1 = { error: e_1_1 }; }
            finally {
                try {
                    if (listeners_1_1 && !listeners_1_1.done && (_a = listeners_1.return)) _a.call(listeners_1);
                }
                finally { if (e_1) throw e_1.error; }
            }
        }
        return true;
    };
    /**
     * Removes an event listener
     */
    ReconnectingWebSocket.prototype.removeEventListener = function (type, listener) {
        if (this._listeners[type]) {
            // @ts-ignore
            this._listeners[type] = this._listeners[type].filter(function (l) { return l !== listener; });
        }
    };
    ReconnectingWebSocket.prototype._debug = function () {
        var args = [];
        for (var _i = 0; _i < arguments.length; _i++) {
            args[_i] = arguments[_i];
        }
        if (this._options.debug) {
            // not using spread because compiled version uses Symbols
            // tslint:disable-next-line
            console.log.apply(console, __spread(['RWS>'], args));
        }
    };
    ReconnectingWebSocket.prototype._getNextDelay = function () {
        var _a = this._options, _b = _a.reconnectionDelayGrowFactor, reconnectionDelayGrowFactor = _b === void 0 ? DEFAULT.reconnectionDelayGrowFactor : _b, _c = _a.minReconnectionDelay, minReconnectionDelay = _c === void 0 ? DEFAULT.minReconnectionDelay : _c, _d = _a.maxReconnectionDelay, maxReconnectionDelay = _d === void 0 ? DEFAULT.maxReconnectionDelay : _d;
        var delay = 0;
        if (this._retryCount > 0) {
            delay =
                minReconnectionDelay * Math.pow(reconnectionDelayGrowFactor, this._retryCount - 1);
            if (delay > maxReconnectionDelay) {
                delay = maxReconnectionDelay;
            }
        }
        this._debug('next delay', delay);
        return delay;
    };
    ReconnectingWebSocket.prototype._wait = function () {
        var _this = this;
        return new Promise(function (resolve) {
            setTimeout(resolve, _this._getNextDelay());
        });
    };
    ReconnectingWebSocket.prototype._getNextUrl = function (urlProvider) {
        if (typeof urlProvider === 'string') {
            return Promise.resolve(urlProvider);
        }
        if (typeof urlProvider === 'function') {
            var url = urlProvider();
            if (typeof url === 'string') {
                return Promise.resolve(url);
            }
            if (!!url.then) {
                return url;
            }
        }
        throw Error('Invalid URL');
    };
    ReconnectingWebSocket.prototype._connect = function () {
        var _this = this;
        if (this._connectLock || !this._shouldReconnect) {
            return;
        }
        this._connectLock = true;
        var _a = this._options, _b = _a.maxRetries, maxRetries = _b === void 0 ? DEFAULT.maxRetries : _b, _c = _a.connectionTimeout, connectionTimeout = _c === void 0 ? DEFAULT.connectionTimeout : _c, _d = _a.WebSocket, WebSocket = _d === void 0 ? getGlobalWebSocket() : _d;
        if (this._retryCount >= maxRetries) {
            this._debug('max retries reached', this._retryCount, '>=', maxRetries);
            return;
        }
        this._retryCount++;
        this._debug('connect', this._retryCount);
        this._removeListeners();
        if (!isWebSocket(WebSocket)) {
            throw Error('No valid WebSocket class provided');
        }
        this._wait()
            .then(function () { return _this._getNextUrl(_this._url); })
            .then(function (url) {
            // close could be called before creating the ws
            if (_this._closeCalled) {
                return;
            }
            _this._debug('connect', { url: url, protocols: _this._protocols });
            _this._ws = _this._protocols
                ? new WebSocket(url, _this._protocols)
                : new WebSocket(url);
            _this._ws.binaryType = _this._binaryType;
            _this._connectLock = false;
            _this._addListeners();
            _this._connectTimeout = setTimeout(function () { return _this._handleTimeout(); }, connectionTimeout);
        });
    };
    ReconnectingWebSocket.prototype._handleTimeout = function () {
        this._debug('timeout event');
        this._handleError(new ErrorEvent(Error('TIMEOUT'), this));
    };
    ReconnectingWebSocket.prototype._disconnect = function (code, reason) {
        if (code === void 0) { code = 1000; }
        this._clearTimeouts();
        if (!this._ws) {
            return;
        }
        this._removeListeners();
        try {
            this._ws.close(code, reason);
            this._handleClose(new CloseEvent(code, reason, this));
        }
        catch (error) {
            // ignore
        }
    };
    ReconnectingWebSocket.prototype._acceptOpen = function () {
        this._debug('accept open');
        this._retryCount = 0;
    };
    ReconnectingWebSocket.prototype._callEventListener = function (event, listener) {
        if ('handleEvent' in listener) {
            // @ts-ignore
            listener.handleEvent(event);
        }
        else {
            // @ts-ignore
            listener(event);
        }
    };
    ReconnectingWebSocket.prototype._removeListeners = function () {
        if (!this._ws) {
            return;
        }
        this._debug('removeListeners');
        this._ws.removeEventListener('open', this._handleOpen);
        this._ws.removeEventListener('close', this._handleClose);
        this._ws.removeEventListener('message', this._handleMessage);
        // @ts-ignore
        this._ws.removeEventListener('error', this._handleError);
    };
    ReconnectingWebSocket.prototype._addListeners = function () {
        if (!this._ws) {
            return;
        }
        this._debug('addListeners');
        this._ws.addEventListener('open', this._handleOpen);
        this._ws.addEventListener('close', this._handleClose);
        this._ws.addEventListener('message', this._handleMessage);
        // @ts-ignore
        this._ws.addEventListener('error', this._handleError);
    };
    ReconnectingWebSocket.prototype._clearTimeouts = function () {
        clearTimeout(this._connectTimeout);
        clearTimeout(this._uptimeTimeout);
    };
    return ReconnectingWebSocket;
}());

module.exports = ReconnectingWebSocket;

},{}],34:[function(require,module,exports){
const blake2b = require('blakejs/blake2b');

(function(nacl) {
'use strict';

// Ported in 2014 by Dmitry Chestnykh and Devi Mandiri.
// Public domain.
//
// Implementation derived from TweetNaCl version 20140427.
// See for details: http://tweetnacl.cr.yp.to/

var gf = function(init) {
  var i, r = new Float64Array(16);
  if (init) for (i = 0; i < init.length; i++) r[i] = init[i];
  return r;
};

//  Pluggable, initialized in high-level API below.
var randombytes = function(/* x, n */) { throw new Error('no PRNG'); };

var _0 = new Uint8Array(16);
var _9 = new Uint8Array(32); _9[0] = 9;

var gf0 = gf(),
    gf1 = gf([1]),
    _121665 = gf([0xdb41, 1]),
    D = gf([0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203]),
    D2 = gf([0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406]),
    X = gf([0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169]),
    Y = gf([0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666]),
    I = gf([0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83]);

function ts64(x, i, h, l) {
  x[i]   = (h >> 24) & 0xff;
  x[i+1] = (h >> 16) & 0xff;
  x[i+2] = (h >>  8) & 0xff;
  x[i+3] = h & 0xff;
  x[i+4] = (l >> 24)  & 0xff;
  x[i+5] = (l >> 16)  & 0xff;
  x[i+6] = (l >>  8)  & 0xff;
  x[i+7] = l & 0xff;
}

function vn(x, xi, y, yi, n) {
  var i,d = 0;
  for (i = 0; i < n; i++) d |= x[xi+i]^y[yi+i];
  return (1 & ((d - 1) >>> 8)) - 1;
}

function crypto_verify_16(x, xi, y, yi) {
  return vn(x,xi,y,yi,16);
}

function crypto_verify_32(x, xi, y, yi) {
  return vn(x,xi,y,yi,32);
}

function core_salsa20(o, p, k, c) {
  var j0  = c[ 0] & 0xff | (c[ 1] & 0xff)<<8 | (c[ 2] & 0xff)<<16 | (c[ 3] & 0xff)<<24,
      j1  = k[ 0] & 0xff | (k[ 1] & 0xff)<<8 | (k[ 2] & 0xff)<<16 | (k[ 3] & 0xff)<<24,
      j2  = k[ 4] & 0xff | (k[ 5] & 0xff)<<8 | (k[ 6] & 0xff)<<16 | (k[ 7] & 0xff)<<24,
      j3  = k[ 8] & 0xff | (k[ 9] & 0xff)<<8 | (k[10] & 0xff)<<16 | (k[11] & 0xff)<<24,
      j4  = k[12] & 0xff | (k[13] & 0xff)<<8 | (k[14] & 0xff)<<16 | (k[15] & 0xff)<<24,
      j5  = c[ 4] & 0xff | (c[ 5] & 0xff)<<8 | (c[ 6] & 0xff)<<16 | (c[ 7] & 0xff)<<24,
      j6  = p[ 0] & 0xff | (p[ 1] & 0xff)<<8 | (p[ 2] & 0xff)<<16 | (p[ 3] & 0xff)<<24,
      j7  = p[ 4] & 0xff | (p[ 5] & 0xff)<<8 | (p[ 6] & 0xff)<<16 | (p[ 7] & 0xff)<<24,
      j8  = p[ 8] & 0xff | (p[ 9] & 0xff)<<8 | (p[10] & 0xff)<<16 | (p[11] & 0xff)<<24,
      j9  = p[12] & 0xff | (p[13] & 0xff)<<8 | (p[14] & 0xff)<<16 | (p[15] & 0xff)<<24,
      j10 = c[ 8] & 0xff | (c[ 9] & 0xff)<<8 | (c[10] & 0xff)<<16 | (c[11] & 0xff)<<24,
      j11 = k[16] & 0xff | (k[17] & 0xff)<<8 | (k[18] & 0xff)<<16 | (k[19] & 0xff)<<24,
      j12 = k[20] & 0xff | (k[21] & 0xff)<<8 | (k[22] & 0xff)<<16 | (k[23] & 0xff)<<24,
      j13 = k[24] & 0xff | (k[25] & 0xff)<<8 | (k[26] & 0xff)<<16 | (k[27] & 0xff)<<24,
      j14 = k[28] & 0xff | (k[29] & 0xff)<<8 | (k[30] & 0xff)<<16 | (k[31] & 0xff)<<24,
      j15 = c[12] & 0xff | (c[13] & 0xff)<<8 | (c[14] & 0xff)<<16 | (c[15] & 0xff)<<24;

  var x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7,
      x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14,
      x15 = j15, u;

  for (var i = 0; i < 20; i += 2) {
    u = x0 + x12 | 0;
    x4 ^= u<<7 | u>>>(32-7);
    u = x4 + x0 | 0;
    x8 ^= u<<9 | u>>>(32-9);
    u = x8 + x4 | 0;
    x12 ^= u<<13 | u>>>(32-13);
    u = x12 + x8 | 0;
    x0 ^= u<<18 | u>>>(32-18);

    u = x5 + x1 | 0;
    x9 ^= u<<7 | u>>>(32-7);
    u = x9 + x5 | 0;
    x13 ^= u<<9 | u>>>(32-9);
    u = x13 + x9 | 0;
    x1 ^= u<<13 | u>>>(32-13);
    u = x1 + x13 | 0;
    x5 ^= u<<18 | u>>>(32-18);

    u = x10 + x6 | 0;
    x14 ^= u<<7 | u>>>(32-7);
    u = x14 + x10 | 0;
    x2 ^= u<<9 | u>>>(32-9);
    u = x2 + x14 | 0;
    x6 ^= u<<13 | u>>>(32-13);
    u = x6 + x2 | 0;
    x10 ^= u<<18 | u>>>(32-18);

    u = x15 + x11 | 0;
    x3 ^= u<<7 | u>>>(32-7);
    u = x3 + x15 | 0;
    x7 ^= u<<9 | u>>>(32-9);
    u = x7 + x3 | 0;
    x11 ^= u<<13 | u>>>(32-13);
    u = x11 + x7 | 0;
    x15 ^= u<<18 | u>>>(32-18);

    u = x0 + x3 | 0;
    x1 ^= u<<7 | u>>>(32-7);
    u = x1 + x0 | 0;
    x2 ^= u<<9 | u>>>(32-9);
    u = x2 + x1 | 0;
    x3 ^= u<<13 | u>>>(32-13);
    u = x3 + x2 | 0;
    x0 ^= u<<18 | u>>>(32-18);

    u = x5 + x4 | 0;
    x6 ^= u<<7 | u>>>(32-7);
    u = x6 + x5 | 0;
    x7 ^= u<<9 | u>>>(32-9);
    u = x7 + x6 | 0;
    x4 ^= u<<13 | u>>>(32-13);
    u = x4 + x7 | 0;
    x5 ^= u<<18 | u>>>(32-18);

    u = x10 + x9 | 0;
    x11 ^= u<<7 | u>>>(32-7);
    u = x11 + x10 | 0;
    x8 ^= u<<9 | u>>>(32-9);
    u = x8 + x11 | 0;
    x9 ^= u<<13 | u>>>(32-13);
    u = x9 + x8 | 0;
    x10 ^= u<<18 | u>>>(32-18);

    u = x15 + x14 | 0;
    x12 ^= u<<7 | u>>>(32-7);
    u = x12 + x15 | 0;
    x13 ^= u<<9 | u>>>(32-9);
    u = x13 + x12 | 0;
    x14 ^= u<<13 | u>>>(32-13);
    u = x14 + x13 | 0;
    x15 ^= u<<18 | u>>>(32-18);
  }
   x0 =  x0 +  j0 | 0;
   x1 =  x1 +  j1 | 0;
   x2 =  x2 +  j2 | 0;
   x3 =  x3 +  j3 | 0;
   x4 =  x4 +  j4 | 0;
   x5 =  x5 +  j5 | 0;
   x6 =  x6 +  j6 | 0;
   x7 =  x7 +  j7 | 0;
   x8 =  x8 +  j8 | 0;
   x9 =  x9 +  j9 | 0;
  x10 = x10 + j10 | 0;
  x11 = x11 + j11 | 0;
  x12 = x12 + j12 | 0;
  x13 = x13 + j13 | 0;
  x14 = x14 + j14 | 0;
  x15 = x15 + j15 | 0;

  o[ 0] = x0 >>>  0 & 0xff;
  o[ 1] = x0 >>>  8 & 0xff;
  o[ 2] = x0 >>> 16 & 0xff;
  o[ 3] = x0 >>> 24 & 0xff;

  o[ 4] = x1 >>>  0 & 0xff;
  o[ 5] = x1 >>>  8 & 0xff;
  o[ 6] = x1 >>> 16 & 0xff;
  o[ 7] = x1 >>> 24 & 0xff;

  o[ 8] = x2 >>>  0 & 0xff;
  o[ 9] = x2 >>>  8 & 0xff;
  o[10] = x2 >>> 16 & 0xff;
  o[11] = x2 >>> 24 & 0xff;

  o[12] = x3 >>>  0 & 0xff;
  o[13] = x3 >>>  8 & 0xff;
  o[14] = x3 >>> 16 & 0xff;
  o[15] = x3 >>> 24 & 0xff;

  o[16] = x4 >>>  0 & 0xff;
  o[17] = x4 >>>  8 & 0xff;
  o[18] = x4 >>> 16 & 0xff;
  o[19] = x4 >>> 24 & 0xff;

  o[20] = x5 >>>  0 & 0xff;
  o[21] = x5 >>>  8 & 0xff;
  o[22] = x5 >>> 16 & 0xff;
  o[23] = x5 >>> 24 & 0xff;

  o[24] = x6 >>>  0 & 0xff;
  o[25] = x6 >>>  8 & 0xff;
  o[26] = x6 >>> 16 & 0xff;
  o[27] = x6 >>> 24 & 0xff;

  o[28] = x7 >>>  0 & 0xff;
  o[29] = x7 >>>  8 & 0xff;
  o[30] = x7 >>> 16 & 0xff;
  o[31] = x7 >>> 24 & 0xff;

  o[32] = x8 >>>  0 & 0xff;
  o[33] = x8 >>>  8 & 0xff;
  o[34] = x8 >>> 16 & 0xff;
  o[35] = x8 >>> 24 & 0xff;

  o[36] = x9 >>>  0 & 0xff;
  o[37] = x9 >>>  8 & 0xff;
  o[38] = x9 >>> 16 & 0xff;
  o[39] = x9 >>> 24 & 0xff;

  o[40] = x10 >>>  0 & 0xff;
  o[41] = x10 >>>  8 & 0xff;
  o[42] = x10 >>> 16 & 0xff;
  o[43] = x10 >>> 24 & 0xff;

  o[44] = x11 >>>  0 & 0xff;
  o[45] = x11 >>>  8 & 0xff;
  o[46] = x11 >>> 16 & 0xff;
  o[47] = x11 >>> 24 & 0xff;

  o[48] = x12 >>>  0 & 0xff;
  o[49] = x12 >>>  8 & 0xff;
  o[50] = x12 >>> 16 & 0xff;
  o[51] = x12 >>> 24 & 0xff;

  o[52] = x13 >>>  0 & 0xff;
  o[53] = x13 >>>  8 & 0xff;
  o[54] = x13 >>> 16 & 0xff;
  o[55] = x13 >>> 24 & 0xff;

  o[56] = x14 >>>  0 & 0xff;
  o[57] = x14 >>>  8 & 0xff;
  o[58] = x14 >>> 16 & 0xff;
  o[59] = x14 >>> 24 & 0xff;

  o[60] = x15 >>>  0 & 0xff;
  o[61] = x15 >>>  8 & 0xff;
  o[62] = x15 >>> 16 & 0xff;
  o[63] = x15 >>> 24 & 0xff;
}

function core_hsalsa20(o,p,k,c) {
  var j0  = c[ 0] & 0xff | (c[ 1] & 0xff)<<8 | (c[ 2] & 0xff)<<16 | (c[ 3] & 0xff)<<24,
      j1  = k[ 0] & 0xff | (k[ 1] & 0xff)<<8 | (k[ 2] & 0xff)<<16 | (k[ 3] & 0xff)<<24,
      j2  = k[ 4] & 0xff | (k[ 5] & 0xff)<<8 | (k[ 6] & 0xff)<<16 | (k[ 7] & 0xff)<<24,
      j3  = k[ 8] & 0xff | (k[ 9] & 0xff)<<8 | (k[10] & 0xff)<<16 | (k[11] & 0xff)<<24,
      j4  = k[12] & 0xff | (k[13] & 0xff)<<8 | (k[14] & 0xff)<<16 | (k[15] & 0xff)<<24,
      j5  = c[ 4] & 0xff | (c[ 5] & 0xff)<<8 | (c[ 6] & 0xff)<<16 | (c[ 7] & 0xff)<<24,
      j6  = p[ 0] & 0xff | (p[ 1] & 0xff)<<8 | (p[ 2] & 0xff)<<16 | (p[ 3] & 0xff)<<24,
      j7  = p[ 4] & 0xff | (p[ 5] & 0xff)<<8 | (p[ 6] & 0xff)<<16 | (p[ 7] & 0xff)<<24,
      j8  = p[ 8] & 0xff | (p[ 9] & 0xff)<<8 | (p[10] & 0xff)<<16 | (p[11] & 0xff)<<24,
      j9  = p[12] & 0xff | (p[13] & 0xff)<<8 | (p[14] & 0xff)<<16 | (p[15] & 0xff)<<24,
      j10 = c[ 8] & 0xff | (c[ 9] & 0xff)<<8 | (c[10] & 0xff)<<16 | (c[11] & 0xff)<<24,
      j11 = k[16] & 0xff | (k[17] & 0xff)<<8 | (k[18] & 0xff)<<16 | (k[19] & 0xff)<<24,
      j12 = k[20] & 0xff | (k[21] & 0xff)<<8 | (k[22] & 0xff)<<16 | (k[23] & 0xff)<<24,
      j13 = k[24] & 0xff | (k[25] & 0xff)<<8 | (k[26] & 0xff)<<16 | (k[27] & 0xff)<<24,
      j14 = k[28] & 0xff | (k[29] & 0xff)<<8 | (k[30] & 0xff)<<16 | (k[31] & 0xff)<<24,
      j15 = c[12] & 0xff | (c[13] & 0xff)<<8 | (c[14] & 0xff)<<16 | (c[15] & 0xff)<<24;

  var x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7,
      x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14,
      x15 = j15, u;

  for (var i = 0; i < 20; i += 2) {
    u = x0 + x12 | 0;
    x4 ^= u<<7 | u>>>(32-7);
    u = x4 + x0 | 0;
    x8 ^= u<<9 | u>>>(32-9);
    u = x8 + x4 | 0;
    x12 ^= u<<13 | u>>>(32-13);
    u = x12 + x8 | 0;
    x0 ^= u<<18 | u>>>(32-18);

    u = x5 + x1 | 0;
    x9 ^= u<<7 | u>>>(32-7);
    u = x9 + x5 | 0;
    x13 ^= u<<9 | u>>>(32-9);
    u = x13 + x9 | 0;
    x1 ^= u<<13 | u>>>(32-13);
    u = x1 + x13 | 0;
    x5 ^= u<<18 | u>>>(32-18);

    u = x10 + x6 | 0;
    x14 ^= u<<7 | u>>>(32-7);
    u = x14 + x10 | 0;
    x2 ^= u<<9 | u>>>(32-9);
    u = x2 + x14 | 0;
    x6 ^= u<<13 | u>>>(32-13);
    u = x6 + x2 | 0;
    x10 ^= u<<18 | u>>>(32-18);

    u = x15 + x11 | 0;
    x3 ^= u<<7 | u>>>(32-7);
    u = x3 + x15 | 0;
    x7 ^= u<<9 | u>>>(32-9);
    u = x7 + x3 | 0;
    x11 ^= u<<13 | u>>>(32-13);
    u = x11 + x7 | 0;
    x15 ^= u<<18 | u>>>(32-18);

    u = x0 + x3 | 0;
    x1 ^= u<<7 | u>>>(32-7);
    u = x1 + x0 | 0;
    x2 ^= u<<9 | u>>>(32-9);
    u = x2 + x1 | 0;
    x3 ^= u<<13 | u>>>(32-13);
    u = x3 + x2 | 0;
    x0 ^= u<<18 | u>>>(32-18);

    u = x5 + x4 | 0;
    x6 ^= u<<7 | u>>>(32-7);
    u = x6 + x5 | 0;
    x7 ^= u<<9 | u>>>(32-9);
    u = x7 + x6 | 0;
    x4 ^= u<<13 | u>>>(32-13);
    u = x4 + x7 | 0;
    x5 ^= u<<18 | u>>>(32-18);

    u = x10 + x9 | 0;
    x11 ^= u<<7 | u>>>(32-7);
    u = x11 + x10 | 0;
    x8 ^= u<<9 | u>>>(32-9);
    u = x8 + x11 | 0;
    x9 ^= u<<13 | u>>>(32-13);
    u = x9 + x8 | 0;
    x10 ^= u<<18 | u>>>(32-18);

    u = x15 + x14 | 0;
    x12 ^= u<<7 | u>>>(32-7);
    u = x12 + x15 | 0;
    x13 ^= u<<9 | u>>>(32-9);
    u = x13 + x12 | 0;
    x14 ^= u<<13 | u>>>(32-13);
    u = x14 + x13 | 0;
    x15 ^= u<<18 | u>>>(32-18);
  }

  o[ 0] = x0 >>>  0 & 0xff;
  o[ 1] = x0 >>>  8 & 0xff;
  o[ 2] = x0 >>> 16 & 0xff;
  o[ 3] = x0 >>> 24 & 0xff;

  o[ 4] = x5 >>>  0 & 0xff;
  o[ 5] = x5 >>>  8 & 0xff;
  o[ 6] = x5 >>> 16 & 0xff;
  o[ 7] = x5 >>> 24 & 0xff;

  o[ 8] = x10 >>>  0 & 0xff;
  o[ 9] = x10 >>>  8 & 0xff;
  o[10] = x10 >>> 16 & 0xff;
  o[11] = x10 >>> 24 & 0xff;

  o[12] = x15 >>>  0 & 0xff;
  o[13] = x15 >>>  8 & 0xff;
  o[14] = x15 >>> 16 & 0xff;
  o[15] = x15 >>> 24 & 0xff;

  o[16] = x6 >>>  0 & 0xff;
  o[17] = x6 >>>  8 & 0xff;
  o[18] = x6 >>> 16 & 0xff;
  o[19] = x6 >>> 24 & 0xff;

  o[20] = x7 >>>  0 & 0xff;
  o[21] = x7 >>>  8 & 0xff;
  o[22] = x7 >>> 16 & 0xff;
  o[23] = x7 >>> 24 & 0xff;

  o[24] = x8 >>>  0 & 0xff;
  o[25] = x8 >>>  8 & 0xff;
  o[26] = x8 >>> 16 & 0xff;
  o[27] = x8 >>> 24 & 0xff;

  o[28] = x9 >>>  0 & 0xff;
  o[29] = x9 >>>  8 & 0xff;
  o[30] = x9 >>> 16 & 0xff;
  o[31] = x9 >>> 24 & 0xff;
}

function crypto_core_salsa20(out,inp,k,c) {
  core_salsa20(out,inp,k,c);
}

function crypto_core_hsalsa20(out,inp,k,c) {
  core_hsalsa20(out,inp,k,c);
}

var sigma = new Uint8Array([101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107]);
            // "expand 32-byte k"

function crypto_stream_salsa20_xor(c,cpos,m,mpos,b,n,k) {
  var z = new Uint8Array(16), x = new Uint8Array(64);
  var u, i;
  for (i = 0; i < 16; i++) z[i] = 0;
  for (i = 0; i < 8; i++) z[i] = n[i];
  while (b >= 64) {
    crypto_core_salsa20(x,z,k,sigma);
    for (i = 0; i < 64; i++) c[cpos+i] = m[mpos+i] ^ x[i];
    u = 1;
    for (i = 8; i < 16; i++) {
      u = u + (z[i] & 0xff) | 0;
      z[i] = u & 0xff;
      u >>>= 8;
    }
    b -= 64;
    cpos += 64;
    mpos += 64;
  }
  if (b > 0) {
    crypto_core_salsa20(x,z,k,sigma);
    for (i = 0; i < b; i++) c[cpos+i] = m[mpos+i] ^ x[i];
  }
  return 0;
}

function crypto_stream_salsa20(c,cpos,b,n,k) {
  var z = new Uint8Array(16), x = new Uint8Array(64);
  var u, i;
  for (i = 0; i < 16; i++) z[i] = 0;
  for (i = 0; i < 8; i++) z[i] = n[i];
  while (b >= 64) {
    crypto_core_salsa20(x,z,k,sigma);
    for (i = 0; i < 64; i++) c[cpos+i] = x[i];
    u = 1;
    for (i = 8; i < 16; i++) {
      u = u + (z[i] & 0xff) | 0;
      z[i] = u & 0xff;
      u >>>= 8;
    }
    b -= 64;
    cpos += 64;
  }
  if (b > 0) {
    crypto_core_salsa20(x,z,k,sigma);
    for (i = 0; i < b; i++) c[cpos+i] = x[i];
  }
  return 0;
}

function crypto_stream(c,cpos,d,n,k) {
  var s = new Uint8Array(32);
  crypto_core_hsalsa20(s,n,k,sigma);
  var sn = new Uint8Array(8);
  for (var i = 0; i < 8; i++) sn[i] = n[i+16];
  return crypto_stream_salsa20(c,cpos,d,sn,s);
}

function crypto_stream_xor(c,cpos,m,mpos,d,n,k) {
  var s = new Uint8Array(32);
  crypto_core_hsalsa20(s,n,k,sigma);
  var sn = new Uint8Array(8);
  for (var i = 0; i < 8; i++) sn[i] = n[i+16];
  return crypto_stream_salsa20_xor(c,cpos,m,mpos,d,sn,s);
}

/*
* Port of Andrew Moon's Poly1305-donna-16. Public domain.
* https://github.com/floodyberry/poly1305-donna
*/

var poly1305 = function(key) {
  this.buffer = new Uint8Array(16);
  this.r = new Uint16Array(10);
  this.h = new Uint16Array(10);
  this.pad = new Uint16Array(8);
  this.leftover = 0;
  this.fin = 0;

  var t0, t1, t2, t3, t4, t5, t6, t7;

  t0 = key[ 0] & 0xff | (key[ 1] & 0xff) << 8; this.r[0] = ( t0                     ) & 0x1fff;
  t1 = key[ 2] & 0xff | (key[ 3] & 0xff) << 8; this.r[1] = ((t0 >>> 13) | (t1 <<  3)) & 0x1fff;
  t2 = key[ 4] & 0xff | (key[ 5] & 0xff) << 8; this.r[2] = ((t1 >>> 10) | (t2 <<  6)) & 0x1f03;
  t3 = key[ 6] & 0xff | (key[ 7] & 0xff) << 8; this.r[3] = ((t2 >>>  7) | (t3 <<  9)) & 0x1fff;
  t4 = key[ 8] & 0xff | (key[ 9] & 0xff) << 8; this.r[4] = ((t3 >>>  4) | (t4 << 12)) & 0x00ff;
  this.r[5] = ((t4 >>>  1)) & 0x1ffe;
  t5 = key[10] & 0xff | (key[11] & 0xff) << 8; this.r[6] = ((t4 >>> 14) | (t5 <<  2)) & 0x1fff;
  t6 = key[12] & 0xff | (key[13] & 0xff) << 8; this.r[7] = ((t5 >>> 11) | (t6 <<  5)) & 0x1f81;
  t7 = key[14] & 0xff | (key[15] & 0xff) << 8; this.r[8] = ((t6 >>>  8) | (t7 <<  8)) & 0x1fff;
  this.r[9] = ((t7 >>>  5)) & 0x007f;

  this.pad[0] = key[16] & 0xff | (key[17] & 0xff) << 8;
  this.pad[1] = key[18] & 0xff | (key[19] & 0xff) << 8;
  this.pad[2] = key[20] & 0xff | (key[21] & 0xff) << 8;
  this.pad[3] = key[22] & 0xff | (key[23] & 0xff) << 8;
  this.pad[4] = key[24] & 0xff | (key[25] & 0xff) << 8;
  this.pad[5] = key[26] & 0xff | (key[27] & 0xff) << 8;
  this.pad[6] = key[28] & 0xff | (key[29] & 0xff) << 8;
  this.pad[7] = key[30] & 0xff | (key[31] & 0xff) << 8;
};

poly1305.prototype.blocks = function(m, mpos, bytes) {
  var hibit = this.fin ? 0 : (1 << 11);
  var t0, t1, t2, t3, t4, t5, t6, t7, c;
  var d0, d1, d2, d3, d4, d5, d6, d7, d8, d9;

  var h0 = this.h[0],
      h1 = this.h[1],
      h2 = this.h[2],
      h3 = this.h[3],
      h4 = this.h[4],
      h5 = this.h[5],
      h6 = this.h[6],
      h7 = this.h[7],
      h8 = this.h[8],
      h9 = this.h[9];

  var r0 = this.r[0],
      r1 = this.r[1],
      r2 = this.r[2],
      r3 = this.r[3],
      r4 = this.r[4],
      r5 = this.r[5],
      r6 = this.r[6],
      r7 = this.r[7],
      r8 = this.r[8],
      r9 = this.r[9];

  while (bytes >= 16) {
    t0 = m[mpos+ 0] & 0xff | (m[mpos+ 1] & 0xff) << 8; h0 += ( t0                     ) & 0x1fff;
    t1 = m[mpos+ 2] & 0xff | (m[mpos+ 3] & 0xff) << 8; h1 += ((t0 >>> 13) | (t1 <<  3)) & 0x1fff;
    t2 = m[mpos+ 4] & 0xff | (m[mpos+ 5] & 0xff) << 8; h2 += ((t1 >>> 10) | (t2 <<  6)) & 0x1fff;
    t3 = m[mpos+ 6] & 0xff | (m[mpos+ 7] & 0xff) << 8; h3 += ((t2 >>>  7) | (t3 <<  9)) & 0x1fff;
    t4 = m[mpos+ 8] & 0xff | (m[mpos+ 9] & 0xff) << 8; h4 += ((t3 >>>  4) | (t4 << 12)) & 0x1fff;
    h5 += ((t4 >>>  1)) & 0x1fff;
    t5 = m[mpos+10] & 0xff | (m[mpos+11] & 0xff) << 8; h6 += ((t4 >>> 14) | (t5 <<  2)) & 0x1fff;
    t6 = m[mpos+12] & 0xff | (m[mpos+13] & 0xff) << 8; h7 += ((t5 >>> 11) | (t6 <<  5)) & 0x1fff;
    t7 = m[mpos+14] & 0xff | (m[mpos+15] & 0xff) << 8; h8 += ((t6 >>>  8) | (t7 <<  8)) & 0x1fff;
    h9 += ((t7 >>> 5)) | hibit;

    c = 0;

    d0 = c;
    d0 += h0 * r0;
    d0 += h1 * (5 * r9);
    d0 += h2 * (5 * r8);
    d0 += h3 * (5 * r7);
    d0 += h4 * (5 * r6);
    c = (d0 >>> 13); d0 &= 0x1fff;
    d0 += h5 * (5 * r5);
    d0 += h6 * (5 * r4);
    d0 += h7 * (5 * r3);
    d0 += h8 * (5 * r2);
    d0 += h9 * (5 * r1);
    c += (d0 >>> 13); d0 &= 0x1fff;

    d1 = c;
    d1 += h0 * r1;
    d1 += h1 * r0;
    d1 += h2 * (5 * r9);
    d1 += h3 * (5 * r8);
    d1 += h4 * (5 * r7);
    c = (d1 >>> 13); d1 &= 0x1fff;
    d1 += h5 * (5 * r6);
    d1 += h6 * (5 * r5);
    d1 += h7 * (5 * r4);
    d1 += h8 * (5 * r3);
    d1 += h9 * (5 * r2);
    c += (d1 >>> 13); d1 &= 0x1fff;

    d2 = c;
    d2 += h0 * r2;
    d2 += h1 * r1;
    d2 += h2 * r0;
    d2 += h3 * (5 * r9);
    d2 += h4 * (5 * r8);
    c = (d2 >>> 13); d2 &= 0x1fff;
    d2 += h5 * (5 * r7);
    d2 += h6 * (5 * r6);
    d2 += h7 * (5 * r5);
    d2 += h8 * (5 * r4);
    d2 += h9 * (5 * r3);
    c += (d2 >>> 13); d2 &= 0x1fff;

    d3 = c;
    d3 += h0 * r3;
    d3 += h1 * r2;
    d3 += h2 * r1;
    d3 += h3 * r0;
    d3 += h4 * (5 * r9);
    c = (d3 >>> 13); d3 &= 0x1fff;
    d3 += h5 * (5 * r8);
    d3 += h6 * (5 * r7);
    d3 += h7 * (5 * r6);
    d3 += h8 * (5 * r5);
    d3 += h9 * (5 * r4);
    c += (d3 >>> 13); d3 &= 0x1fff;

    d4 = c;
    d4 += h0 * r4;
    d4 += h1 * r3;
    d4 += h2 * r2;
    d4 += h3 * r1;
    d4 += h4 * r0;
    c = (d4 >>> 13); d4 &= 0x1fff;
    d4 += h5 * (5 * r9);
    d4 += h6 * (5 * r8);
    d4 += h7 * (5 * r7);
    d4 += h8 * (5 * r6);
    d4 += h9 * (5 * r5);
    c += (d4 >>> 13); d4 &= 0x1fff;

    d5 = c;
    d5 += h0 * r5;
    d5 += h1 * r4;
    d5 += h2 * r3;
    d5 += h3 * r2;
    d5 += h4 * r1;
    c = (d5 >>> 13); d5 &= 0x1fff;
    d5 += h5 * r0;
    d5 += h6 * (5 * r9);
    d5 += h7 * (5 * r8);
    d5 += h8 * (5 * r7);
    d5 += h9 * (5 * r6);
    c += (d5 >>> 13); d5 &= 0x1fff;

    d6 = c;
    d6 += h0 * r6;
    d6 += h1 * r5;
    d6 += h2 * r4;
    d6 += h3 * r3;
    d6 += h4 * r2;
    c = (d6 >>> 13); d6 &= 0x1fff;
    d6 += h5 * r1;
    d6 += h6 * r0;
    d6 += h7 * (5 * r9);
    d6 += h8 * (5 * r8);
    d6 += h9 * (5 * r7);
    c += (d6 >>> 13); d6 &= 0x1fff;

    d7 = c;
    d7 += h0 * r7;
    d7 += h1 * r6;
    d7 += h2 * r5;
    d7 += h3 * r4;
    d7 += h4 * r3;
    c = (d7 >>> 13); d7 &= 0x1fff;
    d7 += h5 * r2;
    d7 += h6 * r1;
    d7 += h7 * r0;
    d7 += h8 * (5 * r9);
    d7 += h9 * (5 * r8);
    c += (d7 >>> 13); d7 &= 0x1fff;

    d8 = c;
    d8 += h0 * r8;
    d8 += h1 * r7;
    d8 += h2 * r6;
    d8 += h3 * r5;
    d8 += h4 * r4;
    c = (d8 >>> 13); d8 &= 0x1fff;
    d8 += h5 * r3;
    d8 += h6 * r2;
    d8 += h7 * r1;
    d8 += h8 * r0;
    d8 += h9 * (5 * r9);
    c += (d8 >>> 13); d8 &= 0x1fff;

    d9 = c;
    d9 += h0 * r9;
    d9 += h1 * r8;
    d9 += h2 * r7;
    d9 += h3 * r6;
    d9 += h4 * r5;
    c = (d9 >>> 13); d9 &= 0x1fff;
    d9 += h5 * r4;
    d9 += h6 * r3;
    d9 += h7 * r2;
    d9 += h8 * r1;
    d9 += h9 * r0;
    c += (d9 >>> 13); d9 &= 0x1fff;

    c = (((c << 2) + c)) | 0;
    c = (c + d0) | 0;
    d0 = c & 0x1fff;
    c = (c >>> 13);
    d1 += c;

    h0 = d0;
    h1 = d1;
    h2 = d2;
    h3 = d3;
    h4 = d4;
    h5 = d5;
    h6 = d6;
    h7 = d7;
    h8 = d8;
    h9 = d9;

    mpos += 16;
    bytes -= 16;
  }
  this.h[0] = h0;
  this.h[1] = h1;
  this.h[2] = h2;
  this.h[3] = h3;
  this.h[4] = h4;
  this.h[5] = h5;
  this.h[6] = h6;
  this.h[7] = h7;
  this.h[8] = h8;
  this.h[9] = h9;
};

poly1305.prototype.finish = function(mac, macpos) {
  var g = new Uint16Array(10);
  var c, mask, f, i;

  if (this.leftover) {
    i = this.leftover;
    this.buffer[i++] = 1;
    for (; i < 16; i++) this.buffer[i] = 0;
    this.fin = 1;
    this.blocks(this.buffer, 0, 16);
  }

  c = this.h[1] >>> 13;
  this.h[1] &= 0x1fff;
  for (i = 2; i < 10; i++) {
    this.h[i] += c;
    c = this.h[i] >>> 13;
    this.h[i] &= 0x1fff;
  }
  this.h[0] += (c * 5);
  c = this.h[0] >>> 13;
  this.h[0] &= 0x1fff;
  this.h[1] += c;
  c = this.h[1] >>> 13;
  this.h[1] &= 0x1fff;
  this.h[2] += c;

  g[0] = this.h[0] + 5;
  c = g[0] >>> 13;
  g[0] &= 0x1fff;
  for (i = 1; i < 10; i++) {
    g[i] = this.h[i] + c;
    c = g[i] >>> 13;
    g[i] &= 0x1fff;
  }
  g[9] -= (1 << 13);

  mask = (c ^ 1) - 1;
  for (i = 0; i < 10; i++) g[i] &= mask;
  mask = ~mask;
  for (i = 0; i < 10; i++) this.h[i] = (this.h[i] & mask) | g[i];

  this.h[0] = ((this.h[0]       ) | (this.h[1] << 13)                    ) & 0xffff;
  this.h[1] = ((this.h[1] >>>  3) | (this.h[2] << 10)                    ) & 0xffff;
  this.h[2] = ((this.h[2] >>>  6) | (this.h[3] <<  7)                    ) & 0xffff;
  this.h[3] = ((this.h[3] >>>  9) | (this.h[4] <<  4)                    ) & 0xffff;
  this.h[4] = ((this.h[4] >>> 12) | (this.h[5] <<  1) | (this.h[6] << 14)) & 0xffff;
  this.h[5] = ((this.h[6] >>>  2) | (this.h[7] << 11)                    ) & 0xffff;
  this.h[6] = ((this.h[7] >>>  5) | (this.h[8] <<  8)                    ) & 0xffff;
  this.h[7] = ((this.h[8] >>>  8) | (this.h[9] <<  5)                    ) & 0xffff;

  f = this.h[0] + this.pad[0];
  this.h[0] = f & 0xffff;
  for (i = 1; i < 8; i++) {
    f = (((this.h[i] + this.pad[i]) | 0) + (f >>> 16)) | 0;
    this.h[i] = f & 0xffff;
  }

  mac[macpos+ 0] = (this.h[0] >>> 0) & 0xff;
  mac[macpos+ 1] = (this.h[0] >>> 8) & 0xff;
  mac[macpos+ 2] = (this.h[1] >>> 0) & 0xff;
  mac[macpos+ 3] = (this.h[1] >>> 8) & 0xff;
  mac[macpos+ 4] = (this.h[2] >>> 0) & 0xff;
  mac[macpos+ 5] = (this.h[2] >>> 8) & 0xff;
  mac[macpos+ 6] = (this.h[3] >>> 0) & 0xff;
  mac[macpos+ 7] = (this.h[3] >>> 8) & 0xff;
  mac[macpos+ 8] = (this.h[4] >>> 0) & 0xff;
  mac[macpos+ 9] = (this.h[4] >>> 8) & 0xff;
  mac[macpos+10] = (this.h[5] >>> 0) & 0xff;
  mac[macpos+11] = (this.h[5] >>> 8) & 0xff;
  mac[macpos+12] = (this.h[6] >>> 0) & 0xff;
  mac[macpos+13] = (this.h[6] >>> 8) & 0xff;
  mac[macpos+14] = (this.h[7] >>> 0) & 0xff;
  mac[macpos+15] = (this.h[7] >>> 8) & 0xff;
};

poly1305.prototype.update = function(m, mpos, bytes) {
  var i, want;

  if (this.leftover) {
    want = (16 - this.leftover);
    if (want > bytes)
      want = bytes;
    for (i = 0; i < want; i++)
      this.buffer[this.leftover + i] = m[mpos+i];
    bytes -= want;
    mpos += want;
    this.leftover += want;
    if (this.leftover < 16)
      return;
    this.blocks(this.buffer, 0, 16);
    this.leftover = 0;
  }

  if (bytes >= 16) {
    want = bytes - (bytes % 16);
    this.blocks(m, mpos, want);
    mpos += want;
    bytes -= want;
  }

  if (bytes) {
    for (i = 0; i < bytes; i++)
      this.buffer[this.leftover + i] = m[mpos+i];
    this.leftover += bytes;
  }
};

function crypto_onetimeauth(out, outpos, m, mpos, n, k) {
  var s = new poly1305(k);
  s.update(m, mpos, n);
  s.finish(out, outpos);
  return 0;
}

function crypto_onetimeauth_verify(h, hpos, m, mpos, n, k) {
  var x = new Uint8Array(16);
  crypto_onetimeauth(x,0,m,mpos,n,k);
  return crypto_verify_16(h,hpos,x,0);
}

function crypto_secretbox(c,m,d,n,k) {
  var i;
  if (d < 32) return -1;
  crypto_stream_xor(c,0,m,0,d,n,k);
  crypto_onetimeauth(c, 16, c, 32, d - 32, c);
  for (i = 0; i < 16; i++) c[i] = 0;
  return 0;
}

function crypto_secretbox_open(m,c,d,n,k) {
  var i;
  var x = new Uint8Array(32);
  if (d < 32) return -1;
  crypto_stream(x,0,32,n,k);
  if (crypto_onetimeauth_verify(c, 16,c, 32,d - 32,x) !== 0) return -1;
  crypto_stream_xor(m,0,c,0,d,n,k);
  for (i = 0; i < 32; i++) m[i] = 0;
  return 0;
}

function set25519(r, a) {
  var i;
  for (i = 0; i < 16; i++) r[i] = a[i]|0;
}

function car25519(o) {
  var i, v, c = 1;
  for (i = 0; i < 16; i++) {
    v = o[i] + c + 65535;
    c = Math.floor(v / 65536);
    o[i] = v - c * 65536;
  }
  o[0] += c-1 + 37 * (c-1);
}

function sel25519(p, q, b) {
  var t, c = ~(b-1);
  for (var i = 0; i < 16; i++) {
    t = c & (p[i] ^ q[i]);
    p[i] ^= t;
    q[i] ^= t;
  }
}

function pack25519(o, n) {
  var i, j, b;
  var m = gf(), t = gf();
  for (i = 0; i < 16; i++) t[i] = n[i];
  car25519(t);
  car25519(t);
  car25519(t);
  for (j = 0; j < 2; j++) {
    m[0] = t[0] - 0xffed;
    for (i = 1; i < 15; i++) {
      m[i] = t[i] - 0xffff - ((m[i-1]>>16) & 1);
      m[i-1] &= 0xffff;
    }
    m[15] = t[15] - 0x7fff - ((m[14]>>16) & 1);
    b = (m[15]>>16) & 1;
    m[14] &= 0xffff;
    sel25519(t, m, 1-b);
  }
  for (i = 0; i < 16; i++) {
    o[2*i] = t[i] & 0xff;
    o[2*i+1] = t[i]>>8;
  }
}

function neq25519(a, b) {
  var c = new Uint8Array(32), d = new Uint8Array(32);
  pack25519(c, a);
  pack25519(d, b);
  return crypto_verify_32(c, 0, d, 0);
}

function par25519(a) {
  var d = new Uint8Array(32);
  pack25519(d, a);
  return d[0] & 1;
}

function unpack25519(o, n) {
  var i;
  for (i = 0; i < 16; i++) o[i] = n[2*i] + (n[2*i+1] << 8);
  o[15] &= 0x7fff;
}

function A(o, a, b) {
  for (var i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

function Z(o, a, b) {
  for (var i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

function M(o, a, b) {
  var v, c,
     t0 = 0,  t1 = 0,  t2 = 0,  t3 = 0,  t4 = 0,  t5 = 0,  t6 = 0,  t7 = 0,
     t8 = 0,  t9 = 0, t10 = 0, t11 = 0, t12 = 0, t13 = 0, t14 = 0, t15 = 0,
    t16 = 0, t17 = 0, t18 = 0, t19 = 0, t20 = 0, t21 = 0, t22 = 0, t23 = 0,
    t24 = 0, t25 = 0, t26 = 0, t27 = 0, t28 = 0, t29 = 0, t30 = 0,
    b0 = b[0],
    b1 = b[1],
    b2 = b[2],
    b3 = b[3],
    b4 = b[4],
    b5 = b[5],
    b6 = b[6],
    b7 = b[7],
    b8 = b[8],
    b9 = b[9],
    b10 = b[10],
    b11 = b[11],
    b12 = b[12],
    b13 = b[13],
    b14 = b[14],
    b15 = b[15];

  v = a[0];
  t0 += v * b0;
  t1 += v * b1;
  t2 += v * b2;
  t3 += v * b3;
  t4 += v * b4;
  t5 += v * b5;
  t6 += v * b6;
  t7 += v * b7;
  t8 += v * b8;
  t9 += v * b9;
  t10 += v * b10;
  t11 += v * b11;
  t12 += v * b12;
  t13 += v * b13;
  t14 += v * b14;
  t15 += v * b15;
  v = a[1];
  t1 += v * b0;
  t2 += v * b1;
  t3 += v * b2;
  t4 += v * b3;
  t5 += v * b4;
  t6 += v * b5;
  t7 += v * b6;
  t8 += v * b7;
  t9 += v * b8;
  t10 += v * b9;
  t11 += v * b10;
  t12 += v * b11;
  t13 += v * b12;
  t14 += v * b13;
  t15 += v * b14;
  t16 += v * b15;
  v = a[2];
  t2 += v * b0;
  t3 += v * b1;
  t4 += v * b2;
  t5 += v * b3;
  t6 += v * b4;
  t7 += v * b5;
  t8 += v * b6;
  t9 += v * b7;
  t10 += v * b8;
  t11 += v * b9;
  t12 += v * b10;
  t13 += v * b11;
  t14 += v * b12;
  t15 += v * b13;
  t16 += v * b14;
  t17 += v * b15;
  v = a[3];
  t3 += v * b0;
  t4 += v * b1;
  t5 += v * b2;
  t6 += v * b3;
  t7 += v * b4;
  t8 += v * b5;
  t9 += v * b6;
  t10 += v * b7;
  t11 += v * b8;
  t12 += v * b9;
  t13 += v * b10;
  t14 += v * b11;
  t15 += v * b12;
  t16 += v * b13;
  t17 += v * b14;
  t18 += v * b15;
  v = a[4];
  t4 += v * b0;
  t5 += v * b1;
  t6 += v * b2;
  t7 += v * b3;
  t8 += v * b4;
  t9 += v * b5;
  t10 += v * b6;
  t11 += v * b7;
  t12 += v * b8;
  t13 += v * b9;
  t14 += v * b10;
  t15 += v * b11;
  t16 += v * b12;
  t17 += v * b13;
  t18 += v * b14;
  t19 += v * b15;
  v = a[5];
  t5 += v * b0;
  t6 += v * b1;
  t7 += v * b2;
  t8 += v * b3;
  t9 += v * b4;
  t10 += v * b5;
  t11 += v * b6;
  t12 += v * b7;
  t13 += v * b8;
  t14 += v * b9;
  t15 += v * b10;
  t16 += v * b11;
  t17 += v * b12;
  t18 += v * b13;
  t19 += v * b14;
  t20 += v * b15;
  v = a[6];
  t6 += v * b0;
  t7 += v * b1;
  t8 += v * b2;
  t9 += v * b3;
  t10 += v * b4;
  t11 += v * b5;
  t12 += v * b6;
  t13 += v * b7;
  t14 += v * b8;
  t15 += v * b9;
  t16 += v * b10;
  t17 += v * b11;
  t18 += v * b12;
  t19 += v * b13;
  t20 += v * b14;
  t21 += v * b15;
  v = a[7];
  t7 += v * b0;
  t8 += v * b1;
  t9 += v * b2;
  t10 += v * b3;
  t11 += v * b4;
  t12 += v * b5;
  t13 += v * b6;
  t14 += v * b7;
  t15 += v * b8;
  t16 += v * b9;
  t17 += v * b10;
  t18 += v * b11;
  t19 += v * b12;
  t20 += v * b13;
  t21 += v * b14;
  t22 += v * b15;
  v = a[8];
  t8 += v * b0;
  t9 += v * b1;
  t10 += v * b2;
  t11 += v * b3;
  t12 += v * b4;
  t13 += v * b5;
  t14 += v * b6;
  t15 += v * b7;
  t16 += v * b8;
  t17 += v * b9;
  t18 += v * b10;
  t19 += v * b11;
  t20 += v * b12;
  t21 += v * b13;
  t22 += v * b14;
  t23 += v * b15;
  v = a[9];
  t9 += v * b0;
  t10 += v * b1;
  t11 += v * b2;
  t12 += v * b3;
  t13 += v * b4;
  t14 += v * b5;
  t15 += v * b6;
  t16 += v * b7;
  t17 += v * b8;
  t18 += v * b9;
  t19 += v * b10;
  t20 += v * b11;
  t21 += v * b12;
  t22 += v * b13;
  t23 += v * b14;
  t24 += v * b15;
  v = a[10];
  t10 += v * b0;
  t11 += v * b1;
  t12 += v * b2;
  t13 += v * b3;
  t14 += v * b4;
  t15 += v * b5;
  t16 += v * b6;
  t17 += v * b7;
  t18 += v * b8;
  t19 += v * b9;
  t20 += v * b10;
  t21 += v * b11;
  t22 += v * b12;
  t23 += v * b13;
  t24 += v * b14;
  t25 += v * b15;
  v = a[11];
  t11 += v * b0;
  t12 += v * b1;
  t13 += v * b2;
  t14 += v * b3;
  t15 += v * b4;
  t16 += v * b5;
  t17 += v * b6;
  t18 += v * b7;
  t19 += v * b8;
  t20 += v * b9;
  t21 += v * b10;
  t22 += v * b11;
  t23 += v * b12;
  t24 += v * b13;
  t25 += v * b14;
  t26 += v * b15;
  v = a[12];
  t12 += v * b0;
  t13 += v * b1;
  t14 += v * b2;
  t15 += v * b3;
  t16 += v * b4;
  t17 += v * b5;
  t18 += v * b6;
  t19 += v * b7;
  t20 += v * b8;
  t21 += v * b9;
  t22 += v * b10;
  t23 += v * b11;
  t24 += v * b12;
  t25 += v * b13;
  t26 += v * b14;
  t27 += v * b15;
  v = a[13];
  t13 += v * b0;
  t14 += v * b1;
  t15 += v * b2;
  t16 += v * b3;
  t17 += v * b4;
  t18 += v * b5;
  t19 += v * b6;
  t20 += v * b7;
  t21 += v * b8;
  t22 += v * b9;
  t23 += v * b10;
  t24 += v * b11;
  t25 += v * b12;
  t26 += v * b13;
  t27 += v * b14;
  t28 += v * b15;
  v = a[14];
  t14 += v * b0;
  t15 += v * b1;
  t16 += v * b2;
  t17 += v * b3;
  t18 += v * b4;
  t19 += v * b5;
  t20 += v * b6;
  t21 += v * b7;
  t22 += v * b8;
  t23 += v * b9;
  t24 += v * b10;
  t25 += v * b11;
  t26 += v * b12;
  t27 += v * b13;
  t28 += v * b14;
  t29 += v * b15;
  v = a[15];
  t15 += v * b0;
  t16 += v * b1;
  t17 += v * b2;
  t18 += v * b3;
  t19 += v * b4;
  t20 += v * b5;
  t21 += v * b6;
  t22 += v * b7;
  t23 += v * b8;
  t24 += v * b9;
  t25 += v * b10;
  t26 += v * b11;
  t27 += v * b12;
  t28 += v * b13;
  t29 += v * b14;
  t30 += v * b15;

  t0  += 38 * t16;
  t1  += 38 * t17;
  t2  += 38 * t18;
  t3  += 38 * t19;
  t4  += 38 * t20;
  t5  += 38 * t21;
  t6  += 38 * t22;
  t7  += 38 * t23;
  t8  += 38 * t24;
  t9  += 38 * t25;
  t10 += 38 * t26;
  t11 += 38 * t27;
  t12 += 38 * t28;
  t13 += 38 * t29;
  t14 += 38 * t30;
  // t15 left as is

  // first car
  c = 1;
  v =  t0 + c + 65535; c = Math.floor(v / 65536);  t0 = v - c * 65536;
  v =  t1 + c + 65535; c = Math.floor(v / 65536);  t1 = v - c * 65536;
  v =  t2 + c + 65535; c = Math.floor(v / 65536);  t2 = v - c * 65536;
  v =  t3 + c + 65535; c = Math.floor(v / 65536);  t3 = v - c * 65536;
  v =  t4 + c + 65535; c = Math.floor(v / 65536);  t4 = v - c * 65536;
  v =  t5 + c + 65535; c = Math.floor(v / 65536);  t5 = v - c * 65536;
  v =  t6 + c + 65535; c = Math.floor(v / 65536);  t6 = v - c * 65536;
  v =  t7 + c + 65535; c = Math.floor(v / 65536);  t7 = v - c * 65536;
  v =  t8 + c + 65535; c = Math.floor(v / 65536);  t8 = v - c * 65536;
  v =  t9 + c + 65535; c = Math.floor(v / 65536);  t9 = v - c * 65536;
  v = t10 + c + 65535; c = Math.floor(v / 65536); t10 = v - c * 65536;
  v = t11 + c + 65535; c = Math.floor(v / 65536); t11 = v - c * 65536;
  v = t12 + c + 65535; c = Math.floor(v / 65536); t12 = v - c * 65536;
  v = t13 + c + 65535; c = Math.floor(v / 65536); t13 = v - c * 65536;
  v = t14 + c + 65535; c = Math.floor(v / 65536); t14 = v - c * 65536;
  v = t15 + c + 65535; c = Math.floor(v / 65536); t15 = v - c * 65536;
  t0 += c-1 + 37 * (c-1);

  // second car
  c = 1;
  v =  t0 + c + 65535; c = Math.floor(v / 65536);  t0 = v - c * 65536;
  v =  t1 + c + 65535; c = Math.floor(v / 65536);  t1 = v - c * 65536;
  v =  t2 + c + 65535; c = Math.floor(v / 65536);  t2 = v - c * 65536;
  v =  t3 + c + 65535; c = Math.floor(v / 65536);  t3 = v - c * 65536;
  v =  t4 + c + 65535; c = Math.floor(v / 65536);  t4 = v - c * 65536;
  v =  t5 + c + 65535; c = Math.floor(v / 65536);  t5 = v - c * 65536;
  v =  t6 + c + 65535; c = Math.floor(v / 65536);  t6 = v - c * 65536;
  v =  t7 + c + 65535; c = Math.floor(v / 65536);  t7 = v - c * 65536;
  v =  t8 + c + 65535; c = Math.floor(v / 65536);  t8 = v - c * 65536;
  v =  t9 + c + 65535; c = Math.floor(v / 65536);  t9 = v - c * 65536;
  v = t10 + c + 65535; c = Math.floor(v / 65536); t10 = v - c * 65536;
  v = t11 + c + 65535; c = Math.floor(v / 65536); t11 = v - c * 65536;
  v = t12 + c + 65535; c = Math.floor(v / 65536); t12 = v - c * 65536;
  v = t13 + c + 65535; c = Math.floor(v / 65536); t13 = v - c * 65536;
  v = t14 + c + 65535; c = Math.floor(v / 65536); t14 = v - c * 65536;
  v = t15 + c + 65535; c = Math.floor(v / 65536); t15 = v - c * 65536;
  t0 += c-1 + 37 * (c-1);

  o[ 0] = t0;
  o[ 1] = t1;
  o[ 2] = t2;
  o[ 3] = t3;
  o[ 4] = t4;
  o[ 5] = t5;
  o[ 6] = t6;
  o[ 7] = t7;
  o[ 8] = t8;
  o[ 9] = t9;
  o[10] = t10;
  o[11] = t11;
  o[12] = t12;
  o[13] = t13;
  o[14] = t14;
  o[15] = t15;
}

function S(o, a) {
  M(o, a, a);
}

function inv25519(o, i) {
  var c = gf();
  var a;
  for (a = 0; a < 16; a++) c[a] = i[a];
  for (a = 253; a >= 0; a--) {
    S(c, c);
    if(a !== 2 && a !== 4) M(c, c, i);
  }
  for (a = 0; a < 16; a++) o[a] = c[a];
}

function pow2523(o, i) {
  var c = gf();
  var a;
  for (a = 0; a < 16; a++) c[a] = i[a];
  for (a = 250; a >= 0; a--) {
      S(c, c);
      if(a !== 1) M(c, c, i);
  }
  for (a = 0; a < 16; a++) o[a] = c[a];
}

function crypto_scalarmult(q, n, p) {
  var z = new Uint8Array(32);
  var x = new Float64Array(80), r, i;
  var a = gf(), b = gf(), c = gf(),
      d = gf(), e = gf(), f = gf();
  for (i = 0; i < 31; i++) z[i] = n[i];
  z[31]=(n[31]&127)|64;
  z[0]&=248;
  unpack25519(x,p);
  for (i = 0; i < 16; i++) {
    b[i]=x[i];
    d[i]=a[i]=c[i]=0;
  }
  a[0]=d[0]=1;
  for (i=254; i>=0; --i) {
    r=(z[i>>>3]>>>(i&7))&1;
    sel25519(a,b,r);
    sel25519(c,d,r);
    A(e,a,c);
    Z(a,a,c);
    A(c,b,d);
    Z(b,b,d);
    S(d,e);
    S(f,a);
    M(a,c,a);
    M(c,b,e);
    A(e,a,c);
    Z(a,a,c);
    S(b,a);
    Z(c,d,f);
    M(a,c,_121665);
    A(a,a,d);
    M(c,c,a);
    M(a,d,f);
    M(d,b,x);
    S(b,e);
    sel25519(a,b,r);
    sel25519(c,d,r);
  }
  for (i = 0; i < 16; i++) {
    x[i+16]=a[i];
    x[i+32]=c[i];
    x[i+48]=b[i];
    x[i+64]=d[i];
  }
  var x32 = x.subarray(32);
  var x16 = x.subarray(16);
  inv25519(x32,x32);
  M(x16,x16,x32);
  pack25519(q,x16);
  return 0;
}

function crypto_scalarmult_base(q, n) {
  return crypto_scalarmult(q, n, _9);
}

function crypto_box_keypair(y, x) {
  randombytes(x, 32);
  return crypto_scalarmult_base(y, x);
}

function crypto_box_beforenm(k, y, x) {
  var s = new Uint8Array(32);
  crypto_scalarmult(s, x, y);
  return crypto_core_hsalsa20(k, _0, s, sigma);
}

var crypto_box_afternm = crypto_secretbox;
var crypto_box_open_afternm = crypto_secretbox_open;

function crypto_box(c, m, d, n, y, x) {
  var k = new Uint8Array(32);
  crypto_box_beforenm(k, y, x);
  return crypto_box_afternm(c, m, d, n, k);
}

function crypto_box_open(m, c, d, n, y, x) {
  var k = new Uint8Array(32);
  crypto_box_beforenm(k, y, x);
  return crypto_box_open_afternm(m, c, d, n, k);
}

function crypto_hash(out, m, n) {
  var input = new Uint8Array(n), i;
  for (i = 0; i < n; ++i) {
    input[i] = m[i];
  }
  var hash = blake2b.blake2b(input);
  for (i = 0; i < crypto_hash_BYTES; ++i) {
    out[i] = hash[i];
  }
  return 0;
}

function add(p, q) {
  var a = gf(), b = gf(), c = gf(),
      d = gf(), e = gf(), f = gf(),
      g = gf(), h = gf(), t = gf();

  Z(a, p[1], p[0]);
  Z(t, q[1], q[0]);
  M(a, a, t);
  A(b, p[0], p[1]);
  A(t, q[0], q[1]);
  M(b, b, t);
  M(c, p[3], q[3]);
  M(c, c, D2);
  M(d, p[2], q[2]);
  A(d, d, d);
  Z(e, b, a);
  Z(f, d, c);
  A(g, d, c);
  A(h, b, a);

  M(p[0], e, f);
  M(p[1], h, g);
  M(p[2], g, f);
  M(p[3], e, h);
}

function cswap(p, q, b) {
  var i;
  for (i = 0; i < 4; i++) {
    sel25519(p[i], q[i], b);
  }
}

function pack(r, p) {
  var tx = gf(), ty = gf(), zi = gf();
  inv25519(zi, p[2]);
  M(tx, p[0], zi);
  M(ty, p[1], zi);
  pack25519(r, ty);
  r[31] ^= par25519(tx) << 7;
}

function scalarmult(p, q, s) {
  var b, i;
  set25519(p[0], gf0);
  set25519(p[1], gf1);
  set25519(p[2], gf1);
  set25519(p[3], gf0);
  for (i = 255; i >= 0; --i) {
    b = (s[(i/8)|0] >> (i&7)) & 1;
    cswap(p, q, b);
    add(q, p);
    add(p, p);
    cswap(p, q, b);
  }
}

function scalarbase(p, s) {
  var q = [gf(), gf(), gf(), gf()];
  set25519(q[0], X);
  set25519(q[1], Y);
  set25519(q[2], gf1);
  M(q[3], X, Y);
  scalarmult(p, q, s);
}

function crypto_sign_keypair(pk, sk, seeded) {
  var d = new Uint8Array(64);
  var p = [gf(), gf(), gf(), gf()];
  var i;

  if (!seeded) randombytes(sk, 32);
  crypto_hash(d, sk, 32);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  scalarbase(p, d);
  pack(pk, p);

  for (i = 0; i < 32; i++) sk[i+32] = pk[i];
  return 0;
}

var L = new Float64Array([0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]);

function modL(r, x) {
  var carry, i, j, k;
  for (i = 63; i >= 32; --i) {
    carry = 0;
    for (j = i - 32, k = i - 12; j < k; ++j) {
      x[j] += carry - 16 * x[i] * L[j - (i - 32)];
      carry = (x[j] + 128) >> 8;
      x[j] -= carry * 256;
    }
    x[j] += carry;
    x[i] = 0;
  }
  carry = 0;
  for (j = 0; j < 32; j++) {
    x[j] += carry - (x[31] >> 4) * L[j];
    carry = x[j] >> 8;
    x[j] &= 255;
  }
  for (j = 0; j < 32; j++) x[j] -= carry * L[j];
  for (i = 0; i < 32; i++) {
    x[i+1] += x[i] >> 8;
    r[i] = x[i] & 255;
  }
}

function reduce(r) {
  var x = new Float64Array(64), i;
  for (i = 0; i < 64; i++) x[i] = r[i];
  for (i = 0; i < 64; i++) r[i] = 0;
  modL(r, x);
}

// Note: difference from C - smlen returned, not passed as argument.
function crypto_sign(sm, m, n, sk) {
  var d = new Uint8Array(64), h = new Uint8Array(64), r = new Uint8Array(64);
  var i, j, x = new Float64Array(64);
  var p = [gf(), gf(), gf(), gf()];

  crypto_hash(d, sk, 32);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  var smlen = n + 64;
  for (i = 0; i < n; i++) sm[64 + i] = m[i];
  for (i = 0; i < 32; i++) sm[32 + i] = d[32 + i];

  crypto_hash(r, sm.subarray(32), n+32);
  reduce(r);
  scalarbase(p, r);
  pack(sm, p);

  for (i = 32; i < 64; i++) sm[i] = sk[i];
  crypto_hash(h, sm, n + 64);
  reduce(h);

  for (i = 0; i < 64; i++) x[i] = 0;
  for (i = 0; i < 32; i++) x[i] = r[i];
  for (i = 0; i < 32; i++) {
    for (j = 0; j < 32; j++) {
      x[i+j] += h[i] * d[j];
    }
  }

  modL(sm.subarray(32), x);
  return smlen;
}

function unpackneg(r, p) {
  var t = gf(), chk = gf(), num = gf(),
      den = gf(), den2 = gf(), den4 = gf(),
      den6 = gf();

  set25519(r[2], gf1);
  unpack25519(r[1], p);
  S(num, r[1]);
  M(den, num, D);
  Z(num, num, r[2]);
  A(den, r[2], den);

  S(den2, den);
  S(den4, den2);
  M(den6, den4, den2);
  M(t, den6, num);
  M(t, t, den);

  pow2523(t, t);
  M(t, t, num);
  M(t, t, den);
  M(t, t, den);
  M(r[0], t, den);

  S(chk, r[0]);
  M(chk, chk, den);
  if (neq25519(chk, num)) M(r[0], r[0], I);

  S(chk, r[0]);
  M(chk, chk, den);
  if (neq25519(chk, num)) return -1;

  if (par25519(r[0]) === (p[31]>>7)) Z(r[0], gf0, r[0]);

  M(r[3], r[0], r[1]);
  return 0;
}

function crypto_sign_open(m, sm, n, pk) {
  var i, mlen;
  var t = new Uint8Array(32), h = new Uint8Array(64);
  var p = [gf(), gf(), gf(), gf()],
      q = [gf(), gf(), gf(), gf()];

  mlen = -1;
  if (n < 64) return -1;

  if (unpackneg(q, pk)) return -1;

  for (i = 0; i < n; i++) m[i] = sm[i];
  for (i = 0; i < 32; i++) m[i+32] = pk[i];
  crypto_hash(h, m, n);
  reduce(h);
  scalarmult(p, q, h);

  scalarbase(q, sm.subarray(32));
  add(p, q);
  pack(t, p);

  n -= 64;
  if (crypto_verify_32(sm, 0, t, 0)) {
    for (i = 0; i < n; i++) m[i] = 0;
    return -1;
  }

  for (i = 0; i < n; i++) m[i] = sm[i + 64];
  mlen = n;
  return mlen;
}

var crypto_secretbox_KEYBYTES = 32,
    crypto_secretbox_NONCEBYTES = 24,
    crypto_secretbox_ZEROBYTES = 32,
    crypto_secretbox_BOXZEROBYTES = 16,
    crypto_scalarmult_BYTES = 32,
    crypto_scalarmult_SCALARBYTES = 32,
    crypto_box_PUBLICKEYBYTES = 32,
    crypto_box_SECRETKEYBYTES = 32,
    crypto_box_BEFORENMBYTES = 32,
    crypto_box_NONCEBYTES = crypto_secretbox_NONCEBYTES,
    crypto_box_ZEROBYTES = crypto_secretbox_ZEROBYTES,
    crypto_box_BOXZEROBYTES = crypto_secretbox_BOXZEROBYTES,
    crypto_sign_BYTES = 64,
    crypto_sign_PUBLICKEYBYTES = 32,
    crypto_sign_SECRETKEYBYTES = 64,
    crypto_sign_SEEDBYTES = 32,
    crypto_hash_BYTES = 64;

nacl.lowlevel = {
  crypto_core_hsalsa20: crypto_core_hsalsa20,
  crypto_stream_xor: crypto_stream_xor,
  crypto_stream: crypto_stream,
  crypto_stream_salsa20_xor: crypto_stream_salsa20_xor,
  crypto_stream_salsa20: crypto_stream_salsa20,
  crypto_onetimeauth: crypto_onetimeauth,
  crypto_onetimeauth_verify: crypto_onetimeauth_verify,
  crypto_verify_16: crypto_verify_16,
  crypto_verify_32: crypto_verify_32,
  crypto_secretbox: crypto_secretbox,
  crypto_secretbox_open: crypto_secretbox_open,
  crypto_scalarmult: crypto_scalarmult,
  crypto_scalarmult_base: crypto_scalarmult_base,
  crypto_box_beforenm: crypto_box_beforenm,
  crypto_box_afternm: crypto_box_afternm,
  crypto_box: crypto_box,
  crypto_box_open: crypto_box_open,
  crypto_box_keypair: crypto_box_keypair,
  crypto_hash: crypto_hash,
  crypto_sign: crypto_sign,
  crypto_sign_keypair: crypto_sign_keypair,
  crypto_sign_open: crypto_sign_open,

  crypto_secretbox_KEYBYTES: crypto_secretbox_KEYBYTES,
  crypto_secretbox_NONCEBYTES: crypto_secretbox_NONCEBYTES,
  crypto_secretbox_ZEROBYTES: crypto_secretbox_ZEROBYTES,
  crypto_secretbox_BOXZEROBYTES: crypto_secretbox_BOXZEROBYTES,
  crypto_scalarmult_BYTES: crypto_scalarmult_BYTES,
  crypto_scalarmult_SCALARBYTES: crypto_scalarmult_SCALARBYTES,
  crypto_box_PUBLICKEYBYTES: crypto_box_PUBLICKEYBYTES,
  crypto_box_SECRETKEYBYTES: crypto_box_SECRETKEYBYTES,
  crypto_box_BEFORENMBYTES: crypto_box_BEFORENMBYTES,
  crypto_box_NONCEBYTES: crypto_box_NONCEBYTES,
  crypto_box_ZEROBYTES: crypto_box_ZEROBYTES,
  crypto_box_BOXZEROBYTES: crypto_box_BOXZEROBYTES,
  crypto_sign_BYTES: crypto_sign_BYTES,
  crypto_sign_PUBLICKEYBYTES: crypto_sign_PUBLICKEYBYTES,
  crypto_sign_SECRETKEYBYTES: crypto_sign_SECRETKEYBYTES,
  crypto_sign_SEEDBYTES: crypto_sign_SEEDBYTES,
  crypto_hash_BYTES: crypto_hash_BYTES
};

/* High-level API */

function checkLengths(k, n) {
  if (k.length !== crypto_secretbox_KEYBYTES) throw new Error('bad key size');
  if (n.length !== crypto_secretbox_NONCEBYTES) throw new Error('bad nonce size');
}

function checkBoxLengths(pk, sk) {
  if (pk.length !== crypto_box_PUBLICKEYBYTES) throw new Error('bad public key size');
  if (sk.length !== crypto_box_SECRETKEYBYTES) throw new Error('bad secret key size');
}

function checkArrayTypes() {
  for (var i = 0; i < arguments.length; i++) {
    if (!(arguments[i] instanceof Uint8Array))
      throw new TypeError('unexpected type, use Uint8Array');
  }
}

function cleanup(arr) {
  for (var i = 0; i < arr.length; i++) arr[i] = 0;
}

nacl.randomBytes = function(n) {
  var b = new Uint8Array(n);
  randombytes(b, n);
  return b;
};

nacl.secretbox = function(msg, nonce, key) {
  checkArrayTypes(msg, nonce, key);
  checkLengths(key, nonce);
  var m = new Uint8Array(crypto_secretbox_ZEROBYTES + msg.length);
  var c = new Uint8Array(m.length);
  for (var i = 0; i < msg.length; i++) m[i+crypto_secretbox_ZEROBYTES] = msg[i];
  crypto_secretbox(c, m, m.length, nonce, key);
  return c.subarray(crypto_secretbox_BOXZEROBYTES);
};

nacl.secretbox.open = function(box, nonce, key) {
  checkArrayTypes(box, nonce, key);
  checkLengths(key, nonce);
  var c = new Uint8Array(crypto_secretbox_BOXZEROBYTES + box.length);
  var m = new Uint8Array(c.length);
  for (var i = 0; i < box.length; i++) c[i+crypto_secretbox_BOXZEROBYTES] = box[i];
  if (c.length < 32) return null;
  if (crypto_secretbox_open(m, c, c.length, nonce, key) !== 0) return null;
  return m.subarray(crypto_secretbox_ZEROBYTES);
};

nacl.secretbox.keyLength = crypto_secretbox_KEYBYTES;
nacl.secretbox.nonceLength = crypto_secretbox_NONCEBYTES;
nacl.secretbox.overheadLength = crypto_secretbox_BOXZEROBYTES;

nacl.scalarMult = function(n, p) {
  checkArrayTypes(n, p);
  if (n.length !== crypto_scalarmult_SCALARBYTES) throw new Error('bad n size');
  if (p.length !== crypto_scalarmult_BYTES) throw new Error('bad p size');
  var q = new Uint8Array(crypto_scalarmult_BYTES);
  crypto_scalarmult(q, n, p);
  return q;
};

nacl.scalarMult.base = function(n) {
  checkArrayTypes(n);
  if (n.length !== crypto_scalarmult_SCALARBYTES) throw new Error('bad n size');
  var q = new Uint8Array(crypto_scalarmult_BYTES);
  crypto_scalarmult_base(q, n);
  return q;
};

nacl.scalarMult.scalarLength = crypto_scalarmult_SCALARBYTES;
nacl.scalarMult.groupElementLength = crypto_scalarmult_BYTES;

nacl.box = function(msg, nonce, publicKey, secretKey) {
  var k = nacl.box.before(publicKey, secretKey);
  return nacl.secretbox(msg, nonce, k);
};

nacl.box.before = function(publicKey, secretKey) {
  checkArrayTypes(publicKey, secretKey);
  checkBoxLengths(publicKey, secretKey);
  var k = new Uint8Array(crypto_box_BEFORENMBYTES);
  crypto_box_beforenm(k, publicKey, secretKey);
  return k;
};

nacl.box.after = nacl.secretbox;

nacl.box.open = function(msg, nonce, publicKey, secretKey) {
  var k = nacl.box.before(publicKey, secretKey);
  return nacl.secretbox.open(msg, nonce, k);
};

nacl.box.open.after = nacl.secretbox.open;

nacl.box.keyPair = function() {
  var pk = new Uint8Array(crypto_box_PUBLICKEYBYTES);
  var sk = new Uint8Array(crypto_box_SECRETKEYBYTES);
  crypto_box_keypair(pk, sk);
  return {publicKey: pk, secretKey: sk};
};

nacl.box.keyPair.fromSecretKey = function(secretKey) {
  checkArrayTypes(secretKey);
  if (secretKey.length !== crypto_box_SECRETKEYBYTES)
    throw new Error('bad secret key size');
  var pk = new Uint8Array(crypto_box_PUBLICKEYBYTES);
  crypto_scalarmult_base(pk, secretKey);
  return {publicKey: pk, secretKey: new Uint8Array(secretKey)};
};

nacl.box.publicKeyLength = crypto_box_PUBLICKEYBYTES;
nacl.box.secretKeyLength = crypto_box_SECRETKEYBYTES;
nacl.box.sharedKeyLength = crypto_box_BEFORENMBYTES;
nacl.box.nonceLength = crypto_box_NONCEBYTES;
nacl.box.overheadLength = nacl.secretbox.overheadLength;

nacl.sign = function(msg, secretKey) {
  checkArrayTypes(msg, secretKey);
  if (secretKey.length !== crypto_sign_SECRETKEYBYTES)
    throw new Error('bad secret key size');
  var signedMsg = new Uint8Array(crypto_sign_BYTES+msg.length);
  crypto_sign(signedMsg, msg, msg.length, secretKey);
  return signedMsg;
};

nacl.sign.open = function(signedMsg, publicKey) {
  checkArrayTypes(signedMsg, publicKey);
  if (publicKey.length !== crypto_sign_PUBLICKEYBYTES)
    throw new Error('bad public key size');
  var tmp = new Uint8Array(signedMsg.length);
  var mlen = crypto_sign_open(tmp, signedMsg, signedMsg.length, publicKey);
  if (mlen < 0) return null;
  var m = new Uint8Array(mlen);
  for (var i = 0; i < m.length; i++) m[i] = tmp[i];
  return m;
};

nacl.sign.detached = function(msg, secretKey) {
  var signedMsg = nacl.sign(msg, secretKey);
  var sig = new Uint8Array(crypto_sign_BYTES);
  for (var i = 0; i < sig.length; i++) sig[i] = signedMsg[i];
  return sig;
};

nacl.sign.detached.verify = function(msg, sig, publicKey) {
  checkArrayTypes(msg, sig, publicKey);
  if (sig.length !== crypto_sign_BYTES)
    throw new Error('bad signature size');
  if (publicKey.length !== crypto_sign_PUBLICKEYBYTES)
    throw new Error('bad public key size');
  var sm = new Uint8Array(crypto_sign_BYTES + msg.length);
  var m = new Uint8Array(crypto_sign_BYTES + msg.length);
  var i;
  for (i = 0; i < crypto_sign_BYTES; i++) sm[i] = sig[i];
  for (i = 0; i < msg.length; i++) sm[i+crypto_sign_BYTES] = msg[i];
  return (crypto_sign_open(m, sm, sm.length, publicKey) >= 0);
};

nacl.sign.keyPair = function() {
  var pk = new Uint8Array(crypto_sign_PUBLICKEYBYTES);
  var sk = new Uint8Array(crypto_sign_SECRETKEYBYTES);
  crypto_sign_keypair(pk, sk);
  return {publicKey: pk, secretKey: sk};
};

nacl.sign.keyPair.fromSecretKey = function(secretKey) {
  checkArrayTypes(secretKey);
  if (secretKey.length !== crypto_sign_SECRETKEYBYTES)
    throw new Error('bad secret key size');
  var pk = new Uint8Array(crypto_sign_PUBLICKEYBYTES);
  for (var i = 0; i < pk.length; i++) pk[i] = secretKey[32+i];
  return {publicKey: pk, secretKey: new Uint8Array(secretKey)};
};

nacl.sign.keyPair.fromSeed = function(seed) {
  checkArrayTypes(seed);
  if (seed.length !== crypto_sign_SEEDBYTES)
    throw new Error('bad seed size');
  var pk = new Uint8Array(crypto_sign_PUBLICKEYBYTES);
  var sk = new Uint8Array(crypto_sign_SECRETKEYBYTES);
  for (var i = 0; i < 32; i++) sk[i] = seed[i];
  crypto_sign_keypair(pk, sk, true);
  return {publicKey: pk, secretKey: sk};
};

nacl.sign.publicKeyLength = crypto_sign_PUBLICKEYBYTES;
nacl.sign.secretKeyLength = crypto_sign_SECRETKEYBYTES;
nacl.sign.seedLength = crypto_sign_SEEDBYTES;
nacl.sign.signatureLength = crypto_sign_BYTES;

nacl.hash = function(msg) {
  checkArrayTypes(msg);
  var h = new Uint8Array(crypto_hash_BYTES);
  crypto_hash(h, msg, msg.length);
  return h;
};

nacl.hash.hashLength = crypto_hash_BYTES;

nacl.verify = function(x, y) {
  checkArrayTypes(x, y);
  // Zero length arguments are considered not equal.
  if (x.length === 0 || y.length === 0) return false;
  if (x.length !== y.length) return false;
  return (vn(x, 0, y, 0, x.length) === 0) ? true : false;
};

nacl.setPRNG = function(fn) {
  randombytes = fn;
};

(function() {
  // Initialize PRNG if environment provides CSPRNG.
  // If not, methods calling randombytes will throw.
  var crypto = typeof self !== 'undefined' ? (self.crypto || self.msCrypto) : null;
  if (crypto && crypto.getRandomValues) {
    // Browsers.
    var QUOTA = 65536;
    nacl.setPRNG(function(x, n) {
      var i, v = new Uint8Array(n);
      for (i = 0; i < n; i += QUOTA) {
        crypto.getRandomValues(v.subarray(i, i + Math.min(n - i, QUOTA)));
      }
      for (i = 0; i < n; i++) x[i] = v[i];
      cleanup(v);
    });
  } else if (typeof require !== 'undefined') {
    // Node.js.
    crypto = require('crypto');
    if (crypto && crypto.randomBytes) {
      nacl.setPRNG(function(x, n) {
        var i, v = crypto.randomBytes(n);
        for (i = 0; i < n; i++) x[i] = v[i];
        cleanup(v);
      });
    }
  }
})();

})(typeof module !== 'undefined' && module.exports ? module.exports : (self.nacl = self.nacl || {}));

},{"blakejs/blake2b":30,"crypto":43}],35:[function(require,module,exports){
'use strict';

module.exports = function () {
  throw new Error(
    'ws does not work in the browser. Browser clients must use the native ' +
      'WebSocket object'
  );
};

},{}],36:[function(require,module,exports){
/**
 * NanoMemoTools.memo module
 * @module NanoMemoTools/memo
 */

const version = require('./version');
const tools = require('./tools');
const node = require('./node');
const NanoCurrency = require('nanocurrency');

/**
* This function validates a given message
* @public
* @param {string} message message to validate
* @param {number} [maxlength=512] configurable maxlength of message
* @returns {boolean} true for validated message, false otherwise
*/
const validateMessage = function(message, maxlength=512) {
  try {
      message = message.toString('ascii');

      if (message.length > maxlength) return false;

      return message;
  } catch {
      return false;
  }
}
module.exports.validateMessage = validateMessage;

/**
* This function validates a given signature
* @public
* @param {string} signature 128-hex string representing a signature
* @returns {boolean} true for validated signature, false otherwise
*/
const validateSignature = function(signature) {
  try {
      if (signature.length != 128) return false;
      return true;
  } catch {
      return false;
  }
}
module.exports.validateSignature = validateSignature;

/**
* This function validates a given key (public or private)
* @public
* @param {string} key 64-hex string representing a key
* @returns {boolean} true for validated key, false otherwise
*/
const validateKey = function(key) {
  try {
      return NanoCurrency.checkKey(key);
  } catch {
      return false;
  }
}
module.exports.validateKey = validateKey;

/**
* This function validates a given address
* @public
* @param {string} address Nano address
* @returns {boolean} true for validated address, false otherwise
*/
const validateAddress = function(address) {
  try {
      return NanoCurrency.checkAddress(address);
  } catch {
      return false;
  }
}
module.exports.validateAddress = validateAddress;

/**
* This function validates a given hash
* @public
* @param {string} hash 64-hex string representing a Nano block hash
* @returns {boolean} true for validated hash, false otherwise
*/
const validateHash = function(hash) {
  try {
      return NanoCurrency.checkHash(hash);
  } catch {
      return false;
  }
}
module.exports.validateHash = validateHash;

/**
 * This function validates a Memo against the Nano Network; No username/password required if connecting to DEFAULT_SERVER or public API
 * @param {Memo} memo Memo to validate against the Nano Network
 * @param {string} [url=node.DEFAULT_SERVER] url of Nano Node RPC
 * @param {string} [username=undefined] username for Nano Node RPC authentication
 * @param {string} [password=password] password for Nano Node RPC authentication
 * @returns {boolean} True if valid, false if not valid, undefined if corresponding block not found
 */
const nodeValidated = async function(memo, url=node.DEFAULT_SERVER, username=undefined, password=undefined) {
  if (!memo.valid_signature) return false;

  const block = await node.block_info(memo.hash, url, username, password).catch(function(e) {
    console.error('In memo.nodeValidated, an error was caught running node.block_info');
    console.error(e);
    return undefined;
  });
  if (!block || !block.block_account) {
      // hash not found on Nano Network, return undefined
      return undefined;
  }

  // Memo has already been validated with the signing_address
  // Don't compare addresses because nano_ or xrb_ prefixes may not match, so convert to public key
  //  and compare to be same
  if (tools.getPublicKeyFromAddress(memo.signing_address).toUpperCase() == tools.getPublicKeyFromAddress(block.block_account).toUpperCase()) return true;

  return false;
}
module.exports.nodeValidated = nodeValidated;

/**
* This function converts a Memo into an EncryptedMemo Object
* @public
* @param {Memo} memo Memo Object to convert
* @param {string} signing_private_key 64-hex string representing a Nano Account's private key
* @param {string} decrypting_address Nano address whose will be able to decrypt the memo
* @param {number} [version_encrypt=undefined] version of encryption algorithm - Versioning not yet implemented
* @returns {EncryptedMemo} EncryptedMemo Object with the message encrypted
*/
module.exports.encrypt = function(memo, signing_private_key, decrypting_address, version_encrypt=undefined) {

  // Validate inputs
  if (!validateKey(signing_private_key)) {
    throw new TypeError('Invalid signing_private_key');
  }
  if (!validateAddress(decrypting_address)) {
    throw new TypeError('Invalid decrypting_address');
  }
  const decrypting_public_key = tools.getPublicKeyFromAddress(decrypting_address);

  // The hash is used as the nonce for encryption
  const encrypted_message = tools.encryptMessage(
    memo.message,
    memo.hash,
    decrypting_public_key,
    signing_private_key,
    version_encrypt
  );
  
  // Clear signature as message has changed
  const encrypted_memo = new EncryptedMemo(
    memo.hash,
    encrypted_message,
    memo.signing_address,
    decrypting_address,
    undefined,
    memo.version_sign,
    version_encrypt
  );
  
  return encrypted_memo;
}

/**
* This function converts an EncryptedMemo into a Memo Object
* @public
* @param {EncryptedMemo} encrypted_memo EncryptedMemo Object to convert
* @param {string} decrypting_private_key 64-hex string representing a Nano Account's private key
* @returns {Memo} Memo Object with the message as plaintext
*/
module.exports.decrypt = function(encrypted_memo, decrypting_private_key) {

  // The hash is used as the nonce for encryption
  const decrypted_message = tools.decryptMessage(
    encrypted_memo.message,
    encrypted_memo.hash,
    encrypted_memo.signing_public_key,
    decrypting_private_key,
    encrypted_memo.version_encrypt
  );

  // Clear signature as message has changed
  const decrypted_memo = new Memo(
    encrypted_memo.hash,
    decrypted_message,
    encrypted_memo.signing_address,
    undefined,
    encrypted_memo.version_sign
  );
  
  return decrypted_memo;
}

/** Class representing a Memo (with plaintext message) */
class Memo {

  /**
   * Creates a Memo
   * @param {string} hash 64-hex string representing a Nano block hash
   * @param {string} message message of memo
   * @param {string} signing_address Nano address that owns block with hash
   * @param {string} [signature=undefined] 128-hex string signature of memo
   * @param {number} [version_sign=version.sign] version of signing algorithm - Versioning not yet implemented
   */
  constructor (hash, message, signing_address, signature=undefined, version_sign=version.sign) {
    this.message = undefined;
    this.hash = undefined;
    this.signing_address = undefined;
    this.signature = undefined;
    this.version_sign = undefined;

    // Validate inputs
    if (validateHash(hash)) {
      this.hash = hash;
    } else {
      throw new TypeError('Invalid hash parameter');
    }

    if (validateMessage(message)) {
      this.message = message;
    } else {
      throw new TypeError('Invalid message parameter');
    }

    if (validateAddress(signing_address)) {
      this.signing_address = signing_address;
    } else {
      throw new TypeError('Invalid signing_address parameter');
    }

    if (signature) {  // Optional argument
      if (validateSignature(signature)) {
        this.signature = signature;
      } else {
        throw new TypeError('Invalid signature parameter');
      }
    }

    this.version_sign = version_sign;
  }

  /**
   * Getter for signing_public_key
   * @returns {string} value of signing public_key, derived from signing_address
   */
  get signing_public_key() {
    return tools.getPublicKeyFromAddress(this.signing_address);
  }

  /**
   * Getter for valid_signature
   * @returns {boolean} True if signature is valid, false otherwise
   */
  get valid_signature() {
    if (!this.signature) return false;

    // Signed buffer is concatenation of the message and the hash
    const buffer = this.message + this.hash;
    return tools.verify(buffer, this.signing_public_key, this.signature);
  }

  /**
   * Getter for is_encrypted
   * @returns {boolean} True if memo is encrypted, false otherwise
   */
  get is_encrypted() {
    return false;
  }

  /**
   * Calculates and signs the memo
   * @param {string} signing_private_key 64-hex private key of Nano Account that owns the memo
   * @param {number} [version_sign=undefined] version of signing algorithm - Versioning not yet implemented
   * @returns {string} 128-hex signature
   */
  sign(signing_private_key, version_sign=undefined) {

    // Update sign version
    if (version_sign !== undefined) this.version_sign = version_sign;

    // Validate inputs
    if (!validateKey(signing_private_key)) {
      throw new TypeError('Invalid signing_private_key parameter');
    }

    // Signed buffer is concatenation of the message and the hash
    const buffer = this.message + this.hash;
    this.signature = tools.sign(buffer, signing_private_key);
    return this.signature;
  }

}
module.exports.Memo = Memo;

/** Class representing an EncryptedMemo (with ciphertext message)
 * @extends Memo
*/
class EncryptedMemo extends Memo {

  /**
   * Creates an EncryptedMemo
   * @param {string} hash 64-hex string representing a Nano block hash
   * @param {string} encrypted_message encrypted message of memo
   * @param {string} signing_address Nano address that owns block with hash
   * @param {string} decrypting_address Nano address that will be able to decrypt and read the message
   * @param {string} [signature=undefined] 128-hex string signature of memo
   * @param {number} [version_sign=version.sign] version of signing algorithm - Versioning not yet implemented
   * @param {number} [version_encrypt=undefined] version of encryption algorithm - Versioning not yet implemented
   */
  constructor(hash, encrypted_message, signing_address, decrypting_address, signature=undefined, version_sign=version.sign, version_encrypt=undefined) {
    super(hash, encrypted_message, signing_address, signature, version_sign);
    this.decrypting_address = undefined;
    this.version_encrypt = undefined;

    if (validateAddress(decrypting_address)) {
      this.decrypting_address = decrypting_address;
    } else {
      throw new TypeError('Invalid decrypting_address parameter');
    }

    this.version_encrypt = version_encrypt;
  }

  /**
   * Getter for is_encrypted
   * @returns {boolean} True if memo is encrypted, false otherwise
   */
  get is_encrypted() {
    return true;
  }

}
module.exports.EncryptedMemo = EncryptedMemo;
},{"./node":38,"./tools":40,"./version":41,"nanocurrency":32}],37:[function(require,module,exports){
/**
 * NanoMemoTools.network module
 * @module NanoMemoTools/network
 */

const axios = require('axios');
const ReconnectingWebSocket = require('reconnecting-websocket');
const WS = require('ws');

/**
* This function sends a network POST request
* @public
* @param {string} url target of POST request
* @param {Object} params data fields to include in POST request
* @returns {Promise} Promise object represents the data field of a POST request's response
*/
module.exports.post = async function(url, params, headers={}) {
    let response = await axios.post(url, params, headers);
    return response.data;
}

/**
* This function sends a network GET request
* @private
* @param {string} url target of POST request
* @returns {Promise} Promise object represents the data field of a POST request's response
*/
module.exports.get = async function(url) {
    let response = await axios.get(url);
    return response.data;
}

/**
* This function sets up a websocket
* @private
* @param {string} url address of websocket
* @param {function} onopen function called when websocket is opened successfully; handles one argument, the websocket object
* @param {function} onmessage function called when websocket receives a message; handles two arguments, 1. websocket object 2. message
* @param {function} onclose function called when websocket is closed; handles one argument, the websocket object
* @param {function} onerror function called when websocket encounters an error; handles two arguments, 1. websocket object 2. error
* @returns {object} websocket object
*/
module.exports.websocket = async function(url, onopen, onmessage, onclose, onerror) {
    let ws = new ReconnectingWebSocket(url, [], {
        // WebSocket: WS,
        connectionTimeout: 1000,
        maxRetries: Infinity,
        maxReconnectionDelay: 8000,
        minReconnectionDelay: 3000
    });

    ws.onmessage = msg => {
        onmessage(ws, msg);
    }
    ws.onopen = () => {
        onopen(ws);
    }
    ws.onclose = () => {
        onclose(ws);
    }
    ws.onerror = (e) => {
        onerror(ws, e);
    }

    return ws;
}
},{"axios":3,"reconnecting-websocket":33,"ws":35}],38:[function(require,module,exports){
(function (Buffer){(function (){
/**
 * NanoMemoTools.node module
 * @module NanoMemoTools/node
 */

const network = require('./network');

/**
 * Default Nano Node Server
 */
const DEFAULT_SERVER = module.exports.DEFAULT_SERVER = 'https://node.somenano.com/proxy';

/**
 * This function returns a headers object to include in a network.post request
 * @private
 * @param {string} username username for auth
 * @param {string} password password for auth 
 * @returns {object} headers object to include in network.post
 */
const basicAuth = function(username, password) {
    let headers = {}
    if (username && password) {
        const auth_token = Buffer.from(username +':'+ password, 'utf8').toString('base64');
        headers = {
            headers: {
                'Authorization': 'Basic '+ auth_token
            }
        }
    }
    return headers;
}

/**
* This function requests information of a Nano Block from a given RPC server
* @public
* @param {string} hash hash identifier for requested Nano Block
* @param {string} [url=DEFAULT_SERVER] target RPC server to send the request
* @param {string} [username=undefined] username for Nano Node RPC authentication
* @param {string} [password=password] password for Nano Node RPC authentication
* @returns {Promise} Promise object represents the fields returned from an RPC block_info request
*/
const block_info = function(hash, url=DEFAULT_SERVER, username=undefined, password=undefined) {
    input = {
        action: 'block_info',
        json_block: true,
        hash: hash
    }

    return network.post(url, input, basicAuth(username, password));
}
module.exports.block_info = block_info;
}).call(this)}).call(this,require("buffer").Buffer)
},{"./network":37,"buffer":44}],39:[function(require,module,exports){
/**
 * NanoMemoTools.server module
 * @module NanoMemoTools/server
 */

const network = require('./network.js');
const node = require('./node');
const Memo = require('./memo.js');
let SERVER = 'https://nanomemo.cc';
let WSS = 'wss://nanomemo.cc';

/**
* This function gathers user data from the server
* @public
* @param {string} api_key user public api key
* @param {string} api_secret user private secret key
* @param {string} [endpoint=/api/user/] endpoint of POST request
* @returns {Promise} Promise object represents the user data as an object
*/
const getUserData = async function(api_key, api_secret, endpoint='/api/user') {
    
    const data = {
        api_key: api_key,
        api_secret: api_secret
    }
    return network.post(SERVER + endpoint, data);
}

/**
* This function gathers a memo's data from the server
* @public
* @param {string} hash 64-hex hash that represents a Nano Block
* @param {string} [endpoint=/api/memo/block/] endpoint of POST request
* @returns {Promise} Promise object represents the memo object 
*/
const getMemo = async function(hash, endpoint='/api/memo/block/') {
    if (!Memo.validateHash(hash)) {
        console.error('In NanoMemoTools.server.getMemo, hash failed validation');
        return undefined;
    }

    let response = await network.get(SERVER + endpoint + hash);
    if (response === undefined || response === null) {
        return {
            success: false,
            dtg: new Date(),
            error: 'No response returned'
        }
    }
    if (response.error !== undefined) return response;

    // Get corresponding block data
    const block = await node.block_info(response.data.hash).catch(function(e) {
        console.error('In NanoMemoTools.server.getMemo, error caught when running node.block_info for hash: '+ response.data.hash);
        console.error(e);
        return undefined;
    });
    if (block === undefined || block === null) {
        console.error('In NanoMemoTools.server.getMemo, no block data returned for hash: '+ response.data.hash);
        return undefined;
    }

    // Create Memo Object
    let memo = undefined;
    if (response.version_encrypt !== undefined) {
        // Yes, encrypted
        memo = new Memo.EncryptedMemo(response.data.hash, response.data.message, response.data.signing_address, response.data.decrypting_address, response.data.signature, response.data.version_sign, response.data.version_encrypt);
    } else {
        // No, not encrypted
        memo = new Memo.Memo(response.data.hash, response.data.message, response.data.signing_address, response.data.signature, response.data.version_sign);
    }

    // Validate signature locally
    if (!memo.valid_signature) {
        console.error('In NanoMemoTools.server.getMemo, memo signature validation failed');
        return undefined;
    }

    return memo;
}

/**
* This function saves a memo to the server
* @public
* @param {Memo.Memo} memo memo data to be saved to the server
* @param {string} api_key public api key
* @param {string} api_secret private api key
* @param {string} [endpoint=/api/memo/new/] endpoint of POST request
* @returns {Promise} Promise object represents the memo object 
*/
const saveMemo = async function(memo, api_key, api_secret, endpoint='/api/memo/new') {

    if (!memo.valid_signature) {
        console.error('Memo has an invalid signature');
        return {
            success: false,
            dtg: new Date(),
            error: 'Memo has an invalid signature'
        }
    }

    const response = await network.post(SERVER + endpoint, {
        api_key: api_key,
        api_secret: api_secret,
        message: memo.message,
        hash: memo.hash,
        signing_address: memo.signing_address,
        decrypting_address: memo.decrypting_address,
        signature: memo.signature,
        version_sign: memo.version_sign,
        version_encrypt: memo.version_encrypt
    });

    return response;
}

/**
 * This function subscribes to a NanoMemo websocket that will send a message for each new memo that is saved
 * @public
 * @param {function} onmessage function to call with newly received memo data
 * @returns {websocket} websocket object 
 */
const websocketSubscribe = async function(onmessage) {
    const websocket = network.websocket(
        WSS,
        function(ws) {
            // onopen
            console.log('Connected to websocket server: '+ WSS);
            const data = {
                "action": "subscribe"
            }
            ws.send(JSON.stringify(data));
        },
        function(ws, message) {
            // onmessage
            console.log('Websocket message received from: '+ WSS);
            let data = undefined;
            try {
                data = JSON.parse(message.data);
            } catch(e) {
                console.error('Error parsing data into Object: '+ message.data);
            }
            onmessage(data);
        },
        function(ws) {
            // onclose
            console.log('Closed connection to websocket server: '+ WSS);
        },
        function(ws, e) {
            // onerror
            console.error(e);
        }
    );

    return websocket;
}

/**
 * This function unsubscribes to a NanoMemo websocket that was receiving new memos
 * @public
 * @returns undefined
 */
const websocketUnsubscribe = async function() {
    if (websocket === undefined) return;
    const data = {
        "action": "unsubscribe"
    }
    websocket.send(JSON.stringify(data));
}

module.exports = {
    getUserData,
    getMemo,
    saveMemo,
    websocketSubscribe,
    websocketUnsubscribe
}
},{"./memo.js":36,"./network.js":37,"./node":38}],40:[function(require,module,exports){
(function (Buffer){(function (){
/**
 * NanoMemoTools.tools module
 * @module NanoMemoTools/tools
 */

// Thanks to https://github.com/dvdbng/nano-lib for a code in the signing portions of this module

const NanoCurrency = require('nanocurrency');
const ed2curve = require('../lib/ed2curve-blake2b/ed2curve-blake2b');
const nacl = require('tweetnacl-blake2b');
const blake2b = require('blakejs/blake2b');

const MAGIC_STRING = 'Nano Signed Message:\n';

/**
 * Encodes Uint8Array as hex string
 * @private
 * @param {Uint8Array} uint8arr array iterable to encode as string 
 * @returns {string} encoded string
 */
function hexEncode (uint8arr) {
    return Array.from(uint8arr).map(function(x) {
      return ('0' + x.toString(16)).substr(-2)
    }).join('');
}

/**
 * Decodes hex string as Uint8Array
 * @private
 * @param {string} hexString string to decode as Uint8Array 
 * @returns {string} encoded array
 */
function hexDecode (hexString) {
    if ((hexString.length % 2) !== 0) throw new Error('can only decode whole bytes');
    if (/[^0-9a-f]/ig.test(hexString)) throw new Error('invalid hex string');
    const out = new Uint8Array(hexString.length / 2);
    for (var i = 0, len = out.length; i < len; i++) {
      out[i] = parseInt(hexString.substr(i * 2, 2), 16);
    }
    return out;
}

/**
 * Hashes given string into string of hex 32 long
 * @private
 * @param {string} msg string to hash 
 * @returns {string} 32-long hex string
 */
function msgHash (msg) {
    return blake2b.blake2b(MAGIC_STRING + msg, null, 32);
}

/**
 * Hashes given string into string of hex 24 long
 * @private
 * @param {string} nonce string to hash 
 * @returns {string} 24-long hex string
 */
function nonceHash (nonce) {
    return blake2b.blake2b(MAGIC_STRING + nonce, null, 24);
}

/**
* This function calculates and returns a 128-hex string signature for given string buffer
* @public
* @param {string} buffer value to sign
* @param {string} private_key 64-hex string private key
* @param {number} [version=undefined] version of signature algorithm - not yet implemented
* @returns {string} 128-hex string signature
*/
const sign = function(buffer, private_key, version=undefined) {
    const key = nacl.sign.keyPair.fromSeed(hexDecode(private_key)).secretKey;
    return hexEncode(nacl.sign.detached(msgHash(buffer), key));
}

/**
 * This function verifies a given signature is true for given buffer and key
 * @public
 * @param {string} buffer string on which the signature is mapped
 * @param {string} public_key 64-hex string public key of keypair that signed the buffer
 * @param {string} signature 128-hex string signature of public_key on buffer
 * @param {number} version version of signature algorithm - not yet implemented
 * @returns {boolean} true for verified, false otherwise
 */
const verify = function(buffer, public_key, signature, version=undefined) {
    return nacl.sign.detached.verify(msgHash(buffer), hexDecode(signature), hexDecode(public_key));
}

/**
 * This function encrypts a message
 * @public
 * @param {string} message message to encrypt
 * @param {string} nonce unique nonce to increase entropy
 * @param {string} decrypting_public_key 64-hex encrypting public key
 * @param {string} signing_private_key 64-hex signing private key
 * @param {number} version version of encryption algorithm - not yet implemented
 * @returns {string} string representing encrypted message
 */
const encryptMessage = function(message, nonce, decrypting_public_key, signing_private_key, version=undefined) {
    // Convert from signing keys (Ed25519 ) to encryption keys (Curve25519)
    
    const signKey = nacl.sign.keyPair.fromSeed(hexDecode(signing_private_key));
    const dh_decrypting_public_key = Buffer.from(ed2curve.convertPublicKey(hexDecode(decrypting_public_key))).toString('hex');
    const dh_signing_private_key = Buffer.from(ed2curve.convertSecretKey(signKey.secretKey)).toString('hex');
    
    return hexEncode(nacl.box(Buffer.from(message), nonceHash(nonce), hexDecode(dh_decrypting_public_key), hexDecode(dh_signing_private_key)));
}

/**
 * This function decrypts a message
 * @public
 * @param {string} cipher_text encrypted message to decrypt
 * @param {string} nonce unique nonce to increase entropy
 * @param {string} signing_public_key 64-hex signing public key
 * @param {string} decrypting_private_key 64-hex decrypting private key
 * @param {number} version version of encryption algorithm - not yet implemented
 * @returns {string} string representing unencrypted message
 */
const decryptMessage = function(cipher_text, nonce, signing_public_key, decrypting_private_key, version=undefined) {
    // Convert from signing keys (Ed25519 ) to encryption keys (Curve25519)
    
    const signKey = nacl.sign.keyPair.fromSeed(hexDecode(decrypting_private_key));
    const dh_signing_public_key = Buffer.from(ed2curve.convertPublicKey(hexDecode(signing_public_key))).toString('hex');
    const dh_decrypting_private_key = Buffer.from(ed2curve.convertSecretKey(signKey.secretKey)).toString('hex');

    return Buffer.from(nacl.box.open(hexDecode(cipher_text), nonceHash(nonce), hexDecode(dh_signing_public_key), hexDecode(dh_decrypting_private_key))).toString('ascii');
}

/**
 * Derive a Nano Account's private key from a seed and index
 * @public
 * @param {string} seed 64-hex string representing a Nano seed
 * @param {number} index index value of account
 * @returns {string} 64-hex private key
 */
const getPrivateKey = function(seed, index) {
    return NanoCurrency.deriveSecretKey(seed, index);
}

/**
 * Derive a Nano Account's public key from a private key
 * @public
 * @param {string} private_key 64-hex string representing a private key
 * @returns {string} 64-hex public key
 */
const getPublicKeyFromPrivateKey = function(private_key) {
    return NanoCurrency.derivePublicKey(private_key);
}

/**
 * Derive a Nano Account's public key from a Nano address
 * @public
 * @param {string} address Nano address; nano_* or xrb_*
 * @returns {string} 64-hex public key
 */
const getPublicKeyFromAddress = function(address) {
    return NanoCurrency.derivePublicKey(address);
}

/**
 * Derive a Nano Account's address from a Nano public key
 * @public
 * @param {string} public_key 64-hex string representing a public key
 * @returns {string} Nano address: nano_*
 */
const getAddress = function(public_key) {
    return NanoCurrency.deriveAddress(public_key).replace('xrb_', 'nano_');
}

module.exports = {
    sign,
    verify,
    encryptMessage,
    decryptMessage,
    getPrivateKey,
    getPublicKeyFromAddress,
    getPublicKeyFromPrivateKey,
    getAddress
}
}).call(this)}).call(this,require("buffer").Buffer)
},{"../lib/ed2curve-blake2b/ed2curve-blake2b":2,"blakejs/blake2b":30,"buffer":44,"nanocurrency":32,"tweetnacl-blake2b":34}],41:[function(require,module,exports){
/**
 * NanoMemoTools.version module
 * @module NanoMemoTools/version
 */

module.exports = {
    sign: 1.0,
    encrypt: 1.0,
}
},{}],42:[function(require,module,exports){
'use strict'

exports.byteLength = byteLength
exports.toByteArray = toByteArray
exports.fromByteArray = fromByteArray

var lookup = []
var revLookup = []
var Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array

var code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
for (var i = 0, len = code.length; i < len; ++i) {
  lookup[i] = code[i]
  revLookup[code.charCodeAt(i)] = i
}

// Support decoding URL-safe base64 strings, as Node.js does.
// See: https://en.wikipedia.org/wiki/Base64#URL_applications
revLookup['-'.charCodeAt(0)] = 62
revLookup['_'.charCodeAt(0)] = 63

function getLens (b64) {
  var len = b64.length

  if (len % 4 > 0) {
    throw new Error('Invalid string. Length must be a multiple of 4')
  }

  // Trim off extra bytes after placeholder bytes are found
  // See: https://github.com/beatgammit/base64-js/issues/42
  var validLen = b64.indexOf('=')
  if (validLen === -1) validLen = len

  var placeHoldersLen = validLen === len
    ? 0
    : 4 - (validLen % 4)

  return [validLen, placeHoldersLen]
}

// base64 is 4/3 + up to two characters of the original data
function byteLength (b64) {
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function _byteLength (b64, validLen, placeHoldersLen) {
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function toByteArray (b64) {
  var tmp
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]

  var arr = new Arr(_byteLength(b64, validLen, placeHoldersLen))

  var curByte = 0

  // if there are placeholders, only get up to the last complete 4 chars
  var len = placeHoldersLen > 0
    ? validLen - 4
    : validLen

  var i
  for (i = 0; i < len; i += 4) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 18) |
      (revLookup[b64.charCodeAt(i + 1)] << 12) |
      (revLookup[b64.charCodeAt(i + 2)] << 6) |
      revLookup[b64.charCodeAt(i + 3)]
    arr[curByte++] = (tmp >> 16) & 0xFF
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 2) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 2) |
      (revLookup[b64.charCodeAt(i + 1)] >> 4)
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 1) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 10) |
      (revLookup[b64.charCodeAt(i + 1)] << 4) |
      (revLookup[b64.charCodeAt(i + 2)] >> 2)
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  return arr
}

function tripletToBase64 (num) {
  return lookup[num >> 18 & 0x3F] +
    lookup[num >> 12 & 0x3F] +
    lookup[num >> 6 & 0x3F] +
    lookup[num & 0x3F]
}

function encodeChunk (uint8, start, end) {
  var tmp
  var output = []
  for (var i = start; i < end; i += 3) {
    tmp =
      ((uint8[i] << 16) & 0xFF0000) +
      ((uint8[i + 1] << 8) & 0xFF00) +
      (uint8[i + 2] & 0xFF)
    output.push(tripletToBase64(tmp))
  }
  return output.join('')
}

function fromByteArray (uint8) {
  var tmp
  var len = uint8.length
  var extraBytes = len % 3 // if we have 1 byte left, pad 2 bytes
  var parts = []
  var maxChunkLength = 16383 // must be multiple of 3

  // go through the array every three bytes, we'll deal with trailing stuff later
  for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
    parts.push(encodeChunk(uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)))
  }

  // pad the end with zeros, but make sure to not forget the extra bytes
  if (extraBytes === 1) {
    tmp = uint8[len - 1]
    parts.push(
      lookup[tmp >> 2] +
      lookup[(tmp << 4) & 0x3F] +
      '=='
    )
  } else if (extraBytes === 2) {
    tmp = (uint8[len - 2] << 8) + uint8[len - 1]
    parts.push(
      lookup[tmp >> 10] +
      lookup[(tmp >> 4) & 0x3F] +
      lookup[(tmp << 2) & 0x3F] +
      '='
    )
  }

  return parts.join('')
}

},{}],43:[function(require,module,exports){

},{}],44:[function(require,module,exports){
(function (Buffer){(function (){
/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <https://feross.org>
 * @license  MIT
 */
/* eslint-disable no-proto */

'use strict'

var base64 = require('base64-js')
var ieee754 = require('ieee754')

exports.Buffer = Buffer
exports.SlowBuffer = SlowBuffer
exports.INSPECT_MAX_BYTES = 50

var K_MAX_LENGTH = 0x7fffffff
exports.kMaxLength = K_MAX_LENGTH

/**
 * If `Buffer.TYPED_ARRAY_SUPPORT`:
 *   === true    Use Uint8Array implementation (fastest)
 *   === false   Print warning and recommend using `buffer` v4.x which has an Object
 *               implementation (most compatible, even IE6)
 *
 * Browsers that support typed arrays are IE 10+, Firefox 4+, Chrome 7+, Safari 5.1+,
 * Opera 11.6+, iOS 4.2+.
 *
 * We report that the browser does not support typed arrays if the are not subclassable
 * using __proto__. Firefox 4-29 lacks support for adding new properties to `Uint8Array`
 * (See: https://bugzilla.mozilla.org/show_bug.cgi?id=695438). IE 10 lacks support
 * for __proto__ and has a buggy typed array implementation.
 */
Buffer.TYPED_ARRAY_SUPPORT = typedArraySupport()

if (!Buffer.TYPED_ARRAY_SUPPORT && typeof console !== 'undefined' &&
    typeof console.error === 'function') {
  console.error(
    'This browser lacks typed array (Uint8Array) support which is required by ' +
    '`buffer` v5.x. Use `buffer` v4.x if you require old browser support.'
  )
}

function typedArraySupport () {
  // Can typed array instances can be augmented?
  try {
    var arr = new Uint8Array(1)
    arr.__proto__ = { __proto__: Uint8Array.prototype, foo: function () { return 42 } }
    return arr.foo() === 42
  } catch (e) {
    return false
  }
}

Object.defineProperty(Buffer.prototype, 'parent', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.buffer
  }
})

Object.defineProperty(Buffer.prototype, 'offset', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.byteOffset
  }
})

function createBuffer (length) {
  if (length > K_MAX_LENGTH) {
    throw new RangeError('The value "' + length + '" is invalid for option "size"')
  }
  // Return an augmented `Uint8Array` instance
  var buf = new Uint8Array(length)
  buf.__proto__ = Buffer.prototype
  return buf
}

/**
 * The Buffer constructor returns instances of `Uint8Array` that have their
 * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
 * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
 * and the `Uint8Array` methods. Square bracket notation works as expected -- it
 * returns a single octet.
 *
 * The `Uint8Array` prototype remains unmodified.
 */

function Buffer (arg, encodingOrOffset, length) {
  // Common case.
  if (typeof arg === 'number') {
    if (typeof encodingOrOffset === 'string') {
      throw new TypeError(
        'The "string" argument must be of type string. Received type number'
      )
    }
    return allocUnsafe(arg)
  }
  return from(arg, encodingOrOffset, length)
}

// Fix subarray() in ES2016. See: https://github.com/feross/buffer/pull/97
if (typeof Symbol !== 'undefined' && Symbol.species != null &&
    Buffer[Symbol.species] === Buffer) {
  Object.defineProperty(Buffer, Symbol.species, {
    value: null,
    configurable: true,
    enumerable: false,
    writable: false
  })
}

Buffer.poolSize = 8192 // not used by this implementation

function from (value, encodingOrOffset, length) {
  if (typeof value === 'string') {
    return fromString(value, encodingOrOffset)
  }

  if (ArrayBuffer.isView(value)) {
    return fromArrayLike(value)
  }

  if (value == null) {
    throw TypeError(
      'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
      'or Array-like Object. Received type ' + (typeof value)
    )
  }

  if (isInstance(value, ArrayBuffer) ||
      (value && isInstance(value.buffer, ArrayBuffer))) {
    return fromArrayBuffer(value, encodingOrOffset, length)
  }

  if (typeof value === 'number') {
    throw new TypeError(
      'The "value" argument must not be of type number. Received type number'
    )
  }

  var valueOf = value.valueOf && value.valueOf()
  if (valueOf != null && valueOf !== value) {
    return Buffer.from(valueOf, encodingOrOffset, length)
  }

  var b = fromObject(value)
  if (b) return b

  if (typeof Symbol !== 'undefined' && Symbol.toPrimitive != null &&
      typeof value[Symbol.toPrimitive] === 'function') {
    return Buffer.from(
      value[Symbol.toPrimitive]('string'), encodingOrOffset, length
    )
  }

  throw new TypeError(
    'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
    'or Array-like Object. Received type ' + (typeof value)
  )
}

/**
 * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
 * if value is a number.
 * Buffer.from(str[, encoding])
 * Buffer.from(array)
 * Buffer.from(buffer)
 * Buffer.from(arrayBuffer[, byteOffset[, length]])
 **/
Buffer.from = function (value, encodingOrOffset, length) {
  return from(value, encodingOrOffset, length)
}

// Note: Change prototype *after* Buffer.from is defined to workaround Chrome bug:
// https://github.com/feross/buffer/pull/148
Buffer.prototype.__proto__ = Uint8Array.prototype
Buffer.__proto__ = Uint8Array

function assertSize (size) {
  if (typeof size !== 'number') {
    throw new TypeError('"size" argument must be of type number')
  } else if (size < 0) {
    throw new RangeError('The value "' + size + '" is invalid for option "size"')
  }
}

function alloc (size, fill, encoding) {
  assertSize(size)
  if (size <= 0) {
    return createBuffer(size)
  }
  if (fill !== undefined) {
    // Only pay attention to encoding if it's a string. This
    // prevents accidentally sending in a number that would
    // be interpretted as a start offset.
    return typeof encoding === 'string'
      ? createBuffer(size).fill(fill, encoding)
      : createBuffer(size).fill(fill)
  }
  return createBuffer(size)
}

/**
 * Creates a new filled Buffer instance.
 * alloc(size[, fill[, encoding]])
 **/
Buffer.alloc = function (size, fill, encoding) {
  return alloc(size, fill, encoding)
}

function allocUnsafe (size) {
  assertSize(size)
  return createBuffer(size < 0 ? 0 : checked(size) | 0)
}

/**
 * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
 * */
Buffer.allocUnsafe = function (size) {
  return allocUnsafe(size)
}
/**
 * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
 */
Buffer.allocUnsafeSlow = function (size) {
  return allocUnsafe(size)
}

function fromString (string, encoding) {
  if (typeof encoding !== 'string' || encoding === '') {
    encoding = 'utf8'
  }

  if (!Buffer.isEncoding(encoding)) {
    throw new TypeError('Unknown encoding: ' + encoding)
  }

  var length = byteLength(string, encoding) | 0
  var buf = createBuffer(length)

  var actual = buf.write(string, encoding)

  if (actual !== length) {
    // Writing a hex string, for example, that contains invalid characters will
    // cause everything after the first invalid character to be ignored. (e.g.
    // 'abxxcd' will be treated as 'ab')
    buf = buf.slice(0, actual)
  }

  return buf
}

function fromArrayLike (array) {
  var length = array.length < 0 ? 0 : checked(array.length) | 0
  var buf = createBuffer(length)
  for (var i = 0; i < length; i += 1) {
    buf[i] = array[i] & 255
  }
  return buf
}

function fromArrayBuffer (array, byteOffset, length) {
  if (byteOffset < 0 || array.byteLength < byteOffset) {
    throw new RangeError('"offset" is outside of buffer bounds')
  }

  if (array.byteLength < byteOffset + (length || 0)) {
    throw new RangeError('"length" is outside of buffer bounds')
  }

  var buf
  if (byteOffset === undefined && length === undefined) {
    buf = new Uint8Array(array)
  } else if (length === undefined) {
    buf = new Uint8Array(array, byteOffset)
  } else {
    buf = new Uint8Array(array, byteOffset, length)
  }

  // Return an augmented `Uint8Array` instance
  buf.__proto__ = Buffer.prototype
  return buf
}

function fromObject (obj) {
  if (Buffer.isBuffer(obj)) {
    var len = checked(obj.length) | 0
    var buf = createBuffer(len)

    if (buf.length === 0) {
      return buf
    }

    obj.copy(buf, 0, 0, len)
    return buf
  }

  if (obj.length !== undefined) {
    if (typeof obj.length !== 'number' || numberIsNaN(obj.length)) {
      return createBuffer(0)
    }
    return fromArrayLike(obj)
  }

  if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
    return fromArrayLike(obj.data)
  }
}

function checked (length) {
  // Note: cannot use `length < K_MAX_LENGTH` here because that fails when
  // length is NaN (which is otherwise coerced to zero.)
  if (length >= K_MAX_LENGTH) {
    throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
                         'size: 0x' + K_MAX_LENGTH.toString(16) + ' bytes')
  }
  return length | 0
}

function SlowBuffer (length) {
  if (+length != length) { // eslint-disable-line eqeqeq
    length = 0
  }
  return Buffer.alloc(+length)
}

Buffer.isBuffer = function isBuffer (b) {
  return b != null && b._isBuffer === true &&
    b !== Buffer.prototype // so Buffer.isBuffer(Buffer.prototype) will be false
}

Buffer.compare = function compare (a, b) {
  if (isInstance(a, Uint8Array)) a = Buffer.from(a, a.offset, a.byteLength)
  if (isInstance(b, Uint8Array)) b = Buffer.from(b, b.offset, b.byteLength)
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError(
      'The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array'
    )
  }

  if (a === b) return 0

  var x = a.length
  var y = b.length

  for (var i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i]
      y = b[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

Buffer.isEncoding = function isEncoding (encoding) {
  switch (String(encoding).toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'latin1':
    case 'binary':
    case 'base64':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return true
    default:
      return false
  }
}

Buffer.concat = function concat (list, length) {
  if (!Array.isArray(list)) {
    throw new TypeError('"list" argument must be an Array of Buffers')
  }

  if (list.length === 0) {
    return Buffer.alloc(0)
  }

  var i
  if (length === undefined) {
    length = 0
    for (i = 0; i < list.length; ++i) {
      length += list[i].length
    }
  }

  var buffer = Buffer.allocUnsafe(length)
  var pos = 0
  for (i = 0; i < list.length; ++i) {
    var buf = list[i]
    if (isInstance(buf, Uint8Array)) {
      buf = Buffer.from(buf)
    }
    if (!Buffer.isBuffer(buf)) {
      throw new TypeError('"list" argument must be an Array of Buffers')
    }
    buf.copy(buffer, pos)
    pos += buf.length
  }
  return buffer
}

function byteLength (string, encoding) {
  if (Buffer.isBuffer(string)) {
    return string.length
  }
  if (ArrayBuffer.isView(string) || isInstance(string, ArrayBuffer)) {
    return string.byteLength
  }
  if (typeof string !== 'string') {
    throw new TypeError(
      'The "string" argument must be one of type string, Buffer, or ArrayBuffer. ' +
      'Received type ' + typeof string
    )
  }

  var len = string.length
  var mustMatch = (arguments.length > 2 && arguments[2] === true)
  if (!mustMatch && len === 0) return 0

  // Use a for loop to avoid recursion
  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'ascii':
      case 'latin1':
      case 'binary':
        return len
      case 'utf8':
      case 'utf-8':
        return utf8ToBytes(string).length
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return len * 2
      case 'hex':
        return len >>> 1
      case 'base64':
        return base64ToBytes(string).length
      default:
        if (loweredCase) {
          return mustMatch ? -1 : utf8ToBytes(string).length // assume utf8
        }
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}
Buffer.byteLength = byteLength

function slowToString (encoding, start, end) {
  var loweredCase = false

  // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
  // property of a typed array.

  // This behaves neither like String nor Uint8Array in that we set start/end
  // to their upper/lower bounds if the value passed is out of range.
  // undefined is handled specially as per ECMA-262 6th Edition,
  // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.
  if (start === undefined || start < 0) {
    start = 0
  }
  // Return early if start > this.length. Done here to prevent potential uint32
  // coercion fail below.
  if (start > this.length) {
    return ''
  }

  if (end === undefined || end > this.length) {
    end = this.length
  }

  if (end <= 0) {
    return ''
  }

  // Force coersion to uint32. This will also coerce falsey/NaN values to 0.
  end >>>= 0
  start >>>= 0

  if (end <= start) {
    return ''
  }

  if (!encoding) encoding = 'utf8'

  while (true) {
    switch (encoding) {
      case 'hex':
        return hexSlice(this, start, end)

      case 'utf8':
      case 'utf-8':
        return utf8Slice(this, start, end)

      case 'ascii':
        return asciiSlice(this, start, end)

      case 'latin1':
      case 'binary':
        return latin1Slice(this, start, end)

      case 'base64':
        return base64Slice(this, start, end)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return utf16leSlice(this, start, end)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = (encoding + '').toLowerCase()
        loweredCase = true
    }
  }
}

// This property is used by `Buffer.isBuffer` (and the `is-buffer` npm package)
// to detect a Buffer instance. It's not possible to use `instanceof Buffer`
// reliably in a browserify context because there could be multiple different
// copies of the 'buffer' package in use. This method works even for Buffer
// instances that were created from another copy of the `buffer` package.
// See: https://github.com/feross/buffer/issues/154
Buffer.prototype._isBuffer = true

function swap (b, n, m) {
  var i = b[n]
  b[n] = b[m]
  b[m] = i
}

Buffer.prototype.swap16 = function swap16 () {
  var len = this.length
  if (len % 2 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 16-bits')
  }
  for (var i = 0; i < len; i += 2) {
    swap(this, i, i + 1)
  }
  return this
}

Buffer.prototype.swap32 = function swap32 () {
  var len = this.length
  if (len % 4 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 32-bits')
  }
  for (var i = 0; i < len; i += 4) {
    swap(this, i, i + 3)
    swap(this, i + 1, i + 2)
  }
  return this
}

Buffer.prototype.swap64 = function swap64 () {
  var len = this.length
  if (len % 8 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 64-bits')
  }
  for (var i = 0; i < len; i += 8) {
    swap(this, i, i + 7)
    swap(this, i + 1, i + 6)
    swap(this, i + 2, i + 5)
    swap(this, i + 3, i + 4)
  }
  return this
}

Buffer.prototype.toString = function toString () {
  var length = this.length
  if (length === 0) return ''
  if (arguments.length === 0) return utf8Slice(this, 0, length)
  return slowToString.apply(this, arguments)
}

Buffer.prototype.toLocaleString = Buffer.prototype.toString

Buffer.prototype.equals = function equals (b) {
  if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
  if (this === b) return true
  return Buffer.compare(this, b) === 0
}

Buffer.prototype.inspect = function inspect () {
  var str = ''
  var max = exports.INSPECT_MAX_BYTES
  str = this.toString('hex', 0, max).replace(/(.{2})/g, '$1 ').trim()
  if (this.length > max) str += ' ... '
  return '<Buffer ' + str + '>'
}

Buffer.prototype.compare = function compare (target, start, end, thisStart, thisEnd) {
  if (isInstance(target, Uint8Array)) {
    target = Buffer.from(target, target.offset, target.byteLength)
  }
  if (!Buffer.isBuffer(target)) {
    throw new TypeError(
      'The "target" argument must be one of type Buffer or Uint8Array. ' +
      'Received type ' + (typeof target)
    )
  }

  if (start === undefined) {
    start = 0
  }
  if (end === undefined) {
    end = target ? target.length : 0
  }
  if (thisStart === undefined) {
    thisStart = 0
  }
  if (thisEnd === undefined) {
    thisEnd = this.length
  }

  if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
    throw new RangeError('out of range index')
  }

  if (thisStart >= thisEnd && start >= end) {
    return 0
  }
  if (thisStart >= thisEnd) {
    return -1
  }
  if (start >= end) {
    return 1
  }

  start >>>= 0
  end >>>= 0
  thisStart >>>= 0
  thisEnd >>>= 0

  if (this === target) return 0

  var x = thisEnd - thisStart
  var y = end - start
  var len = Math.min(x, y)

  var thisCopy = this.slice(thisStart, thisEnd)
  var targetCopy = target.slice(start, end)

  for (var i = 0; i < len; ++i) {
    if (thisCopy[i] !== targetCopy[i]) {
      x = thisCopy[i]
      y = targetCopy[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

// Finds either the first index of `val` in `buffer` at offset >= `byteOffset`,
// OR the last index of `val` in `buffer` at offset <= `byteOffset`.
//
// Arguments:
// - buffer - a Buffer to search
// - val - a string, Buffer, or number
// - byteOffset - an index into `buffer`; will be clamped to an int32
// - encoding - an optional encoding, relevant is val is a string
// - dir - true for indexOf, false for lastIndexOf
function bidirectionalIndexOf (buffer, val, byteOffset, encoding, dir) {
  // Empty buffer means no match
  if (buffer.length === 0) return -1

  // Normalize byteOffset
  if (typeof byteOffset === 'string') {
    encoding = byteOffset
    byteOffset = 0
  } else if (byteOffset > 0x7fffffff) {
    byteOffset = 0x7fffffff
  } else if (byteOffset < -0x80000000) {
    byteOffset = -0x80000000
  }
  byteOffset = +byteOffset // Coerce to Number.
  if (numberIsNaN(byteOffset)) {
    // byteOffset: it it's undefined, null, NaN, "foo", etc, search whole buffer
    byteOffset = dir ? 0 : (buffer.length - 1)
  }

  // Normalize byteOffset: negative offsets start from the end of the buffer
  if (byteOffset < 0) byteOffset = buffer.length + byteOffset
  if (byteOffset >= buffer.length) {
    if (dir) return -1
    else byteOffset = buffer.length - 1
  } else if (byteOffset < 0) {
    if (dir) byteOffset = 0
    else return -1
  }

  // Normalize val
  if (typeof val === 'string') {
    val = Buffer.from(val, encoding)
  }

  // Finally, search either indexOf (if dir is true) or lastIndexOf
  if (Buffer.isBuffer(val)) {
    // Special case: looking for empty string/buffer always fails
    if (val.length === 0) {
      return -1
    }
    return arrayIndexOf(buffer, val, byteOffset, encoding, dir)
  } else if (typeof val === 'number') {
    val = val & 0xFF // Search for a byte value [0-255]
    if (typeof Uint8Array.prototype.indexOf === 'function') {
      if (dir) {
        return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset)
      } else {
        return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset)
      }
    }
    return arrayIndexOf(buffer, [ val ], byteOffset, encoding, dir)
  }

  throw new TypeError('val must be string, number or Buffer')
}

function arrayIndexOf (arr, val, byteOffset, encoding, dir) {
  var indexSize = 1
  var arrLength = arr.length
  var valLength = val.length

  if (encoding !== undefined) {
    encoding = String(encoding).toLowerCase()
    if (encoding === 'ucs2' || encoding === 'ucs-2' ||
        encoding === 'utf16le' || encoding === 'utf-16le') {
      if (arr.length < 2 || val.length < 2) {
        return -1
      }
      indexSize = 2
      arrLength /= 2
      valLength /= 2
      byteOffset /= 2
    }
  }

  function read (buf, i) {
    if (indexSize === 1) {
      return buf[i]
    } else {
      return buf.readUInt16BE(i * indexSize)
    }
  }

  var i
  if (dir) {
    var foundIndex = -1
    for (i = byteOffset; i < arrLength; i++) {
      if (read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
        if (foundIndex === -1) foundIndex = i
        if (i - foundIndex + 1 === valLength) return foundIndex * indexSize
      } else {
        if (foundIndex !== -1) i -= i - foundIndex
        foundIndex = -1
      }
    }
  } else {
    if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength
    for (i = byteOffset; i >= 0; i--) {
      var found = true
      for (var j = 0; j < valLength; j++) {
        if (read(arr, i + j) !== read(val, j)) {
          found = false
          break
        }
      }
      if (found) return i
    }
  }

  return -1
}

Buffer.prototype.includes = function includes (val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1
}

Buffer.prototype.indexOf = function indexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, true)
}

Buffer.prototype.lastIndexOf = function lastIndexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, false)
}

function hexWrite (buf, string, offset, length) {
  offset = Number(offset) || 0
  var remaining = buf.length - offset
  if (!length) {
    length = remaining
  } else {
    length = Number(length)
    if (length > remaining) {
      length = remaining
    }
  }

  var strLen = string.length

  if (length > strLen / 2) {
    length = strLen / 2
  }
  for (var i = 0; i < length; ++i) {
    var parsed = parseInt(string.substr(i * 2, 2), 16)
    if (numberIsNaN(parsed)) return i
    buf[offset + i] = parsed
  }
  return i
}

function utf8Write (buf, string, offset, length) {
  return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
}

function asciiWrite (buf, string, offset, length) {
  return blitBuffer(asciiToBytes(string), buf, offset, length)
}

function latin1Write (buf, string, offset, length) {
  return asciiWrite(buf, string, offset, length)
}

function base64Write (buf, string, offset, length) {
  return blitBuffer(base64ToBytes(string), buf, offset, length)
}

function ucs2Write (buf, string, offset, length) {
  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length)
}

Buffer.prototype.write = function write (string, offset, length, encoding) {
  // Buffer#write(string)
  if (offset === undefined) {
    encoding = 'utf8'
    length = this.length
    offset = 0
  // Buffer#write(string, encoding)
  } else if (length === undefined && typeof offset === 'string') {
    encoding = offset
    length = this.length
    offset = 0
  // Buffer#write(string, offset[, length][, encoding])
  } else if (isFinite(offset)) {
    offset = offset >>> 0
    if (isFinite(length)) {
      length = length >>> 0
      if (encoding === undefined) encoding = 'utf8'
    } else {
      encoding = length
      length = undefined
    }
  } else {
    throw new Error(
      'Buffer.write(string, encoding, offset[, length]) is no longer supported'
    )
  }

  var remaining = this.length - offset
  if (length === undefined || length > remaining) length = remaining

  if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
    throw new RangeError('Attempt to write outside buffer bounds')
  }

  if (!encoding) encoding = 'utf8'

  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'hex':
        return hexWrite(this, string, offset, length)

      case 'utf8':
      case 'utf-8':
        return utf8Write(this, string, offset, length)

      case 'ascii':
        return asciiWrite(this, string, offset, length)

      case 'latin1':
      case 'binary':
        return latin1Write(this, string, offset, length)

      case 'base64':
        // Warning: maxLength not taken into account in base64Write
        return base64Write(this, string, offset, length)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return ucs2Write(this, string, offset, length)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}

Buffer.prototype.toJSON = function toJSON () {
  return {
    type: 'Buffer',
    data: Array.prototype.slice.call(this._arr || this, 0)
  }
}

function base64Slice (buf, start, end) {
  if (start === 0 && end === buf.length) {
    return base64.fromByteArray(buf)
  } else {
    return base64.fromByteArray(buf.slice(start, end))
  }
}

function utf8Slice (buf, start, end) {
  end = Math.min(buf.length, end)
  var res = []

  var i = start
  while (i < end) {
    var firstByte = buf[i]
    var codePoint = null
    var bytesPerSequence = (firstByte > 0xEF) ? 4
      : (firstByte > 0xDF) ? 3
        : (firstByte > 0xBF) ? 2
          : 1

    if (i + bytesPerSequence <= end) {
      var secondByte, thirdByte, fourthByte, tempCodePoint

      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 0x80) {
            codePoint = firstByte
          }
          break
        case 2:
          secondByte = buf[i + 1]
          if ((secondByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F)
            if (tempCodePoint > 0x7F) {
              codePoint = tempCodePoint
            }
          }
          break
        case 3:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F)
            if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
              codePoint = tempCodePoint
            }
          }
          break
        case 4:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          fourthByte = buf[i + 3]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F)
            if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
              codePoint = tempCodePoint
            }
          }
      }
    }

    if (codePoint === null) {
      // we did not generate a valid codePoint so insert a
      // replacement char (U+FFFD) and advance only 1 byte
      codePoint = 0xFFFD
      bytesPerSequence = 1
    } else if (codePoint > 0xFFFF) {
      // encode to utf16 (surrogate pair dance)
      codePoint -= 0x10000
      res.push(codePoint >>> 10 & 0x3FF | 0xD800)
      codePoint = 0xDC00 | codePoint & 0x3FF
    }

    res.push(codePoint)
    i += bytesPerSequence
  }

  return decodeCodePointsArray(res)
}

// Based on http://stackoverflow.com/a/22747272/680742, the browser with
// the lowest limit is Chrome, with 0x10000 args.
// We go 1 magnitude less, for safety
var MAX_ARGUMENTS_LENGTH = 0x1000

function decodeCodePointsArray (codePoints) {
  var len = codePoints.length
  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints) // avoid extra slice()
  }

  // Decode in chunks to avoid "call stack size exceeded".
  var res = ''
  var i = 0
  while (i < len) {
    res += String.fromCharCode.apply(
      String,
      codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
    )
  }
  return res
}

function asciiSlice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i] & 0x7F)
  }
  return ret
}

function latin1Slice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i])
  }
  return ret
}

function hexSlice (buf, start, end) {
  var len = buf.length

  if (!start || start < 0) start = 0
  if (!end || end < 0 || end > len) end = len

  var out = ''
  for (var i = start; i < end; ++i) {
    out += toHex(buf[i])
  }
  return out
}

function utf16leSlice (buf, start, end) {
  var bytes = buf.slice(start, end)
  var res = ''
  for (var i = 0; i < bytes.length; i += 2) {
    res += String.fromCharCode(bytes[i] + (bytes[i + 1] * 256))
  }
  return res
}

Buffer.prototype.slice = function slice (start, end) {
  var len = this.length
  start = ~~start
  end = end === undefined ? len : ~~end

  if (start < 0) {
    start += len
    if (start < 0) start = 0
  } else if (start > len) {
    start = len
  }

  if (end < 0) {
    end += len
    if (end < 0) end = 0
  } else if (end > len) {
    end = len
  }

  if (end < start) end = start

  var newBuf = this.subarray(start, end)
  // Return an augmented `Uint8Array` instance
  newBuf.__proto__ = Buffer.prototype
  return newBuf
}

/*
 * Need to make sure that buffer isn't trying to write out of bounds.
 */
function checkOffset (offset, ext, length) {
  if ((offset % 1) !== 0 || offset < 0) throw new RangeError('offset is not uint')
  if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length')
}

Buffer.prototype.readUIntLE = function readUIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }

  return val
}

Buffer.prototype.readUIntBE = function readUIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    checkOffset(offset, byteLength, this.length)
  }

  var val = this[offset + --byteLength]
  var mul = 1
  while (byteLength > 0 && (mul *= 0x100)) {
    val += this[offset + --byteLength] * mul
  }

  return val
}

Buffer.prototype.readUInt8 = function readUInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  return this[offset]
}

Buffer.prototype.readUInt16LE = function readUInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return this[offset] | (this[offset + 1] << 8)
}

Buffer.prototype.readUInt16BE = function readUInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return (this[offset] << 8) | this[offset + 1]
}

Buffer.prototype.readUInt32LE = function readUInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return ((this[offset]) |
      (this[offset + 1] << 8) |
      (this[offset + 2] << 16)) +
      (this[offset + 3] * 0x1000000)
}

Buffer.prototype.readUInt32BE = function readUInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] * 0x1000000) +
    ((this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    this[offset + 3])
}

Buffer.prototype.readIntLE = function readIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readIntBE = function readIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var i = byteLength
  var mul = 1
  var val = this[offset + --i]
  while (i > 0 && (mul *= 0x100)) {
    val += this[offset + --i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readInt8 = function readInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  if (!(this[offset] & 0x80)) return (this[offset])
  return ((0xff - this[offset] + 1) * -1)
}

Buffer.prototype.readInt16LE = function readInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset] | (this[offset + 1] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt16BE = function readInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset + 1] | (this[offset] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt32LE = function readInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset]) |
    (this[offset + 1] << 8) |
    (this[offset + 2] << 16) |
    (this[offset + 3] << 24)
}

Buffer.prototype.readInt32BE = function readInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] << 24) |
    (this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    (this[offset + 3])
}

Buffer.prototype.readFloatLE = function readFloatLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, true, 23, 4)
}

Buffer.prototype.readFloatBE = function readFloatBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, false, 23, 4)
}

Buffer.prototype.readDoubleLE = function readDoubleLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, true, 52, 8)
}

Buffer.prototype.readDoubleBE = function readDoubleBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, false, 52, 8)
}

function checkInt (buf, value, offset, ext, max, min) {
  if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance')
  if (value > max || value < min) throw new RangeError('"value" argument is out of bounds')
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
}

Buffer.prototype.writeUIntLE = function writeUIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var mul = 1
  var i = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUIntBE = function writeUIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var i = byteLength - 1
  var mul = 1
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUInt8 = function writeUInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0)
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeUInt16LE = function writeUInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeUInt16BE = function writeUInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeUInt32LE = function writeUInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset + 3] = (value >>> 24)
  this[offset + 2] = (value >>> 16)
  this[offset + 1] = (value >>> 8)
  this[offset] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeUInt32BE = function writeUInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeIntLE = function writeIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = 0
  var mul = 1
  var sub = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeIntBE = function writeIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = byteLength - 1
  var mul = 1
  var sub = 0
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeInt8 = function writeInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80)
  if (value < 0) value = 0xff + value + 1
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeInt16LE = function writeInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeInt16BE = function writeInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeInt32LE = function writeInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  this[offset + 2] = (value >>> 16)
  this[offset + 3] = (value >>> 24)
  return offset + 4
}

Buffer.prototype.writeInt32BE = function writeInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (value < 0) value = 0xffffffff + value + 1
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

function checkIEEE754 (buf, value, offset, ext, max, min) {
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
  if (offset < 0) throw new RangeError('Index out of range')
}

function writeFloat (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 4, 3.4028234663852886e+38, -3.4028234663852886e+38)
  }
  ieee754.write(buf, value, offset, littleEndian, 23, 4)
  return offset + 4
}

Buffer.prototype.writeFloatLE = function writeFloatLE (value, offset, noAssert) {
  return writeFloat(this, value, offset, true, noAssert)
}

Buffer.prototype.writeFloatBE = function writeFloatBE (value, offset, noAssert) {
  return writeFloat(this, value, offset, false, noAssert)
}

function writeDouble (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 8, 1.7976931348623157E+308, -1.7976931348623157E+308)
  }
  ieee754.write(buf, value, offset, littleEndian, 52, 8)
  return offset + 8
}

Buffer.prototype.writeDoubleLE = function writeDoubleLE (value, offset, noAssert) {
  return writeDouble(this, value, offset, true, noAssert)
}

Buffer.prototype.writeDoubleBE = function writeDoubleBE (value, offset, noAssert) {
  return writeDouble(this, value, offset, false, noAssert)
}

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function copy (target, targetStart, start, end) {
  if (!Buffer.isBuffer(target)) throw new TypeError('argument should be a Buffer')
  if (!start) start = 0
  if (!end && end !== 0) end = this.length
  if (targetStart >= target.length) targetStart = target.length
  if (!targetStart) targetStart = 0
  if (end > 0 && end < start) end = start

  // Copy 0 bytes; we're done
  if (end === start) return 0
  if (target.length === 0 || this.length === 0) return 0

  // Fatal error conditions
  if (targetStart < 0) {
    throw new RangeError('targetStart out of bounds')
  }
  if (start < 0 || start >= this.length) throw new RangeError('Index out of range')
  if (end < 0) throw new RangeError('sourceEnd out of bounds')

  // Are we oob?
  if (end > this.length) end = this.length
  if (target.length - targetStart < end - start) {
    end = target.length - targetStart + start
  }

  var len = end - start

  if (this === target && typeof Uint8Array.prototype.copyWithin === 'function') {
    // Use built-in when available, missing from IE11
    this.copyWithin(targetStart, start, end)
  } else if (this === target && start < targetStart && targetStart < end) {
    // descending copy from end
    for (var i = len - 1; i >= 0; --i) {
      target[i + targetStart] = this[i + start]
    }
  } else {
    Uint8Array.prototype.set.call(
      target,
      this.subarray(start, end),
      targetStart
    )
  }

  return len
}

// Usage:
//    buffer.fill(number[, offset[, end]])
//    buffer.fill(buffer[, offset[, end]])
//    buffer.fill(string[, offset[, end]][, encoding])
Buffer.prototype.fill = function fill (val, start, end, encoding) {
  // Handle string cases:
  if (typeof val === 'string') {
    if (typeof start === 'string') {
      encoding = start
      start = 0
      end = this.length
    } else if (typeof end === 'string') {
      encoding = end
      end = this.length
    }
    if (encoding !== undefined && typeof encoding !== 'string') {
      throw new TypeError('encoding must be a string')
    }
    if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
      throw new TypeError('Unknown encoding: ' + encoding)
    }
    if (val.length === 1) {
      var code = val.charCodeAt(0)
      if ((encoding === 'utf8' && code < 128) ||
          encoding === 'latin1') {
        // Fast path: If `val` fits into a single byte, use that numeric value.
        val = code
      }
    }
  } else if (typeof val === 'number') {
    val = val & 255
  }

  // Invalid ranges are not set to a default, so can range check early.
  if (start < 0 || this.length < start || this.length < end) {
    throw new RangeError('Out of range index')
  }

  if (end <= start) {
    return this
  }

  start = start >>> 0
  end = end === undefined ? this.length : end >>> 0

  if (!val) val = 0

  var i
  if (typeof val === 'number') {
    for (i = start; i < end; ++i) {
      this[i] = val
    }
  } else {
    var bytes = Buffer.isBuffer(val)
      ? val
      : Buffer.from(val, encoding)
    var len = bytes.length
    if (len === 0) {
      throw new TypeError('The value "' + val +
        '" is invalid for argument "value"')
    }
    for (i = 0; i < end - start; ++i) {
      this[i + start] = bytes[i % len]
    }
  }

  return this
}

// HELPER FUNCTIONS
// ================

var INVALID_BASE64_RE = /[^+/0-9A-Za-z-_]/g

function base64clean (str) {
  // Node takes equal signs as end of the Base64 encoding
  str = str.split('=')[0]
  // Node strips out invalid characters like \n and \t from the string, base64-js does not
  str = str.trim().replace(INVALID_BASE64_RE, '')
  // Node converts strings with length < 2 to ''
  if (str.length < 2) return ''
  // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
  while (str.length % 4 !== 0) {
    str = str + '='
  }
  return str
}

function toHex (n) {
  if (n < 16) return '0' + n.toString(16)
  return n.toString(16)
}

function utf8ToBytes (string, units) {
  units = units || Infinity
  var codePoint
  var length = string.length
  var leadSurrogate = null
  var bytes = []

  for (var i = 0; i < length; ++i) {
    codePoint = string.charCodeAt(i)

    // is surrogate component
    if (codePoint > 0xD7FF && codePoint < 0xE000) {
      // last char was a lead
      if (!leadSurrogate) {
        // no lead yet
        if (codePoint > 0xDBFF) {
          // unexpected trail
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        } else if (i + 1 === length) {
          // unpaired lead
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        }

        // valid lead
        leadSurrogate = codePoint

        continue
      }

      // 2 leads in a row
      if (codePoint < 0xDC00) {
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
        leadSurrogate = codePoint
        continue
      }

      // valid surrogate pair
      codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000
    } else if (leadSurrogate) {
      // valid bmp char, but last char was a lead
      if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
    }

    leadSurrogate = null

    // encode utf8
    if (codePoint < 0x80) {
      if ((units -= 1) < 0) break
      bytes.push(codePoint)
    } else if (codePoint < 0x800) {
      if ((units -= 2) < 0) break
      bytes.push(
        codePoint >> 0x6 | 0xC0,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x10000) {
      if ((units -= 3) < 0) break
      bytes.push(
        codePoint >> 0xC | 0xE0,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x110000) {
      if ((units -= 4) < 0) break
      bytes.push(
        codePoint >> 0x12 | 0xF0,
        codePoint >> 0xC & 0x3F | 0x80,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else {
      throw new Error('Invalid code point')
    }
  }

  return bytes
}

function asciiToBytes (str) {
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push(str.charCodeAt(i) & 0xFF)
  }
  return byteArray
}

function utf16leToBytes (str, units) {
  var c, hi, lo
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    if ((units -= 2) < 0) break

    c = str.charCodeAt(i)
    hi = c >> 8
    lo = c % 256
    byteArray.push(lo)
    byteArray.push(hi)
  }

  return byteArray
}

function base64ToBytes (str) {
  return base64.toByteArray(base64clean(str))
}

function blitBuffer (src, dst, offset, length) {
  for (var i = 0; i < length; ++i) {
    if ((i + offset >= dst.length) || (i >= src.length)) break
    dst[i + offset] = src[i]
  }
  return i
}

// ArrayBuffer or Uint8Array objects from other contexts (i.e. iframes) do not pass
// the `instanceof` check but they should be treated as of that type.
// See: https://github.com/feross/buffer/issues/166
function isInstance (obj, type) {
  return obj instanceof type ||
    (obj != null && obj.constructor != null && obj.constructor.name != null &&
      obj.constructor.name === type.name)
}
function numberIsNaN (obj) {
  // For IE11 support
  return obj !== obj // eslint-disable-line no-self-compare
}

}).call(this)}).call(this,require("buffer").Buffer)
},{"base64-js":42,"buffer":44,"ieee754":45}],45:[function(require,module,exports){
/*! ieee754. BSD-3-Clause License. Feross Aboukhadijeh <https://feross.org/opensource> */
exports.read = function (buffer, offset, isLE, mLen, nBytes) {
  var e, m
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var nBits = -7
  var i = isLE ? (nBytes - 1) : 0
  var d = isLE ? -1 : 1
  var s = buffer[offset + i]

  i += d

  e = s & ((1 << (-nBits)) - 1)
  s >>= (-nBits)
  nBits += eLen
  for (; nBits > 0; e = (e * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  m = e & ((1 << (-nBits)) - 1)
  e >>= (-nBits)
  nBits += mLen
  for (; nBits > 0; m = (m * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  if (e === 0) {
    e = 1 - eBias
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity)
  } else {
    m = m + Math.pow(2, mLen)
    e = e - eBias
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen)
}

exports.write = function (buffer, value, offset, isLE, mLen, nBytes) {
  var e, m, c
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0)
  var i = isLE ? 0 : (nBytes - 1)
  var d = isLE ? 1 : -1
  var s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0

  value = Math.abs(value)

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0
    e = eMax
  } else {
    e = Math.floor(Math.log(value) / Math.LN2)
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--
      c *= 2
    }
    if (e + eBias >= 1) {
      value += rt / c
    } else {
      value += rt * Math.pow(2, 1 - eBias)
    }
    if (value * c >= 2) {
      e++
      c /= 2
    }

    if (e + eBias >= eMax) {
      m = 0
      e = eMax
    } else if (e + eBias >= 1) {
      m = ((value * c) - 1) * Math.pow(2, mLen)
      e = e + eBias
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen)
      e = 0
    }
  }

  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8) {}

  e = (e << mLen) | m
  eLen += mLen
  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8) {}

  buffer[offset + i - d] |= s * 128
}

},{}],46:[function(require,module,exports){
// shim for using process in browser
var process = module.exports = {};

// cached from whatever global is present so that test runners that stub it
// don't break things.  But we need to wrap it in a try catch in case it is
// wrapped in strict mode code which doesn't define any globals.  It's inside a
// function because try/catches deoptimize in certain engines.

var cachedSetTimeout;
var cachedClearTimeout;

function defaultSetTimout() {
    throw new Error('setTimeout has not been defined');
}
function defaultClearTimeout () {
    throw new Error('clearTimeout has not been defined');
}
(function () {
    try {
        if (typeof setTimeout === 'function') {
            cachedSetTimeout = setTimeout;
        } else {
            cachedSetTimeout = defaultSetTimout;
        }
    } catch (e) {
        cachedSetTimeout = defaultSetTimout;
    }
    try {
        if (typeof clearTimeout === 'function') {
            cachedClearTimeout = clearTimeout;
        } else {
            cachedClearTimeout = defaultClearTimeout;
        }
    } catch (e) {
        cachedClearTimeout = defaultClearTimeout;
    }
} ())
function runTimeout(fun) {
    if (cachedSetTimeout === setTimeout) {
        //normal enviroments in sane situations
        return setTimeout(fun, 0);
    }
    // if setTimeout wasn't available but was latter defined
    if ((cachedSetTimeout === defaultSetTimout || !cachedSetTimeout) && setTimeout) {
        cachedSetTimeout = setTimeout;
        return setTimeout(fun, 0);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedSetTimeout(fun, 0);
    } catch(e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't trust the global object when called normally
            return cachedSetTimeout.call(null, fun, 0);
        } catch(e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error
            return cachedSetTimeout.call(this, fun, 0);
        }
    }


}
function runClearTimeout(marker) {
    if (cachedClearTimeout === clearTimeout) {
        //normal enviroments in sane situations
        return clearTimeout(marker);
    }
    // if clearTimeout wasn't available but was latter defined
    if ((cachedClearTimeout === defaultClearTimeout || !cachedClearTimeout) && clearTimeout) {
        cachedClearTimeout = clearTimeout;
        return clearTimeout(marker);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedClearTimeout(marker);
    } catch (e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't  trust the global object when called normally
            return cachedClearTimeout.call(null, marker);
        } catch (e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error.
            // Some versions of I.E. have different rules for clearTimeout vs setTimeout
            return cachedClearTimeout.call(this, marker);
        }
    }



}
var queue = [];
var draining = false;
var currentQueue;
var queueIndex = -1;

function cleanUpNextTick() {
    if (!draining || !currentQueue) {
        return;
    }
    draining = false;
    if (currentQueue.length) {
        queue = currentQueue.concat(queue);
    } else {
        queueIndex = -1;
    }
    if (queue.length) {
        drainQueue();
    }
}

function drainQueue() {
    if (draining) {
        return;
    }
    var timeout = runTimeout(cleanUpNextTick);
    draining = true;

    var len = queue.length;
    while(len) {
        currentQueue = queue;
        queue = [];
        while (++queueIndex < len) {
            if (currentQueue) {
                currentQueue[queueIndex].run();
            }
        }
        queueIndex = -1;
        len = queue.length;
    }
    currentQueue = null;
    draining = false;
    runClearTimeout(timeout);
}

process.nextTick = function (fun) {
    var args = new Array(arguments.length - 1);
    if (arguments.length > 1) {
        for (var i = 1; i < arguments.length; i++) {
            args[i - 1] = arguments[i];
        }
    }
    queue.push(new Item(fun, args));
    if (queue.length === 1 && !draining) {
        runTimeout(drainQueue);
    }
};

// v8 likes predictible objects
function Item(fun, array) {
    this.fun = fun;
    this.array = array;
}
Item.prototype.run = function () {
    this.fun.apply(null, this.array);
};
process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];
process.version = ''; // empty string to avoid regexp issues
process.versions = {};

function noop() {}

process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;
process.prependListener = noop;
process.prependOnceListener = noop;

process.listeners = function (name) { return [] }

process.binding = function (name) {
    throw new Error('process.binding is not supported');
};

process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};
process.umask = function() { return 0; };

},{}]},{},[1])(1)
});
