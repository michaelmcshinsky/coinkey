const assert = require('assert')
const cs = require('coinstring')
const ECKey = require('@hyperbitjs/eckey')
const inherits = require('inherits')
const secureRandom = require('secure-random')
const util = require('./util')

// Bitcoin
const DEFAULT_VERSIONS = {
  public: 0x0,
  private: 0x80
}

function CoinKey (privateKey, versions) {
  if (!(this instanceof CoinKey)) return new CoinKey(privateKey, versions)
  assert(util.isArrayish(privateKey), 'privateKey must be arrayish')
  this._versions = util.normalizeVersions(versions) || util.clone(DEFAULT_VERSIONS)
  // true => default compressed
  ECKey.call(this, privateKey, true)
}
inherits(CoinKey, ECKey)

// Instance props

Object.defineProperty(CoinKey.prototype, 'versions', {
  enumerable: true,
  configurable: true,
  get: function () {
    return this._versions
  },
  set: function (versions) {
    this._versions = versions
  }
})

Object.defineProperty(CoinKey.prototype, 'privateWif', {
  get: function () {
    return cs.encode(this.privateExportKey, this.versions.private)
  }
})

Object.defineProperty(CoinKey.prototype, 'publicAddress', {
  get: function () {
    const bufVersion = util.bufferizeVersion(this.versions.public)
    return cs.encode(this.pubKeyHash, bufVersion)
  }
})

CoinKey.prototype.toString = function () {
  return this.privateWif + ': ' + this.publicAddress
}

// Class methods

CoinKey.fromWif = function (wif, versions) {
  versions = util.normalizeVersions(versions)
  const res = cs.decode(wif)
  const version = res.slice(0, 1)
  let privateKey = res.slice(1) // get rid of version byte
  const compressed = (privateKey.length === 33)
  if (compressed) privateKey = privateKey.slice(0, 32) // slice off compression byte

  const v = versions || {}
  v.private = v.private || version.readUInt8(0)
  v.public = v.public || v.private - 0x80

  const ck = new CoinKey(privateKey, v)
  ck.compressed = compressed
  return ck
}

CoinKey.createRandom = function (versions) {
  const privateKey = secureRandom.randomBuffer(32)
  return new CoinKey(privateKey, versions)
}

CoinKey.addressToHash = function (address) {
  return cs.decode(address).slice(1)
}

module.exports = CoinKey
