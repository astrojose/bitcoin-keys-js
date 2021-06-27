const sha256 = require('sha256')
const base58 = require('bs58')
const EC = require('elliptic').ec
const ripemd160 = require('ripemd160')

let ec = new EC('secp256k1')

let privKey = sha256('secret')
console.log('> Private Key: ',privKey)


let doubleHash =  sha256.x2('80' + privKey)
let checksum = doubleHash.substring(0, 8);
let payload = Buffer.from('80'+privKey+checksum, 'hex')
let b58 = base58.encode(payload )

console.log("> Private Key WIF: ", b58)

// generate key pairs from curve
let kp = ec.keyFromPrivate(privKey);
// get public key point (x,y)
let pubPoint = kp.getPublic()

let pubKey = pubPoint.encode('hex')

console.log("> Uncompressed Public Key : ", pubKey)

let x = pubPoint.getX();
let y = pubPoint.getY();

let  pub = { x: x.toString('hex'), y: y.toString('hex') };

compressedPub = '03'+pub.x
console.log("> Compressed Public Key : ", compressedPub)

let addrHash = new ripemd160().update(sha256(pubKey)).digest('hex')
console.log("> Unencoded Bitcoin Address: ", addrHash)

// base58check encoding
let doubleHashAddr =  sha256.x2(Buffer.from('00' + addrHash, 'hex'))
let checksumAddr = doubleHashAddr.substring(0, 8);
let payloadAddr = Buffer.from('00'+addrHash+checksum, 'hex')
let encodedAddr = base58.encode(payloadAddr)

console.log("> Bitcoin Address: ", encodedAddr)
