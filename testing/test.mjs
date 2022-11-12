import * as secUtl from "../output/index.js"
import { performance } from "perf_hooks"

const results = {}

const testString = "testorritestorritestorri - asdaf 456789 äö90ß´ä-`''°^"

const count = 1000

//############################################################
async function testShas() {
    try {
        var sha256Hex = await secUtl.sha256Hex(testString)
        var sha256Bytes = await secUtl.sha256Bytes(testString)    
        
        var sha512Hex = await secUtl.sha512Hex(testString)
        var sha512Bytes = await secUtl.sha512Bytes(testString)    

        var isMatch256 = sha256Hex == Buffer.from(sha256Bytes).toString("hex")
        var isMatch512 = sha512Hex == Buffer.from(sha512Bytes).toString("hex")
    
        if(isMatch256 && isMatch512) {

            let success = true
            let sha256HexMS = 0
            let sha256BytesMS = 0
            let sha512HexMS = 0
            let sha512BytesMS = 0
            let before = 0
            let after = 0
            let c = 0
            

            c = count
            before = performance.now()
            while(c--) {
                sha512Hex = await secUtl.sha512Hex(testString)
            }
            after = performance.now()
            sha512HexMS = after - before

            c = count
            before = performance.now()
            while(c--) {
                sha512Bytes = await secUtl.sha512Bytes(testString)
            }
            after = performance.now()
            sha512BytesMS = after - before


            c = count
            before = performance.now()
            while(c--) {
                sha256Hex = await secUtl.sha256Hex(testString)
            }
            after = performance.now()
            sha256HexMS = after - before

            c = count
            before = performance.now()
            while(c--) {
                sha256Bytes = await secUtl.sha256Bytes(testString)
            }
            after = performance.now()
            sha256BytesMS = after - before            


            results.testShas = { success, sha256HexMS, sha256BytesMS, sha512HexMS, sha512BytesMS }
    
        } else {
            results.testShas="Error! Hex did not match the bytes version."
        }
    
    } catch(error) {
        results.testShas=error.message
    }
}

async function testPublicKey() {
    try {
        var keyPairHex = await secUtl.createKeyPairHex()
        var keyPairBytes = await secUtl.createKeyPairBytes()
        // console.log(JSON.stringify(keyPairHex, null, 4))
        // console.log(JSON.stringify(keyPairBytes, null, 4))
        var pubHex = await secUtl.createPublicKeyHex(keyPairHex.secretKeyHex)
        var pubBytes = await secUtl.createPublicKeyBytes(keyPairBytes.secretKeyBytes)

        var isMatchHex = keyPairHex.publicKeyHex == pubHex
        var isMatchBytes = JSON.stringify(keyPairBytes.publicKeyBytes) == JSON.stringify(pubBytes)
    
        if(isMatchHex && isMatchBytes) {

            let success = true
            let hexMS = 0
            let bytesMS = 0
            let before = 0
            let after = 0
            let c = 0
            

            c = count
            before = performance.now()
            while(c--) {
                pubHex = await secUtl.createPublicKeyHex(keyPairHex.secretKeyHex)
            }
            after = performance.now()
            hexMS = after - before

            c = count
            before = performance.now()
            while(c--) {
                pubBytes = await secUtl.createPublicKeyBytes(keyPairBytes.secretKeyBytes)
            }
            after = performance.now()
            bytesMS = after - before            

            results.testPublicKey = { success, bytesMS, hexMS }
    
        } else {
            results.testPublicKey="Error! New generated PublicKey did not match autogenerated."
        }
    
    } catch(error) {
        results.testPublicKey=error.message
    }
}

//############################################################
async function testSignatures() {

    try {
        var { secretKeyBytes, publicKeyBytes } = await secUtl.createKeyPairBytes()
        var { secretKeyHex, publicKeyHex } = await secUtl.createKeyPairHex()

        var signatureBytes = await secUtl.createSignatureBytes(testString, secretKeyBytes)
        var verifiedBytes = await secUtl.verify(signatureBytes, publicKeyBytes, testString)

        var signatureHex = await secUtl.createSignatureHex(testString, secretKeyHex)
        var verifiedHex = await secUtl.verify(signatureHex, publicKeyHex, testString)

        if(verifiedBytes && verifiedHex) {
            let success = true
            let hexMS = 0
            let bytesMS = 0
            let before = 0
            let after = 0
            let c = 0


            c = count
            before = performance.now()
            while(c--) {
                signatureHex = await secUtl.createSignatureHex(testString, secretKeyHex)
                verifiedHex = await secUtl.verify(signatureHex, publicKeyHex, testString)
            }
            after = performance.now()
            hexMS = after - before


            c = count
            before = performance.now()
            while(c--) {
                signatureBytes = await secUtl.createSignatureBytes(testString, secretKeyBytes)
                verifiedBytes = await secUtl.verify(signatureBytes, publicKeyBytes, testString)
            }
            after = performance.now()
            bytesMS = after - before


            results.testSignatures= {success, hexMS, bytesMS}

        } else {
            let error =  "Error: Signature not verified"
            results.testSignatures = {error, verifiedBytes, verifiedHex}
        }

    } catch(error) {
        results.testSignatures=error.message
    }

}

//############################################################
async function testSymmetricEncryption() {

    try {
        var keyHex = await secUtl.createSymKeyHex()
    
        var gibbrishHex = await secUtl.symmetricEncryptHex(testString, keyHex)    
        var decrypted = await secUtl.symmetricDecrypt(gibbrishHex, keyHex)
        
        var hexMatched = decrypted == testString

        var keyBytes = await secUtl.createSymKeyBytes()
        var gibbrishBytes = await secUtl.symmetricEncryptBytes(testString, keyBytes)    
        decrypted = await secUtl.symmetricDecryptBytes(gibbrishBytes, keyBytes)

        var bytesMatched = decrypted == testString

        if(hexMatched && bytesMatched){
            let success = true
            let before
            let after
            let hexMS
            let bytesMS
            let c

            c = count
            before = performance.now()
            while(c--) {
                gibbrishHex = await secUtl.symmetricEncryptHex(testString, keyHex)
                decrypted = await secUtl.symmetricDecrypt(gibbrishHex, keyHex)
            }
            after = performance.now()
            hexMS = after - before

            c = count
            before = performance.now()
            while(c--) {
                gibbrishBytes = await secUtl.symmetricEncryptBytes(testString, keyBytes)    
                decrypted = await secUtl.symmetricDecryptBytes(gibbrishBytes, keyBytes)
                    }
            after = performance.now()
            bytesMS = after - before


            results.testSymmetricEncryption = {success, hexMS, bytesMS}
        } else {
            results.testSymmetricEncryption = "Error: Decrypted did not match original content!"
        }
    } catch(error) {
        results.testSymmetricEncryption = error.message
    }


}

//############################################################
async function testAsymmetricEncryption() {

    try {
        var { secretKeyHex, publicKeyHex } = await secUtl.createKeyPairHex()
        var { secretKeyBytes, publicKeyBytes } = await secUtl.createKeyPairBytes()
        
        var secretsObject = await secUtl.asymmetricEncryptHex(testString, publicKeyHex)
        var decrypted = await secUtl.asymmetricDecryptHex(secretsObject, secretKeyHex)
        var hexMatched = decrypted == testString

        secretsObject = await secUtl.asymmetricEncryptBytes(testString, publicKeyBytes)
        decrypted = await secUtl.asymmetricDecryptBytes(secretsObject, secretKeyBytes)
        var bytesMatched = decrypted == testString

        // secretsObject = await secUtl.asymmetricEncryptOld(testString, publicKeyHex)
        // decrypted = await secUtl.asymmetricDecryptHex(secretsObject, secretKeyHex)
        // console.log("hello 1! "+(decrypted == testString))
        // secretsObject = await secUtl.asymmetricEncryptHex(testString, publicKeyHex)
        // decrypted = await secUtl.asymmetricDecryptOld(secretsObject, secretKeyHex)
        // console.log("hello 2! "+(decrypted == testString))

        if(hexMatched && bytesMatched){
            let success = true
            let before
            let after
            let hexMS
            let bytesMS
            let c


            c = count
            before = performance.now()
            while(c--) {
                secretsObject = await secUtl.asymmetricEncryptHex(testString, publicKeyHex)
                decrypted = await secUtl.asymmetricDecryptHex(secretsObject, secretKeyHex)
            }
            after = performance.now()
            hexMS = after - before

            c = count
            before = performance.now()
            while(c--) {
                secretsObject = await secUtl.asymmetricEncryptBytes(testString, publicKeyBytes)
                decrypted = await secUtl.asymmetricDecryptBytes(secretsObject, secretKeyBytes)        
            }
            after = performance.now()
            bytesMS = after - before


            results.testAsymmetricEncryption = {success, hexMS, bytesMS}
        } else {
            var error = "Error: Decrypted did not match original content!"
            results.testAsymmetricEncryption = {error, hexMatched, bytesMatched} 
        }
    } catch(error) {
        results.testAsymmetricEncryption = error.message
    }

}

//############################################################
async function testCreateSharedSecretContexedHash512() {

    try {
        var kp = await secUtl.createKeyPairHex()
        var alicePriv = kp.secretKeyHex
        var alicePub = kp.publicKeyHex
        kp = await secUtl.createKeyPairHex()
        var bobPriv = kp.secretKeyHex
        var bobPub = kp.publicKeyHex
        
        var context = "test.extensivlyon.coffee/ultra-context"

        var sharedSecretAlice = await secUtl.createSharedSecretContexedHash512(alicePriv, bobPub, context)
        var sharedSecretBob = await secUtl.createSharedSecretContexedHash512(bobPriv, alicePub, context)
        
        if(sharedSecretAlice == sharedSecretBob) {
            let success = true
            let before
            let after
            let hexMS
            let bytesMS
            let c

            c = count
            before = performance.now()
            while(c--) {
                sharedSecretAlice = await secUtl.createSharedSecretContexedHash512(alicePriv, bobPub, context)
                sharedSecretBob = await secUtl.createSharedSecretContexedHash512(bobPriv, alicePub, context)
            }
            after = performance.now()
            hexMS = after - before

            bytesMS = 9001
            results.testCreateSharedSecretContexedHash512 = {success, hexMS, bytesMS}
        } else {
            var error = "Error: created shared secrets did not match!"
            results.testCreateSharedSecretContexedHash512 = {error, sharedSecretAlice, sharedSecretBob} 
        }
    } catch(error) {
        results.testCreateSharedSecretContexedHash512 = error.message
    }

}

//############################################################
async function testCreateSharedSecretHash512() {

    try {
        var kp = await secUtl.createKeyPairHex()
        var alicePriv = kp.secretKeyHex
        var alicePub = kp.publicKeyHex
        kp = await secUtl.createKeyPairHex()
        var bobPriv = kp.secretKeyHex
        var bobPub = kp.publicKeyHex
        

        var sharedSecretAlice = await secUtl.createSharedSecretHash512(alicePriv, bobPub)

        var sharedSecretBob = await secUtl.createSharedSecretHash512(bobPriv, alicePub)
        
        if(sharedSecretAlice == sharedSecretBob) {
            let success = true
            let before
            let after
            let hexMS
            let bytesMS
            let c

            c = count
            before = performance.now()
            while(c--) {
                sharedSecretAlice = await secUtl.createSharedSecretHash512(alicePriv, bobPub)
                sharedSecretBob = await secUtl.createSharedSecretHash512(bobPriv, alicePub)
            }
            after = performance.now()
            hexMS = after - before

            bytesMS = 9001
            results.createSharedSecretHash512 = {success, hexMS, bytesMS}
        } else {
            var error = "Error: shared secrets did not match!"
            results.createSharedSecretHash512 = {error, sharedSecretAlice, sharedSecretBob} 
        }
    } catch(error) {
        results.createSharedSecretHash512 = error.message
    }

}

//############################################################
async function testReferencedSharedSecretContexedHash512() {

    try {
        var kp = await secUtl.createKeyPairHex()
        var alicePriv = kp.secretKeyHex
        var alicePub = kp.publicKeyHex
        kp = await secUtl.createKeyPairHex()
        var bobPriv = kp.secretKeyHex
        var bobPub = kp.publicKeyHex
        
        var context = "test.extensivlyon.coffee/ultra-context"

        var referencedSharedSecret = await secUtl.referencedSharedSecretContexedHash512(bobPub, context)
        var referencePoint = referencedSharedSecret.referencePointHex
        var sharedSecretAlice = referencedSharedSecret.sharedSecretHex
    
        var sharedSecretBob = await secUtl.createSharedSecretContexedHash512(bobPriv, referencePoint, context)

        if(sharedSecretAlice == sharedSecretBob) {
            let success = true
            let before
            let after
            let hexMS
            let bytesMS
            let c

            c = count
            before = performance.now()
            while(c--) {
                referencedSharedSecret = await secUtl.referencedSharedSecretContexedHash512(bobPub, context)
                referencedSharedSecret = await secUtl.referencedSharedSecretContexedHash512(alicePub, context)
            }
            after = performance.now()
            hexMS = after - before

            bytesMS = 9001
            results.referencedSharedSecretContexedHash512 = {success, hexMS, bytesMS}
        } else {
            var error = "Error: referenced shared secret did not match!"
            results.referencedSharedSecretContexedHash512 = {error, sharedSecretAlice, sharedSecretBob} 
        }
    } catch(error) {
        results.referencedSharedSecretContexedHash512 = error.message
    }

}

//############################################################
async function testReferencedSharedSecretHash512() {

    try {
        var kp = await secUtl.createKeyPairHex()
        var alicePriv = kp.secretKeyHex
        var alicePub = kp.publicKeyHex
        kp = await secUtl.createKeyPairHex()
        var bobPriv = kp.secretKeyHex
        var bobPub = kp.publicKeyHex
        
        var referencedSharedSecret = await secUtl.referencedSharedSecretHash512(bobPub)
        var referencePoint = referencedSharedSecret.referencePointHex
        var sharedSecretAlice = referencedSharedSecret.sharedSecretHex
    
        var sharedSecretBob = await secUtl.createSharedSecretHash512(bobPriv, referencePoint)

        if(sharedSecretAlice == sharedSecretBob) {
            let success = true
            let before
            let after
            let hexMS
            let bytesMS
            let c

            c = count
            before = performance.now()
            while(c--) {
                referencedSharedSecret = await secUtl.referencedSharedSecretHash512(bobPub)
                referencePoint = referencedSharedSecret.referencePointHex
                sharedSecretBob = await secUtl.createSharedSecretHash512(bobPriv, referencePoint)
            }
            after = performance.now()
            hexMS = after - before

            bytesMS = 9001
            results.referencedSharedSecretHash512 = {success, hexMS, bytesMS}
        } else {
            var error = "Error: referenced shared secret did not match!"
            results.referencedSharedSecretHash512 = {error, sharedSecretAlice, sharedSecretBob} 
        }
    } catch(error) {
        results.referencedSharedSecretHash512 = error.message
    }

}

//############################################################
async function testCreateSharedSecretContexedHash256() {

    try {
        var kp = await secUtl.createKeyPairHex()
        var alicePriv = kp.secretKeyHex
        var alicePub = kp.publicKeyHex
        kp = await secUtl.createKeyPairHex()
        var bobPriv = kp.secretKeyHex
        var bobPub = kp.publicKeyHex
        
        var context = "test.extensivlyon.coffee/ultra-context"

        var sharedSecretAlice = await secUtl.createSharedSecretContexedHash256(alicePriv, bobPub, context)
        var sharedSecretBob = await secUtl.createSharedSecretContexedHash256(bobPriv, alicePub, context)
        
        if(sharedSecretAlice == sharedSecretBob) {
            let success = true
            let before
            let after
            let hexMS
            let bytesMS
            let c

            c = count
            before = performance.now()
            while(c--) {
                sharedSecretAlice = await secUtl.createSharedSecretContexedHash256(alicePriv, bobPub, context)
                sharedSecretBob = await secUtl.createSharedSecretContexedHash256(bobPriv, alicePub, context)
            }
            after = performance.now()
            hexMS = after - before

            bytesMS = 9001
            results.testCreateSharedSecretContexedHash256 = {success, hexMS, bytesMS}
        } else {
            var error = "Error: created shared secrets did not match!"
            results.testCreateSharedSecretContexedHash256 = {error, sharedSecretAlice, sharedSecretBob} 
        }
    } catch(error) {
        results.testCreateSharedSecretContexedHash256 = error.message
    }

}

//############################################################
async function testCreateSharedSecretHash256() {

    try {
        var kp = await secUtl.createKeyPairHex()
        var alicePriv = kp.secretKeyHex
        var alicePub = kp.publicKeyHex
        kp = await secUtl.createKeyPairHex()
        var bobPriv = kp.secretKeyHex
        var bobPub = kp.publicKeyHex
        

        var sharedSecretAlice = await secUtl.createSharedSecretHash256(alicePriv, bobPub)

        var sharedSecretBob = await secUtl.createSharedSecretHash256(bobPriv, alicePub)
        
        if(sharedSecretAlice == sharedSecretBob) {
            let success = true
            let before
            let after
            let hexMS
            let bytesMS
            let c

            c = count
            before = performance.now()
            while(c--) {
                sharedSecretAlice = await secUtl.createSharedSecretHash256(alicePriv, bobPub)
                sharedSecretBob = await secUtl.createSharedSecretHash256(bobPriv, alicePub)
            }
            after = performance.now()
            hexMS = after - before

            bytesMS = 9001
            results.createSharedSecretHash256 = {success, hexMS, bytesMS}
        } else {
            var error = "Error: shared secrets did not match!"
            results.createSharedSecretHash256 = {error, sharedSecretAlice, sharedSecretBob} 
        }
    } catch(error) {
        results.createSharedSecretHash256 = error.message
    }

}

//############################################################
async function testCreateSharedSecretRaw() {

    try {
        var kp = await secUtl.createKeyPairHex()
        var alicePriv = kp.secretKeyHex
        var alicePub = kp.publicKeyHex
        kp = await secUtl.createKeyPairHex()
        var bobPriv = kp.secretKeyHex
        var bobPub = kp.publicKeyHex
        

        var sharedSecretAlice = await secUtl.createSharedSecretRaw(alicePriv, bobPub)

        var sharedSecretBob = await secUtl.createSharedSecretRaw(bobPriv, alicePub)
        
        if(sharedSecretAlice == sharedSecretBob) {
            let success = true
            let before
            let after
            let hexMS
            let bytesMS
            let c

            c = count
            before = performance.now()
            while(c--) {
                sharedSecretAlice = await secUtl.createSharedSecretRaw(alicePriv, bobPub)
                sharedSecretBob = await secUtl.createSharedSecretRaw(bobPriv, alicePub)
            }
            after = performance.now()
            hexMS = after - before

            bytesMS = 9001
            results.createSharedSecretRaw = {success, hexMS, bytesMS}
        } else {
            var error = "Error: shared secrets did not match!"
            results.createSharedSecretRaw = {error, sharedSecretAlice, sharedSecretBob} 
        }
    } catch(error) {
        results.createSharedSecretRaw = error.message
    }

}

//############################################################
async function testReferencedSharedSecretContexedHash256() {

    try {
        var kp = await secUtl.createKeyPairHex()
        var alicePriv = kp.secretKeyHex
        var alicePub = kp.publicKeyHex
        kp = await secUtl.createKeyPairHex()
        var bobPriv = kp.secretKeyHex
        var bobPub = kp.publicKeyHex
        
        var context = "test.extensivlyon.coffee/ultra-context"

        var referencedSharedSecret = await secUtl.referencedSharedSecretContexedHash256(bobPub, context)
        var referencePoint = referencedSharedSecret.referencePointHex
        var sharedSecretAlice = referencedSharedSecret.sharedSecretHex
    
        var sharedSecretBob = await secUtl.createSharedSecretContexedHash256(bobPriv, referencePoint, context)

        if(sharedSecretAlice == sharedSecretBob) {
            let success = true
            let before
            let after
            let hexMS
            let bytesMS
            let c

            c = count
            before = performance.now()
            while(c--) {
                referencedSharedSecret = await secUtl.referencedSharedSecretContexedHash256(bobPub, context)
                referencedSharedSecret = await secUtl.referencedSharedSecretContexedHash256(alicePub, context)
            }
            after = performance.now()
            hexMS = after - before

            bytesMS = 9001
            results.referencedSharedSecretContexedHash256 = {success, hexMS, bytesMS}
        } else {
            var error = "Error: referenced shared secret did not match!"
            results.referencedSharedSecretContexedHash256 = {error, sharedSecretAlice, sharedSecretBob} 
        }
    } catch(error) {
        results.referencedSharedSecretContexedHash256 = error.message
    }

}

//############################################################
async function testReferencedSharedSecretHash256() {

    try {
        var kp = await secUtl.createKeyPairHex()
        var alicePriv = kp.secretKeyHex
        var alicePub = kp.publicKeyHex
        kp = await secUtl.createKeyPairHex()
        var bobPriv = kp.secretKeyHex
        var bobPub = kp.publicKeyHex
        
        var referencedSharedSecret = await secUtl.referencedSharedSecretHash256(bobPub)
        var referencePoint = referencedSharedSecret.referencePointHex
        var sharedSecretAlice = referencedSharedSecret.sharedSecretHex
    
        var sharedSecretBob = await secUtl.createSharedSecretHash256(bobPriv, referencePoint)

        if(sharedSecretAlice == sharedSecretBob) {
            let success = true
            let before
            let after
            let hexMS
            let bytesMS
            let c

            c = count
            before = performance.now()
            while(c--) {
                referencedSharedSecret = await secUtl.referencedSharedSecretHash256(bobPub)
                referencePoint = referencedSharedSecret.referencePointHex
                sharedSecretBob = await secUtl.createSharedSecretHash256(bobPriv, referencePoint)
            }
            after = performance.now()
            hexMS = after - before

            bytesMS = 9001
            results.referencedSharedSecretHash256 = {success, hexMS, bytesMS}
        } else {
            var error = "Error: referenced shared secret did not match!"
            results.referencedSharedSecretHash256 = {error, sharedSecretAlice, sharedSecretBob} 
        }
    } catch(error) {
        results.referencedSharedSecretHash256 = error.message
    }

}

//############################################################
async function testReferencedSharedSecretRaw() {

    try {
        var kp = await secUtl.createKeyPairHex()
        var alicePriv = kp.secretKeyHex
        var alicePub = kp.publicKeyHex
        kp = await secUtl.createKeyPairHex()
        var bobPriv = kp.secretKeyHex
        var bobPub = kp.publicKeyHex
        
        var referencedSharedSecret = await secUtl.referencedSharedSecretRaw(bobPub)
        var referencePoint = referencedSharedSecret.referencePointHex
        var sharedSecretAlice = referencedSharedSecret.sharedSecretHex
    
        var sharedSecretBob = await secUtl.createSharedSecretRaw(bobPriv, referencePoint)

        if(sharedSecretAlice == sharedSecretBob) {
            let success = true
            let before
            let after
            let hexMS
            let bytesMS
            let c

            c = count
            before = performance.now()
            while(c--) {
                referencedSharedSecret = await secUtl.referencedSharedSecretRaw(bobPub)
                referencePoint = referencedSharedSecret.referencePointHex
                sharedSecretBob = await secUtl.createSharedSecretRaw(bobPriv, referencePoint)
            }
            after = performance.now()
            hexMS = after - before

            bytesMS = 9001
            results.referencedSharedSecretRaw = {success, hexMS, bytesMS}
        } else {
            var error = "Error: referenced shared secret did not match!"
            results.referencedSharedSecretRaw = {error, sharedSecretAlice, sharedSecretBob} 
        }
    } catch(error) {
        results.referencedSharedSecretRaw = error.message
    }

}

//############################################################
async function testSalts() {

    try {
        var salt = await secUtl.createRandomLengthSalt()
        var saltedContent = salt+testString
        var content = await secUtl.removeSalt(saltedContent)
        if(content == testString) {
            results.testSalts="success"
        } else {
            results.testSalts="Error: original: "+testString+" doesn't match unsalted: "+content
        }

    } catch(error) {
        results.testSalts=error.message
    }

}

//############################################################
async function runAllTest() {

    await testShas()
    // await testPublicKey()
    // await testSignatures()
    await testSymmetricEncryption()
    await testAsymmetricEncryption()
    
    // await testCreateSharedSecretContexedHash512()
    // await testCreateSharedSecretContexedHash256()
    await testCreateSharedSecretHash512()
    await testCreateSharedSecretHash256()
    await testCreateSharedSecretRaw()

    // await testReferencedSharedSecretContexedHash512()
    // await testReferencedSharedSecretContexedHash256()
    await testReferencedSharedSecretHash512()
    await testReferencedSharedSecretHash256()
    await testReferencedSharedSecretRaw()

    // await testSalts()

    evaluate()
}

function evaluate() {
    console.log(JSON.stringify(results, null, 4))
}

runAllTest()
