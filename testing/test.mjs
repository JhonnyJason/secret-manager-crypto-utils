import * as secUtl from "../output/index.js"
import { performance } from "perf_hooks"
import constructionmodule from "thingymodulecreate/constructionmodule.js"

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

//############################################################
async function testPublicKey() {
    try {
        var keyPairHex = await secUtl.createKeyPairHex()
        // console.log(keyPairHex.publicKeyHex)

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
                if(!verifiedHex) {throw new Error("Error: Signature not verified! verifiedHex @count"+c)}
            }
            after = performance.now()
            hexMS = after - before


            c = count
            before = performance.now()
            while(c--) {
                signatureBytes = await secUtl.createSignatureBytes(testString, secretKeyBytes)
                verifiedBytes = await secUtl.verify(signatureBytes, publicKeyBytes, testString)
                if(!verifiedBytes) {throw new Error("Error: Signature not verified! verifiedBytes @count"+c)}
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
            let saltedContent
            let unsaltedContent
            let c

            c = count
            before = performance.now()
            while(c--) {
                gibbrishBytes = await secUtl.symmetricEncryptBytes(testString, keyBytes)    
                decrypted = await secUtl.symmetricDecryptBytes(gibbrishBytes, keyBytes)
                    }
            after = performance.now()
            bytesMS = after - before

            c = count
            before = performance.now()
            while(c--) {
                gibbrishHex = await secUtl.symmetricEncryptHex(testString, keyHex)
                decrypted = await secUtl.symmetricDecrypt(gibbrishHex, keyHex)
            }
            after = performance.now()
            hexMS = after - before

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
async function testSalts() {

    try {

        // var content = "aaaaa"
        var content = testString
        // console.log("content: "+content)
        var saltedContent = secUtl.saltContent(content)
        // console.log(JSON.stringify(saltedContent, null, 4))
        // console.log("saltedContent: "+saltedContent)
        var unsaltedContent = secUtl.unsaltContent(saltedContent)
        // console.log("unsaltedContent: "+unsaltedContent)
        
        if(content == unsaltedContent) {
            let success = true
            let before
            let after
            let saltMS
            let c


            c = count
            before = performance.now()
            while(c--) {
                saltedContent = secUtl.saltContent(content)
                unsaltedContent = secUtl.unsaltContent(saltedContent)
                if(content != unsaltedContent) {
                    console.log(JSON.stringify(Uint8Array.from(saltedContent)))
                    console.log("unsaltedContent: "+unsaltedContent)
                    throw new Error("Error on NewSalt: Unsalted content did not match original content!")
                }
            }
            after = performance.now()
            saltMS = after - before

            results.testSalts = {success, saltMS}
        } else {
            var error = "Error: Unsalted content did not match original content!"
            unsaltedContent = Uint8Array.from(unsaltedContent)
            results.testSalts = {error, content, unsaltedContent} 
        }

        // var salt = await secUtl.createRandomLengthSalt()
        // var saltedContent = salt+testString
        // var content = await secUtl.removeSalt(saltedContent)
        // if(content == testString) {
        //     results.testSalts="success"
        // } else {
        //     results.testSalts="Error: original: "+testString+" doesn't match unsalted: "+content
        // }



    } catch(error) {
        results.testSalts=error.message
    }

}


//############################################################
async function testCreateSharedSecretHash() {

    try {
        var kpBytes = await secUtl.createKeyPairBytes()
        var alicePrivBytes = kpBytes.secretKeyBytes
        var alicePubBytes = kpBytes.publicKeyBytes
        kpBytes = await secUtl.createKeyPairBytes()
        var bobPrivBytes = kpBytes.secretKeyBytes
        var bobPubBytes = kpBytes.publicKeyBytes

        var alicePrivHex = Buffer.from(alicePrivBytes).toString("hex")
        var alicePubHex = Buffer.from(alicePubBytes).toString("hex")
        var bobPrivHex = Buffer.from(bobPrivBytes).toString("hex")
        var bobPubHex = Buffer.from(bobPubBytes).toString("hex")

        var context = "test.extensivlyon.coffee/ultra-context"

        var sharedSecretAliceHex = await secUtl.createSharedSecretHashHex(alicePrivHex, bobPubHex, context)
        var sharedSecretBobHex = await secUtl.createSharedSecretHashHex(bobPrivHex, alicePubHex, context)
        if(sharedSecretAliceHex != sharedSecretBobHex) { throw new Error(`Hex Shared Secrets did not match!\n sharedSecretAliceHex: ${sharedSecretAliceHex}\nsharedSecretBobHex: ${sharedSecretBobHex}`)}


        var sharedSecretAliceBytes = await secUtl.createSharedSecretHashBytes(alicePrivBytes, bobPubBytes, context)
        var sharedSecretBobBytes = await secUtl.createSharedSecretHashBytes(bobPrivBytes, alicePubBytes, context)
        if(sharedSecretAliceBytes.toString("hex") != sharedSecretBobBytes.toString("hex")) { throw new Error(`Bytes Shared Secrets did not match!\n sharedSecretAliceBytes: ${sharedSecretAliceBytes}\nsharedSecretBobBytes: ${sharedSecretBobBytes}`)}
        
        
        var compHex = sharedSecretBobBytes.toString("hex")
        if(sharedSecretAliceHex != compHex){ throw new Error(`Hex version of Bytes Secret did not match the original Hex version!\ncompHex: ${compHex}\nsharedSecretAliceHex: ${sharedSecretAliceHex}`)}

        let success = true
        let before
        let after
        let hexMS
        let bytesMS
        let c

        c = count
        before = performance.now()
        while(c--) {
            sharedSecretAliceHex = await secUtl.createSharedSecretHashHex(alicePrivHex, bobPubHex, context)
            sharedSecretBobHex = await secUtl.createSharedSecretHashHex(bobPrivHex, alicePubHex, context)
        }
        after = performance.now()
        hexMS = after - before

        c = count
        before = performance.now()
        while(c--) {
            sharedSecretAliceBytes = await secUtl.createSharedSecretHashBytes(alicePrivBytes, bobPubBytes, context)
            sharedSecretBobBytes = await secUtl.createSharedSecretHashBytes(bobPrivBytes, alicePubBytes, context)
        }
        after = performance.now()
        bytesMS = after - before
        results.createSharedSecretHash = {success, hexMS, bytesMS}

    } catch(error) {
        results.createSharedSecretHash = error.message
    }

}

//############################################################
async function testCreateSharedSecretRaw() {

    try {
        var kpBytes = await secUtl.createKeyPairBytes()
        var alicePrivBytes = kpBytes.secretKeyBytes
        var alicePubBytes = kpBytes.publicKeyBytes
        kpBytes = await secUtl.createKeyPairBytes()
        var bobPrivBytes = kpBytes.secretKeyBytes
        var bobPubBytes = kpBytes.publicKeyBytes

        var alicePrivHex = Buffer.from(alicePrivBytes).toString("hex")
        var alicePubHex = Buffer.from(alicePubBytes).toString("hex")
        var bobPrivHex = Buffer.from(bobPrivBytes).toString("hex")
        var bobPubHex = Buffer.from(bobPubBytes).toString("hex")

        var sharedSecretAliceHex = await secUtl.createSharedSecretRawHex(alicePrivHex, bobPubHex)
        var sharedSecretBobHex = await secUtl.createSharedSecretRawHex(bobPrivHex, alicePubHex)
        if(sharedSecretAliceHex != sharedSecretBobHex) { throw new Error(`Hex Shared Secrets did not match!\n sharedSecretAliceHex: ${sharedSecretAliceHex}\nsharedSecretBobHex: ${sharedSecretBobHex}`)}


        var sharedSecretAliceBytes = await secUtl.createSharedSecretRawBytes(alicePrivBytes, bobPubBytes)
        var sharedSecretBobBytes = await secUtl.createSharedSecretRawBytes(bobPrivBytes, alicePubBytes)
        if(sharedSecretAliceBytes.toString("hex") != sharedSecretBobBytes.toString("hex")) { throw new Error(`Bytes Shared Secrets did not match!\n sharedSecretAliceBytes: ${sharedSecretAliceBytes}\nsharedSecretBobBytes: ${sharedSecretBobBytes}`)}
        
        
        var compHex = Buffer.from(sharedSecretBobBytes).toString("hex")
        if(sharedSecretAliceHex != compHex){ throw new Error(`Hex version of Bytes Secret did not match the original Hex version!\ncompHex: ${compHex}\nsharedSecretAliceHex: ${sharedSecretAliceHex}`)}

        let success = true
        let before
        let after
        let hexMS
        let bytesMS
        let c

        c = count
        before = performance.now()
        while(c--) {
            sharedSecretAliceHex = await secUtl.createSharedSecretRawHex(alicePrivHex, bobPubHex)
            sharedSecretBobHex = await secUtl.createSharedSecretRawHex(bobPrivHex, alicePubHex)
        }
        after = performance.now()
        hexMS = after - before

        c = count
        before = performance.now()
        while(c--) {
            sharedSecretAliceBytes = await secUtl.createSharedSecretRawBytes(alicePrivBytes, bobPubBytes)
            sharedSecretBobBytes = await secUtl.createSharedSecretRawBytes(bobPrivBytes, alicePubBytes)
        }
        after = performance.now()
        bytesMS = after - before
        results.createSharedSecretRaw = {success, hexMS, bytesMS}

    } catch(error) {
        results.createSharedSecretRaw = error.message
    }

}

//############################################################
async function testReferencedSharedSecretHash() {

    try {
        var kpBytes = await secUtl.createKeyPairBytes()
        var alicePrivBytes = kpBytes.secretKeyBytes
        var alicePubBytes = kpBytes.publicKeyBytes
        kpBytes = await secUtl.createKeyPairBytes()
        var bobPrivBytes = kpBytes.secretKeyBytes
        var bobPubBytes = kpBytes.publicKeyBytes

        var alicePrivHex = Buffer.from(alicePrivBytes).toString("hex")
        var alicePubHex = Buffer.from(alicePubBytes).toString("hex")
        var bobPrivHex = Buffer.from(bobPrivBytes).toString("hex")
        var bobPubHex = Buffer.from(bobPubBytes).toString("hex")

        var context = "test.extensivlyon.coffee/ultra-context"

        var referencedHex = await secUtl.referencedSharedSecretHashHex(bobPubHex, context)
        var referencePointHex = referencedHex.referencePointHex
        var sharedSecretAliceHex = referencedHex.sharedSecretHex

        var sharedSecretBobHex = await secUtl.createSharedSecretHashHex(bobPrivHex, referencePointHex, context)
        if(sharedSecretAliceHex != sharedSecretBobHex) { throw new Error(`Hex Shared Secrets did not match!\n sharedSecretAliceHex: ${sharedSecretAliceHex}\nsharedSecretBobHex: ${sharedSecretBobHex}`)}


        var referencedBytes = await secUtl.referencedSharedSecretHashBytes(bobPubBytes, context)
        var referencePointBytes = referencedBytes.referencePointBytes
        var sharedSecretAliceBytes = referencedBytes.sharedSecretBytes

        var sharedSecretBobBytes = await secUtl.createSharedSecretHashBytes(bobPrivBytes, referencePointBytes, context)
        if(Buffer.from(sharedSecretAliceBytes).toString("hex") != Buffer.from(sharedSecretBobBytes).toString("hex")) { throw new Error(`Bytes Shared Secrets did not match!\n sharedSecretAliceBytes: ${sharedSecretAliceBytes}\nsharedSecretBobBytes: ${sharedSecretBobBytes}`)}
        
        
        let success = true
        let before
        let after
        let hexMS
        let bytesMS
        let c

        c = count
        before = performance.now()
        while(c--) {
            sharedSecretAliceHex = await secUtl.referencedSharedSecretHashHex(bobPubHex, context)
            sharedSecretBobHex = await secUtl.referencedSharedSecretHashHex(alicePubHex, context)
        }
        after = performance.now()
        hexMS = after - before

        c = count
        before = performance.now()
        while(c--) {
            sharedSecretAliceBytes = await secUtl.referencedSharedSecretHashBytes(bobPubBytes, context)
            sharedSecretBobBytes = await secUtl.referencedSharedSecretHashBytes(alicePubBytes, context)
        }
        after = performance.now()
        bytesMS = after - before
        results.referencedSharedSecretHash = {success, hexMS, bytesMS}

    } catch(error) {
        results.referencedSharedSecretHash = error.message
    }

}

//############################################################
async function testReferencedSharedSecretRaw() {

    try {
        var kpBytes = await secUtl.createKeyPairBytes()
        var alicePrivBytes = kpBytes.secretKeyBytes
        var alicePubBytes = kpBytes.publicKeyBytes
        kpBytes = await secUtl.createKeyPairBytes()
        var bobPrivBytes = kpBytes.secretKeyBytes
        var bobPubBytes = kpBytes.publicKeyBytes

        var alicePrivHex = Buffer.from(alicePrivBytes).toString("hex")
        var alicePubHex = Buffer.from(alicePubBytes).toString("hex")
        var bobPrivHex = Buffer.from(bobPrivBytes).toString("hex")
        var bobPubHex = Buffer.from(bobPubBytes).toString("hex")

        var context = "test.extensivlyon.coffee/ultra-context"

        var referencedHex = await secUtl.referencedSharedSecretRawHex(bobPubHex, context)
        var referencePointHex = referencedHex.referencePointHex
        var sharedSecretAliceHex = referencedHex.sharedSecretHex

        var sharedSecretBobHex = await secUtl.createSharedSecretRawHex(bobPrivHex, referencePointHex, context)
        if(sharedSecretAliceHex != sharedSecretBobHex) { throw new Error(`Hex Shared Secrets did not match!\n sharedSecretAliceHex: ${sharedSecretAliceHex}\nsharedSecretBobHex: ${sharedSecretBobHex}`)}


        var referencedBytes = await secUtl.referencedSharedSecretRawBytes(bobPubBytes, context)
        var referencePointBytes = referencedBytes.referencePointBytes
        var sharedSecretAliceBytes = referencedBytes.sharedSecretBytes

        var sharedSecretBobBytes = await secUtl.createSharedSecretRawBytes(bobPrivBytes, referencePointBytes, context)
        if(Buffer.from(sharedSecretAliceBytes).toString("hex") != Buffer.from(sharedSecretBobBytes).toString("hex")) { throw new Error(`Bytes Shared Secrets did not match!\n sharedSecretAliceBytes: ${sharedSecretAliceBytes}\nsharedSecretBobBytes: ${sharedSecretBobBytes}`)}
        
        
        let success = true
        let before
        let after
        let hexMS
        let bytesMS
        let c

        c = count
        before = performance.now()
        while(c--) {
            sharedSecretAliceHex = await secUtl.referencedSharedSecretRawHex(bobPubHex, context)
            sharedSecretBobHex = await secUtl.referencedSharedSecretRawHex(alicePubHex, context)
        }
        after = performance.now()
        hexMS = after - before

        c = count
        before = performance.now()
        while(c--) {
            sharedSecretAliceBytes = await secUtl.referencedSharedSecretRawBytes(bobPubBytes, context)
            sharedSecretBobBytes = await secUtl.referencedSharedSecretRawBytes(alicePubBytes, context)
        }
        after = performance.now()
        bytesMS = after - before
        results.referencedSharedSecretRaw = {success, hexMS, bytesMS}

    } catch(error) {
        results.referencedSharedSecretRaw = error.message
    }
}


//############################################################
async function runAllTest() {
    await testShas() // get rid fresh start performance regression

    // real tests
    await testShas() // seem to work ;)
    await testPublicKey() // seem to work ;)
    await testSignatures() // seem to work ;)
    await testSymmetricEncryption() // seem to work ;)
    await testAsymmetricEncryption()    

    // await testCreateSharedSecretHash()
    // await testCreateSharedSecretRaw()
    // await testReferencedSharedSecretHash()
    // await testReferencedSharedSecretRaw()

    // await testSalts()

    evaluate()

}

function evaluate() {
    console.log(JSON.stringify(results, null, 4))
}

runAllTest()
