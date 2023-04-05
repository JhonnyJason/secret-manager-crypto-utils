import * as secUtl from "../output/index.js"
import { performance } from "perf_hooks"
import constructionmodule from "thingymodulecreate/constructionmodule.js"
import * as secUtlOld from "old-secret-manager-crypto-utils"
import * as secUtlOlder from "older-secret-manager-crypto-utils"

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
            let oldHexMS = 0
            let before = 0
            let after = 0
            let c = 0


            c = count
            before = performance.now()
            while(c--) {
                signatureHex = await secUtl.createSignatureHex(testString, secretKeyHex)
                verifiedHex = await secUtl.verify(signatureHex, publicKeyHex, testString)
                if(!verifiedHex) {throw new Error("Error: Signature not verified! hes version @count"+c)}
            }
            after = performance.now()
            hexMS = after - before


            c = count
            before = performance.now()
            while(c--) {
                signatureBytes = await secUtl.createSignatureBytes(testString, secretKeyBytes)
                verifiedBytes = await secUtl.verify(signatureBytes, publicKeyBytes, testString)
                if(!verifiedBytes) {throw new Error("Error: Signature not verified! bytes version @count"+c)}
            }
            after = performance.now()
            bytesMS = after - before

            c = count
            before = performance.now()
            while(c--) {
                signatureBytes = await secUtlOld.createSignatureBytes(testString, secretKeyBytes)
                verifiedBytes = await secUtlOld.verify(signatureBytes, publicKeyBytes, testString)
                if(!verifiedBytes) {throw new Error("Error: Signature not verified! oldHex version @count"+c)}
            }
            after = performance.now()
            oldHexMS = after - before


            results.testSignatures= {success, hexMS, bytesMS, oldHexMS}

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
            let unsaltedMS
            let oldHexMS
            let c

            c = count
            before = performance.now()
            while(c--) {
                gibbrishBytes = await secUtl.symmetricEncryptBytes(testString, keyBytes)    
                decrypted = await secUtl.symmetricDecryptBytes(gibbrishBytes, keyBytes)
                if(decrypted != testString) {throw new Error("Error: Decrypted did not match original content! bytes version @count"+c)}
            }
            after = performance.now()
            bytesMS = after - before

            c = count
            before = performance.now()
            while(c--) {
                gibbrishHex = await secUtl.symmetricEncryptHex(testString, keyHex)
                decrypted = await secUtl.symmetricDecrypt(gibbrishHex, keyHex)
                if(decrypted != testString) {throw new Error("Error: Decrypted did not match original content! hex version @count"+c)}
            }
            after = performance.now()
            hexMS = after - before

            c = count
            before = performance.now()
            while(c--) {
                gibbrishHex = await secUtl.symmetricEncryptUnsalted(testString, keyHex)
                decrypted = await secUtl.symmetricDecryptUnsalted(gibbrishHex, keyHex)
                if(decrypted != testString) {throw new Error("Error: Decrypted did not match original content! unsalted Version @count"+c)}
            }
            after = performance.now()
            unsaltedMS = after - before

            c = count
            before = performance.now()
            while(c--) {
                gibbrishHex = await secUtlOld.symmetricEncrypt(testString, keyHex)
                decrypted = await secUtlOld.symmetricDecrypt(gibbrishHex, keyHex)
                if(decrypted != testString) {throw new Error("Error: Decrypted did not match original content! oldHex Version @count"+c)}
            }
            after = performance.now()
            oldHexMS = after - before


            results.testSymmetricEncryption = {success, hexMS, bytesMS, unsaltedMS, oldHexMS}
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
            let oldHexMS
            let olderHexMS
            let c


            c = count
            before = performance.now()
            while(c--) {
                secretsObject = await secUtl.asymmetricEncryptHex(testString, publicKeyHex)
                decrypted = await secUtl.asymmetricDecryptHex(secretsObject, secretKeyHex)
                if(decrypted != testString) {throw new Error("Error: Decrypted did not match original content! hex Version @count"+c)}
            }
            after = performance.now()
            hexMS = after - before

            c = count
            before = performance.now()
            while(c--) {
                secretsObject = await secUtl.asymmetricEncryptBytes(testString, publicKeyBytes)
                decrypted = await secUtl.asymmetricDecryptBytes(secretsObject, secretKeyBytes)
                if(decrypted != testString) {throw new Error("Error: Decrypted did not match original content! bytes Version @count"+c)}
            }
            after = performance.now()
            bytesMS = after - before

            c = count
            before = performance.now()
            while(c--) {
                secretsObject = await secUtlOld.asymmetricEncryptBytes(testString, publicKeyBytes)
                decrypted = await secUtlOld.asymmetricDecryptBytes(secretsObject, secretKeyBytes)
                if(decrypted != testString) {throw new Error("Error: Decrypted did not match original content! oldHex Version @count"+c)}
            }
            after = performance.now()
            oldHexMS = after - before

            c = count
            before = performance.now()
            while(c--) {
                secretsObject = await secUtlOlder.asymmetricEncryptBytes(testString, publicKeyBytes)
                decrypted = await secUtlOlder.asymmetricDecryptBytes(secretsObject, secretKeyBytes)
                if(decrypted != testString) {throw new Error("Error: Decrypted did not match original content! olderHex Version @count"+c)}
            }
            after = performance.now()
            olderHexMS = after - before


            results.testAsymmetricEncryption = {success, hexMS, bytesMS, oldHexMS, olderHexMS}
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
async function testDiffieHellmanSecretHash() {

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

        var sharedSecretAliceHex = await secUtl.diffieHellmanSecretHashHex(alicePrivHex, bobPubHex, context)
        var sharedSecretBobHex = await secUtl.diffieHellmanSecretHashHex(bobPrivHex, alicePubHex, context)
        if(sharedSecretAliceHex != sharedSecretBobHex) { throw new Error(`Hex Shared Secrets did not match!\n sharedSecretAliceHex: ${sharedSecretAliceHex}\nsharedSecretBobHex: ${sharedSecretBobHex}`)}


        var sharedSecretAliceBytes = await secUtl.diffieHellmanSecretHashBytes(alicePrivBytes, bobPubBytes, context)
        var sharedSecretBobBytes = await secUtl.diffieHellmanSecretHashBytes(bobPrivBytes, alicePubBytes, context)
        if(sharedSecretAliceBytes.toString("hex") != sharedSecretBobBytes.toString("hex")) { throw new Error(`Bytes Shared Secrets did not match!\n sharedSecretAliceBytes: ${sharedSecretAliceBytes}\nsharedSecretBobBytes: ${sharedSecretBobBytes}`)}
        
        
        var compHex = sharedSecretBobBytes.toString("hex")
        if(sharedSecretAliceHex != compHex){ throw new Error(`Hex version of Bytes Secret did not match the original Hex version!\ncompHex: ${compHex}\nsharedSecretAliceHex: ${sharedSecretAliceHex}`)}

        let success = true
        let before
        let after
        let hexMS
        let bytesMS
        let oldHexMS
        let c

        c = count
        before = performance.now()
        while(c--) {
            sharedSecretAliceHex = await secUtl.diffieHellmanSecretHashHex(alicePrivHex, bobPubHex, context)
            sharedSecretBobHex = await secUtl.diffieHellmanSecretHashHex(bobPrivHex, alicePubHex, context)
            if(sharedSecretAliceHex != sharedSecretBobHex) { throw new Error("Shared Secrets did not Match! oldHex version @count"+c)}        
        }
        after = performance.now()
        hexMS = after - before

        c = count
        before = performance.now()
        while(c--) {
            sharedSecretAliceBytes = await secUtl.diffieHellmanSecretHashBytes(alicePrivBytes, bobPubBytes, context)
            sharedSecretBobBytes = await secUtl.diffieHellmanSecretHashBytes(bobPrivBytes, alicePubBytes, context)
            if(sharedSecretAliceBytes.toString("hex") != sharedSecretBobBytes.toString("hex")) { throw new Error("Shared Secrets did not Match! oldHex version @count"+c)}
        }
        after = performance.now()
        bytesMS = after - before

        c = count
        before = performance.now()
        while(c--) {
            sharedSecretAliceHex = await secUtlOld.createSharedSecretHashHex(alicePrivHex, bobPubHex, context)
            sharedSecretBobHex = await secUtlOld.createSharedSecretHashHex(bobPrivHex, alicePubHex, context)
            if(sharedSecretAliceHex != sharedSecretBobHex) { throw new Error("Shared Secrets did not Match! oldHex version @count"+c)}
        }
        after = performance.now()
        oldHexMS = after - before

        results.diffieHellmanSecretHash = {success, hexMS, bytesMS, oldHexMS}

    } catch(error) {
        results.diffieHellmanSecretHash = error.message
    }

}

//############################################################
async function testDiffieHellmanSecretRaw() {

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

        var sharedSecretAliceHex = await secUtl.diffieHellmanSecretRawHex(alicePrivHex, bobPubHex)
        var sharedSecretBobHex = await secUtl.diffieHellmanSecretRawHex(bobPrivHex, alicePubHex)
        if(sharedSecretAliceHex != sharedSecretBobHex) { throw new Error(`Hex Shared Secrets did not match!\n sharedSecretAliceHex: ${sharedSecretAliceHex}\nsharedSecretBobHex: ${sharedSecretBobHex}`)}


        var sharedSecretAliceBytes = await secUtl.diffieHellmanSecretRawBytes(alicePrivBytes, bobPubBytes)
        var sharedSecretBobBytes = await secUtl.diffieHellmanSecretRawBytes(bobPrivBytes, alicePubBytes)
        if(sharedSecretAliceBytes.toString("hex") != sharedSecretBobBytes.toString("hex")) { throw new Error(`Bytes Shared Secrets did not match!\n sharedSecretAliceBytes: ${sharedSecretAliceBytes}\nsharedSecretBobBytes: ${sharedSecretBobBytes}`)}
        
        
        var compHex = Buffer.from(sharedSecretBobBytes).toString("hex")
        if(sharedSecretAliceHex != compHex){ throw new Error(`Hex version of Bytes Secret did not match the original Hex version!\ncompHex: ${compHex}\nsharedSecretAliceHex: ${sharedSecretAliceHex}`)}

        let success = true
        let before
        let after
        let hexMS
        let bytesMS
        let oldHexMS
        let c

        c = count
        before = performance.now()
        while(c--) {
            sharedSecretAliceHex = await secUtl.diffieHellmanSecretRawHex(alicePrivHex, bobPubHex)
            sharedSecretBobHex = await secUtl.diffieHellmanSecretRawHex(bobPrivHex, alicePubHex)
            if(sharedSecretAliceHex != sharedSecretBobHex) { throw new Error("Shared Secrets did not Match! hex version @count"+c)}
        }
        after = performance.now()
        hexMS = after - before

        c = count
        before = performance.now()
        while(c--) {
            sharedSecretAliceBytes = await secUtl.diffieHellmanSecretRawBytes(alicePrivBytes, bobPubBytes)
            sharedSecretBobBytes = await secUtl.diffieHellmanSecretRawBytes(bobPrivBytes, alicePubBytes)
            if(sharedSecretAliceBytes.toString("hex") != sharedSecretBobBytes.toString("hex")) { throw new Error("Shared Secrets did not Match! bytes version @count"+c)}
        }
        after = performance.now()
        bytesMS = after - before

        c = count
        before = performance.now()
        while(c--) {
            sharedSecretAliceHex = await secUtlOld.createSharedSecretRawHex(alicePrivHex, bobPubHex)
            sharedSecretBobHex = await secUtlOld.createSharedSecretRawHex(bobPrivHex, alicePubHex)
            if(sharedSecretAliceHex != sharedSecretBobHex) { throw new Error("Shared Secrets did not Match! oldHex version @count"+c)}
        }
        after = performance.now()
        oldHexMS = after - before

        results.diffieHellmanSecretRaw = {success, hexMS, bytesMS, oldHexMS}
    } catch(error) {
        results.diffieHellmanSecretRaw = error.message
    }

}

//############################################################
async function testElGamalSecretHash() {

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

        var referencedHex = await secUtl.elGamalSecretHashHex(bobPubHex, context)
        var referencePointHex = referencedHex.referencePointHex
        var sharedSecretAliceHex = referencedHex.sharedSecretHex

        var sharedSecretBobHex = await secUtl.diffieHellmanSecretHashHex(bobPrivHex, referencePointHex, context)
        if(sharedSecretAliceHex != sharedSecretBobHex) { throw new Error(`Hex Shared Secrets did not match!\n sharedSecretAliceHex: ${sharedSecretAliceHex}\nsharedSecretBobHex: ${sharedSecretBobHex}`)}


        var referencedBytes = await secUtl.elGamalSecretHashBytes(bobPubBytes, context)
        var referencePointBytes = referencedBytes.referencePointBytes
        var sharedSecretAliceBytes = referencedBytes.sharedSecretBytes

        var sharedSecretBobBytes = await secUtl.diffieHellmanSecretHashBytes(bobPrivBytes, referencePointBytes, context)
        if(Buffer.from(sharedSecretAliceBytes).toString("hex") != Buffer.from(sharedSecretBobBytes).toString("hex")) { throw new Error(`Bytes Shared Secrets did not match!\n sharedSecretAliceBytes: ${sharedSecretAliceBytes}\nsharedSecretBobBytes: ${sharedSecretBobBytes}`)}
        
        
        let success = true
        let before
        let after
        let hexMS
        let bytesMS
        let oldHexMS
        let c

        c = count
        before = performance.now()
        while(c--) {
            sharedSecretAliceHex = await secUtl.elGamalSecretHashHex(bobPubHex, context)
            referencePointHex = referencedHex.referencePointHex
            sharedSecretAliceHex = referencedHex.sharedSecretHex
            sharedSecretBobHex = await secUtl.diffieHellmanSecretHashHex(bobPrivHex, referencePointHex, context)
            if(sharedSecretAliceHex != sharedSecretBobHex) { throw new Error("Shared Secrets did not Match! hex version @count"+c)}
        }
        after = performance.now()
        hexMS = after - before

        c = count
        before = performance.now()
        while(c--) {
            sharedSecretAliceBytes = await secUtl.elGamalSecretHashBytes(bobPubBytes, context)
            referencePointBytes = referencedBytes.referencePointBytes
            sharedSecretAliceBytes = referencedBytes.sharedSecretBytes
            sharedSecretBobBytes = await secUtl.diffieHellmanSecretHashBytes(bobPrivBytes, referencePointBytes, context)
            if(sharedSecretAliceBytes.toString("hex") != sharedSecretBobBytes.toString("hex")) { throw new Error("Shared Secrets did not Match! hex version @count"+c) }
        }
        after = performance.now()
        bytesMS = after - before


        c = count
        before = performance.now()
        while(c--) {
            sharedSecretAliceHex = await secUtlOld.referencedSharedSecretHashHex(bobPubHex, context)
            referencePointHex = sharedSecretAliceHex.referencePointHex
            sharedSecretAliceHex = sharedSecretAliceHex.sharedSecretHex
            sharedSecretBobHex = await secUtlOld.createSharedSecretHashHex(bobPrivHex, referencePointHex, context)
            if(sharedSecretAliceHex != sharedSecretBobHex) { throw new Error("Shared Secrets did not Match! oldHex version @count"+c)}
        }
        after = performance.now()
        oldHexMS = after - before

        results.elGamalSecretHash = {success, hexMS, bytesMS, oldHexMS}

    } catch(error) {
        results.elGamalSecretHash = error.message
    }

}

//############################################################
async function testElGamalSecretRaw() {

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

        var referencedHex = await secUtl.elGamalSecretRawHex(bobPubHex, context)
        var referencePointHex = referencedHex.referencePointHex
        var sharedSecretAliceHex = referencedHex.sharedSecretHex

        var sharedSecretBobHex = await secUtl.diffieHellmanSecretRawHex(bobPrivHex, referencePointHex, context)
        if(sharedSecretAliceHex != sharedSecretBobHex) { throw new Error(`Hex Shared Secrets did not match!\n sharedSecretAliceHex: ${sharedSecretAliceHex}\nsharedSecretBobHex: ${sharedSecretBobHex}`)}


        var referencedBytes = await secUtl.elGamalSecretRawBytes(bobPubBytes, context)
        var referencePointBytes = referencedBytes.referencePointBytes
        var sharedSecretAliceBytes = referencedBytes.sharedSecretBytes

        var sharedSecretBobBytes = await secUtl.diffieHellmanSecretRawBytes(bobPrivBytes, referencePointBytes, context)
        if(Buffer.from(sharedSecretAliceBytes).toString("hex") != Buffer.from(sharedSecretBobBytes).toString("hex")) { throw new Error(`Bytes Shared Secrets did not match!\n sharedSecretAliceBytes: ${sharedSecretAliceBytes}\nsharedSecretBobBytes: ${sharedSecretBobBytes}`)}
        
        
        let success = true
        let before
        let after
        let hexMS
        let bytesMS
        let oldHexMS
        let c

        c = count
        before = performance.now()
        while(c--) {
            sharedSecretAliceHex = await secUtl.elGamalSecretRawHex(bobPubHex)
            referencePointHex = sharedSecretAliceHex.referencePointHex
            sharedSecretAliceHex = sharedSecretAliceHex.sharedSecretHex
            sharedSecretBobHex = await secUtl.diffieHellmanSecretRawHex(bobPrivHex, referencePointHex)
            if(sharedSecretAliceHex != sharedSecretBobHex) { throw new Error("Shared Secrets did not Match! hex version @count"+c)}
        }
        after = performance.now()
        hexMS = after - before

        c = count
        before = performance.now()
        while(c--) {
            sharedSecretAliceBytes = await secUtl.elGamalSecretRawBytes(bobPubBytes)
            referencePointBytes = sharedSecretAliceBytes.referencePointBytes
            sharedSecretAliceBytes = sharedSecretAliceBytes.sharedSecretBytes
            sharedSecretBobBytes = await secUtl.diffieHellmanSecretRawBytes(bobPrivBytes, referencePointBytes)
            if(sharedSecretAliceBytes.toString("hex") != sharedSecretBobBytes.toString("hex")) { throw new Error("Shared Secrets did not Match! bytes version @count"+c)}
        }
        after = performance.now()
        bytesMS = after - before

        c = count
        before = performance.now()
        while(c--) {
            sharedSecretAliceHex = await secUtlOld.referencedSharedSecretRawHex(bobPubHex)
            referencePointHex = sharedSecretAliceHex.referencePointHex
            sharedSecretAliceHex = sharedSecretAliceHex.sharedSecretHex
            sharedSecretBobHex = await secUtlOld.createSharedSecretRawHex(bobPrivHex, referencePointHex)
            if(sharedSecretAliceHex != sharedSecretBobHex) { throw new Error("Shared Secrets did not Match! oldHex version @count"+c)}
        }
        after = performance.now()
        oldHexMS = after - before

        results.elGamalSecretRaw = {success, hexMS, bytesMS, oldHexMS}

    } catch(error) {
        results.elGamalSecretRaw = error.message
    }
}


//############################################################
async function runAllTest() {
    await testSignatures() // get rid fresh start performance regression

    // real tests
    await testShas() // seem to work ;)
    await testPublicKey() // seem to work ;)
    await testSignatures() // seem to work ;)
    await testSymmetricEncryption() // seem to work ;)
    await testAsymmetricEncryption()    

    await testDiffieHellmanSecretHash()
    await testDiffieHellmanSecretRaw()
    await testElGamalSecretHash()
    await testElGamalSecretRaw()

    await testSalts()

    evaluate()

}

function evaluate() {
    console.log(JSON.stringify(results, null, 4))
}

runAllTest()
