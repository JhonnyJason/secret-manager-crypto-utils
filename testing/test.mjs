import * as secUtl from "../output/index.js"
import { performance } from "perf_hooks"

const stamp = performance.now

const results = {}

const testString = "testorritestorritestorri - asdaf 456789 äö90ß´ä-`''°^"

const count = 100

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
            before = stamp()
            while(c--) {
                sha512Hex = await secUtl.sha512Hex(testString)
            }
            after = stamp()
            sha512HexMS = after - before

            c = count
            before = stamp()
            while(c--) {
                sha512Bytes = await secUtl.sha512Bytes(testString)
            }
            after = stamp()
            sha512BytesMS = after - before


            c = count
            before = stamp()
            while(c--) {
                sha256Hex = await secUtl.sha256Hex(testString)
            }
            after = stamp()
            sha256HexMS = after - before

            c = count
            before = stamp()
            while(c--) {
                sha256Bytes = await secUtl.sha256Bytes(testString)
            }
            after = stamp()
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
            before = stamp()
            while(c--) {
                signatureHex = await secUtl.createSignatureHex(testString, secretKeyHex)
                verifiedHex = await secUtl.verify(signatureHex, publicKeyHex, testString)
            }
            after = stamp()
            hexMS = after - before


            c = count
            before = stamp()
            while(c--) {
                signatureBytes = await secUtl.createSignatureBytes(testString, secretKeyBytes)
                verifiedBytes = await secUtl.verify(signatureBytes, publicKeyBytes, testString)
            }
            after = stamp()
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
async function testsymmetricEncryption() {

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
            before = stamp()
            while(c--) {
                gibbrishHex = await secUtl.symmetricEncryptHex(testString, keyHex)
                decrypted = await secUtl.symmetricDecrypt(gibbrishHex, keyHex)
            }
            after = stamp()
            hexMS = after - before

            c = count
            before = stamp()
            while(c--) {
                gibbrishBytes = await secUtl.symmetricEncryptBytes(testString, keyBytes)    
                decrypted = await secUtl.symmetricDecryptBytes(gibbrishBytes, keyBytes)
                    }
            after = stamp()
            bytesMS = after - before


            results.testsymmetricEncryption = {success, hexMS, bytesMS}
        } else {
            results.testsymmetricEncryption = "Error: Decrypted did not match original content!"
        }
    } catch(error) {
        results.testsymmetricEncryption = error.message
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
            before = stamp()
            while(c--) {
                secretsObject = await secUtl.asymmetricEncryptHex(testString, publicKeyHex)
                decrypted = await secUtl.asymmetricDecryptHex(secretsObject, secretKeyHex)
            }
            after = stamp()
            hexMS = after - before

            c = count
            before = stamp()
            while(c--) {
                secretsObject = await secUtl.asymmetricEncryptBytes(testString, publicKeyBytes)
                decrypted = await secUtl.asymmetricDecryptBytes(secretsObject, secretKeyBytes)        
            }
            after = stamp()
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
    await testSignatures()
    await testsymmetricEncryption()
    await testAsymmetricEncryption()
    await testSalts()

    evaluate()
}

function evaluate() {
    console.log(JSON.stringify(results, null, 4))
}

runAllTest()