import * as secUtl from "../output/index.js"
import { performance } from "perf_hooks"

const stamp = performance.now

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
async function testSymetricEncryption() {

    try {
        var keyHex = await secUtl.createSymKeyHex()
    
        var gibbrishHex = await secUtl.symetricEncryptHex(testString, keyHex)    
        var decrypted = await secUtl.symetricDecrypt(gibbrishHex, keyHex)
        
        var hexMatched = decrypted == testString

        var keyBytes = await secUtl.createSymKeyBytes()
        var gibbrishBytes = await secUtl.symetricEncryptBytes(testString, keyBytes)    
        decrypted = await secUtl.symetricDecryptBytes(gibbrishBytes, keyBytes)

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
                gibbrishHex = await secUtl.symetricEncryptHex(testString, keyHex)
                decrypted = await secUtl.symetricDecrypt(gibbrishHex, keyHex)
            }
            after = stamp()
            hexMS = after - before

            c = count
            before = stamp()
            while(c--) {
                gibbrishBytes = await secUtl.symetricEncryptBytes(testString, keyBytes)    
                decrypted = await secUtl.symetricDecryptBytes(gibbrishBytes, keyBytes)
                    }
            after = stamp()
            bytesMS = after - before


            results.testSymetricEncryption = {success, hexMS, bytesMS}
        } else {
            results.testSymetricEncryption = "Error: Decrypted did not match original content!"
        }
    } catch(error) {
        results.testSymetricEncryption = error.message
    }


}

//############################################################
async function testAsymetricEncryption() {

    try {
        var { secretKeyHex, publicKeyHex } = await secUtl.createKeyPairHex()
        var { secretKeyBytes, publicKeyBytes } = await secUtl.createKeyPairBytes()
        
        var gibbrishHex = await secUtl.asymetricEncryptHex(testString, publicKeyHex)
        var decrypted = await secUtl.asymetricDecryptHex(gibbrishHex, secretKeyHex)
        var hexMatched = decrypted == testString
        
        var gibbrishBytes = await secUtl.asymetricEncryptHex(testString, publicKeyBytes)
        var decrypted = await secUtl.asymetricDecryptHex(gibbrishBytes, secretKeyBytes)
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
                gibbrishHex = await secUtl.asymetricEncryptHex(testString, publicKeyHex)
                decrypted = await secUtl.asymetricDecryptHex(gibbrishHex, secretKeyHex)
            }
            after = stamp()
            hexMS = after - before



            c = count
            before = stamp()
            while(c--) {
                gibbrishBytes = await secUtl.asymetricEncryptHex(testString, publicKeyBytes)
                decrypted = await secUtl.asymetricDecryptHex(gibbrishBytes, secretKeyBytes)        
            }
            after = stamp()
            bytesMS = after - before


            results.testAsymetricEncryption = {success, hexMS, bytesMS}
        } else {
            var error = "Error: Decrypted did not match original content!"
            results.testAsymetricEncryption = {error, hexMatched, bytesMatched} 
        }
    } catch(error) {
        results.testAsymetricEncryption = error.message
    }

}

//############################################################
async function testSalts() {

    try {
        var salt = await secUtl.createRandomLengthSalt()
        var saltedContent = salt+testString
        console.log(saltedContent)
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
    
    // await testShas()
    // await testSignatures()
    // await testSymetricEncryption()
    await testAsymetricEncryption()
    await testSalts()

    evaluate()
}

function evaluate() {
    console.log(JSON.stringify(results, null, 4))
}

runAllTest()
