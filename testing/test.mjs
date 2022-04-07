import * as secUtl from "../output/index.js"

const results = {}

var testString = "test"



async function testShas() {
    try {
        var sha256Hex = await secUtl.sha256Hex(testString)
        var sha256Bytes = await secUtl.sha256Bytes(testString)    

        console.log("hex sha256: "+sha256Hex)

        var isMatch = sha256Hex == Buffer.from(sha256Bytes).toString("hex")
    
        if(isMatch) {
            // console.log("Sha256 - hex matched the bytes version.")
            results.testShas="success"
        
        } else {
            // console.log("Error! Hex did not match the bytes version.")
            results.testShas="Error! Hex did not match the bytes version."
        }
    
    } catch(error) {
        results.testShas=error.message
    }
    
}

async function testSignatures() {

    try {
        var { secretKeyHex, publicKeyHex } = await secUtl.getNewKeyPair()

        var signatureHex = await secUtl.createSignature(testString, secretKeyHex)
        var verified = await secUtl.verify(signatureHex, publicKeyHex, testString)

        console.log(verified)
        if(verified) {
            results.testSignatures="success"
        } else {
            results.testSignatures="Error: Signature not verified"
        }

    } catch(error) {
        results.testSignatures=error.message
    }

}

async function testAsyncEncryption() {

}

async function testSyncEncryption() {


}

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


async function runAllTest() {
    var promises = []
    promises.push(testShas())
    promises.push(testSignatures())
    promises.push(testAsyncEncryption())
    promises.push(testSyncEncryption())
    promises.push(testSalts())

    await Promise.all(promises)

    evaluate()
}

function evaluate() {
    console.log(JSON.stringify(results, null, 4))
}

runAllTest()
