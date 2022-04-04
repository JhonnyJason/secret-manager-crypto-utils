var secUtl = require("../output/index.js")

var testString = "test"


async function runTest() {
    var sha256Hex = await secUtl.sha256Hex(testString)
    var sha256Bytes = await secUtl.sha256Bytes(testString)
    

    console.log("hex sha256: "+sha256Hex)
    var isMatch = sha256Hex == Buffer.from(sha256Bytes).toString("hex")

    if(isMatch) {
        console.log("Sha256 - hex matched the bytes version.")
    } else {
        console.log("Error! Sha256 - hex did not match the bytes version.")
    }

}


runTest()
