//
//  RSAUtilsTests.swift
//  CloudFrontMiddlewareTests
//
//  Created by Greg Neagle on 5/16/25.
//

import Foundation
import Testing

let PRIVATE_KEY_STRING = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA4XZhFX3V4NFUQbZdWmDPEN5KJeRVm9bOJUigDRyD2UfdZbpd
Hy1lddomfxziRlJhuSTEsKBANhdiEv8rkHghtwIlpzzbROMkkbYHZETileAWy4tn
qHtgCBtVvwMU8Rjza9eUJzDdzC/fT7zYcYbAdT8R3Er55A18J8jDuBMzmMQEnNbL
oSIMP5ISPd5bPzG/3gdHsEvLuHweWhGCi1gvfaB6/mssng/wlQOHm6P8NPBcmWAW
gSVyF7xafCQsaS/0GnzhfZCjvTwMiCtoqEkvCQMdMd9yRFSoPm8V85tKRpfnPxOu
3+W2BXnILIg03RdAY9ZLUj7l0FyPTs/BLFqdIwIDAQABAoIBAQCHcR/9UyzK87WU
DEOkaYe68G7GuJadGbuZNjm/5qNmQf/EfuI2OoU6+SQrNGTSLec629W07W/ljsKB
+vxmu2Q1lnqcLrjidzmetyVVnPQpaQcIm+RXmFYmSJWIPAe2lnCVFlqP+JElepTC
SAYWnQa86HiISBo6X8d39ulsiUxzthyL2sHz2FBDyGfXifMi53Xze4C8tqk0jqxc
bTZTquUoPwmn4CNt65vQv5TWyeDeu0M+nHkoemZvtJ2b8/l3C1KjjqSHgODHqhg7
69PInOv9PFKTe6nh38+ARRKbGkQQ25JuULl8WVDMDXVitAb91PPHDSjpH2/towEG
ORvIbVvxAoGBAP8XLy9YrZDaNYGBHivqTDOLFMNFXl2V2UxwsvsRimc/qKHGKv5A
EorzRJ/DJNfNaq4WY+eH/yMtcyD3QAJ5BMgsv6FjpJii7dg3BnQdu+DGSfA5skv5
x6HsUAhCBI2W+rpfLLn6Hwz5VQ2a5/Z1rp/Fa4MMusXtm9/fpKDEY6JFAoGBAOJE
J2kARshHpCV5Tx3Vp1CCOTJyZWnL+P857IYkweCeYnnIzPnTx+JEi0d3v8PxkUuP
Ctq8G5zC6eC0mH4V9J5QOr8UVXVp5v+sX3CaubNEog3m9NfCETW1uLZ7ca2/yASP
dbY/D9tn/rF9jOGuMb/lOOi3fPcOfq52wy3RLexHAoGBANgN9vUPEtLhPvhVOAzS
AYCWiBtsIaT6SnYn7jAghy00CcwbYEbAVfRCXxlB2268mWKhrDRqR3qwABcn05tE
jPxOinBTSRHOzcyXrmui04Jp8C37cDxRbviCgra708do3SwFeIh8hNgkRhmj3lwt
CJ5iQ9FXcso5mhBgB7vzGsBRAoGAeCyqoeI7tfQXArBDjR0FGIWRy3Fm26IyRZyG
O1kagCqfMv+rnqUU7OBq+TJo77FF8lOu+C4gnEoJ3gcNVypiGhOSoBo0qX/t6K2s
oyoKp2Q0jh20vUOd0GEMEh/OaPILUiC/7GPiEC5T4AFG6jaSxdEBQNjzzmQsdI0v
bQ5EzdECgYBAyQe6+LA6PPp19T15zR52yI3A2GCxhnWo85j3J0DBSMfTJkqTkZ8A
qetlov0aId57N48fco3Uno1zybEzUxFMCi7x/04xNY8TpMsPSzHpqgIuGVVtBBz/
YgobcZkFwOQZ+omcKfbH7qs7U8cZ2+eKE+hjUR/+DCH5UEMwUohbAw==
-----END RSA PRIVATE KEY-----
"""

struct RSAUtilsTests {
    @Test func getPrivateKeyFromPEM() {
        let keyData = privateKeyDataFromPEM(PRIVATE_KEY_STRING)
        #expect(keyData != nil)
        let key = privateKeyfromData(keyData!)
        #expect(key != nil)
    }

    @Test func signDataWithPrivateKeyGeneratesExpected() {
        let expectedSignature = "i+W2UtxTiYXoL/yeeYgGtQ4knoedWBS7DND0FUjL1usZIx6pwzqvxegwssuEvPRgWq+SQqXJT5ikX0ARNBzHU7ve/kg0TGjWNK0ZvtyXdoExpNnEI/u3glVcovMt8oGa4xr4RvWLyU57bdxvbkYIG0bsiMpD4mUffg7dxxguf7WQ7Be0+VkAByL/KJFyDl+oOTxqckuQJ27pPZrESeH46XA6YpsG/mcsTIXkXqSKd5NQ0cIEWHeQ8LL3yIafMQ5rSQCxWy54GJ38qD74O6e4aqJ5rtWbGWGl7bjgNPjgom+ECC1uKMP0NJT0S61NPETsxkYygxjrtdweio4WEwpABA=="
        let message = Data("Hello, World!".utf8)
        if let keyData = privateKeyDataFromPEM(PRIVATE_KEY_STRING),
           let key = privateKeyfromData(keyData),
           let signature = sign(message, withKey: key)
        {
            #expect(signature.base64EncodedString() == expectedSignature)
        } else {
            #expect(Bool(false))
        }
    }
}
