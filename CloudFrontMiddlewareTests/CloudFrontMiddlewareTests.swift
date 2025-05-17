//
//  CloudFrontMiddlewareTests.swift
//  CloudFrontMiddlewareTests
//
//  Created by Greg Neagle on 5/17/25.
//

import Testing

struct CloudFrontMiddlewareTests {
    let expires = 1_747_270_308
    let url = "https://example.com"
    let accessId = "FOO"
    let privateKey = rsaPrivateKeyFromPemString(PRIVATE_KEY_STRING)

    @Test func signRequestPolicyReturnsExpected() {
        let expectedSignature = "2AX-VxZP-D4SDZRTFPKYuMuFFiWT6oxMiZnrx4bdd9SgxWGl-JfeS1YoO4l2l~Hmf26WigIW2P~Deypbecc86qCexQrhs1dRQ1mBm4C1FSXPBCIyXUTK~MAR7EjP-iSElGSBNK3J3B7q8PT-ykieLJsB5ZbBKtw7~wmAGeng6HwHIXSnBLEqBzCSzZobuICv7f3xVNumxHF6Ibolz4uhk0jgEK7-GaikcumIVizAjrtEVY3BEQgje6t1SJeP0HxMqp1~9QH8yu95TMWXyEISvvpeBETxWm7rIyjrugU0J4f~Y2plgnV3yZA0iyeS7sACcUtm-rOJzO9VpmbBZQXuhg__"
        let requestPolicy = "FOO_BAR_BAZ"
        if let privateKey {
            let generatedSignature = signRequestPolicy(requestPolicy, withKey: privateKey)
            #expect(generatedSignature == expectedSignature)
        } else {
            #expect(Bool(false))
        }
    }

    @Test func makeJsonPolicyRequestReturnsExpected() {
        let expectedJsonString = """
        {"Statement":[{"Resource":"https://example.com","Condition":{"DateLessThan":{"AWS:EpochTime":1747270308}}}]}
        """
        let generatedJsonString = makeJsonPolicyRequest(url: url, expires: expires)
        #expect(generatedJsonString == expectedJsonString)
    }

    @Test func assembleCloudFrontRequestReturnsExpected() {
        let expectedURL = "https://example.com?Expires=1747270308&Signature=mCHEo~swKdxn9mJfAXi5vodA9-H8XrO5ca8NPrFmQA8crmxgaJqlvl2gOAiECVLbTVFdQeiUtnHK2blvC2edEws8IkemkFhA2hJT4HdpnUWj1uD~JQq8qaqTL1ZmC2ohZQekueajS-ZgJdMGgaumd7iyCFBhxrimOZE-B~iZbE8vxLe-6JuKv2~RXfIaNYBEfQInAJxEpgHXwseKTSaVOFLGp804dgK1QjEM3sQi~LN~2vUrvO73JgqIgq85S6raMhvxD7qPZKfTgngFpT2iWP-x21g7Zvh6Pc9K47Iw4bQeysGZj5UFPZ0Sci5vnvJw9qFu9WDvkCh8iWyh-~b0gg__&Key-Pair-Id=FOO"
        if let privateKey {
            let generatedURL = assembleCloudFrontRequest(
                url: url, key: privateKey, accessId: accessId, expires: expires
            )
            #expect(generatedURL == expectedURL)
        } else {
            #expect(Bool(false))
        }
    }
}
