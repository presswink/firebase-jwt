import Sinon from "sinon";
import { FirebaseJwt } from ".";
import jwt, { JwtPayload } from 'jsonwebtoken'
import utils from "./utils";
import { expect } from "chai";


describe("FirebaseJwt class Testing", function(){
    let fbJwt: FirebaseJwt;
    let projectId: string;
    before(function(){
        projectId = "typing-monkey";
        fbJwt = new FirebaseJwt(projectId)
    })

    describe("verify method Testing", function(){
        before(function(){
            Sinon.stub(jwt, "decode")
            .onFirstCall().returns({
                header: {
                    alg: "RS256"
                },
                payload:{
                    name: 'Aditya kumar',
                    iss: 'https://securetoken.google.com/typing-monkey',
                    aud: 'typing-monkey',
                    auth_time: 1724471969,
                    user_id: 'xagcOFWkPnWMLkKRc96kcxbc8uo1',
                    sub: 'xagcOFWkPnWMLkKRc96kcxbc8uo1',
                    iat: 1724471969,
                    exp: 1724475569,
                    email: 'raj68518@gmail.com',
                    email_verified: true,
                    firebase: { identities: { email: [Array] }, sign_in_provider: 'password' }
                  }
            } as JwtPayload)
            .onSecondCall().returns({
                header: {
                },
                payload:{
                    name: 'Aditya kumar',
                    iss: 'https://securetoken.google.com/typing-monkey',
                    aud: 'typing-monkey',
                    auth_time: 1724471969,
                    user_id: 'xagcOFWkPnWMLkKRc96kcxbc8uo1',
                    sub: 'xagcOFWkPnWMLkKRc96kcxbc8uo1',
                    iat: 1724471969,
                    exp: 1724475569,
                    email: 'raj68518@gmail.com',
                    email_verified: true,
                    firebase: { identities: { email: [Array] }, sign_in_provider: 'password' }
                  }
            } as JwtPayload)
            .onThirdCall().returns({
                header: {
                    alg: "RS256"
                },
                payload:{
                    name: 'Aditya kumar',
                    iss: 'https://securetoken.google.com/typing-monkey-12',
                    aud: 'typing-monkey',
                    auth_time: 1724471969,
                    user_id: 'xagcOFWkPnWMLkKRc96kcxbc8uo1',
                    sub: 'xagcOFWkPnWMLkKRc96kcxbc8uo1',
                    iat: 1724471969,
                    exp: 1724475569,
                    email: 'raj68518@gmail.com',
                    email_verified: true,
                    firebase: { identities: { email: [Array] }, sign_in_provider: 'password' }
                  }
            } as JwtPayload)

              Sinon.stub(utils, "getPublicKey").returns(Promise.resolve("pub"))
              Sinon.stub(utils, "getProjectUrl").returns(`https://securetoken.google.com/${projectId}`)

            const vstb = Sinon.stub(jwt, "verify") as unknown as Sinon.SinonStub<[token: string, secretOrPublicKey: jwt.Secret | jwt.GetPublicKeyOrSecret, options?: jwt.VerifyOptions | undefined], JwtPayload | string>
            vstb
            .onFirstCall().returns({
                name: 'Aditya kumar',
                iss: 'https://securetoken.google.com/typing-monkey',
                aud: 'typing-monkey',
                auth_time: 1724471969,
                user_id: 'xagcOFWkPnWMLkKRc96kcxbc8uo1',
                sub: 'xagcOFWkPnWMLkKRc96kcxbc8uo1',
                iat: 1724471969,
                exp: 1724475569,
                email: 'raj68518@gmail.com',
                email_verified: true,
                firebase: { identities: { email: [Array] }, sign_in_provider: 'password' }
              })
        })

        it("should pass", async function(){
            const result = await fbJwt.verify("token")
            expect(result).to.be.an("object")
        })

        it("should fail if algo doesn't match", async function(){
            try {
                await fbJwt.verify("token")
            } catch (error) {
                expect(typeof error).to.be.eq("object");
            }
        })

        it("should fail if project id doesn't match", async function(){
            try {
                await fbJwt.verify("token")
            } catch (error) {
                expect(typeof error).to.be.eq("object");
            }
        })

        after(function(){
            Sinon.restore()
        })

    })

    describe("decode method Testing", function(){
        before(function(){
            Sinon.stub(jwt, "decode").returns({
                name: 'Aditya kumar',
                iss: 'https://securetoken.google.com/typing-monkey',
                aud: 'typing-monkey',
                auth_time: 1724471969,
                user_id: 'xagcOFWkPnWMLkKRc96kcxbc8uo1',
                sub: 'xagcOFWkPnWMLkKRc96kcxbc8uo1',
                iat: 1724471969,
                exp: 1724475569,
                email: 'raj68518@gmail.com',
                email_verified: true,
                firebase: { identities: { email: [Array] }, sign_in_provider: 'password' }
              })
        })

        it("should pass", function(){
            const response = fbJwt.decode("token")
            expect(response).to.be.an("object")
        })
    })
})