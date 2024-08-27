import Sinon from "sinon";
import FirebaseJwt, { NextFirebaseJwt } from ".";
import jwt, { JwtPayload } from 'jsonwebtoken'
import utils from "./utils";
import { expect } from "chai";
import * as jose from 'jose'
import * as crypto from 'crypto'
import * as nodeforge from 'node-forge'
import pem from 'pem'

describe("FirebaseJwt testing", function(){
    
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

            after(function(){
                Sinon.restore()
            })
        })
    })


    describe("NextFirebaseJwt class Testing", function(){
        let nFbJwt: NextFirebaseJwt;
        let projectId: string;
        before(function(){
            projectId = "typing-monkey";
            nFbJwt = new NextFirebaseJwt(projectId)
        })
    
        describe("verify method Testing", function(){
            let jwtToken: string;
            before(async function(){
                var _pem = {
                    privateKey: '-----BEGIN PRIVATE KEY-----\r\n' +
                      'MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCtQM1R5VoB8Hrr\r\n' +
                      'hdL514H+oQN/FSIiHXsdoZlQqUEQ7yUBgC2c7fbq4Wm9AUHBkc/KfUGb9+ZeX6xo\r\n' +
                      '6L06M57QBD8nkSTStNHozlOwjnKu7DnlyW4j3ej9rBZzshLzAvWGZkx5sR1Eyz/2\r\n' +
                      '2Ns9PL+S4h3eiRGpTw3g3geI1wxBv3CCb/LUF5Wa4NWwIU1GP9S6d8MrOb3WGhR3\r\n' +
                      '64ZxajxSeX8R9WLsAo1Qx0dhsJ/UMwIibZ3hA9y1VBma2QyqQMzdY9OYC4oyE646\r\n' +
                      'WfyJzHscpc6KNiVsWnYDP9+NStQlvaXMwhaPFpyVkLLB0vHho4oMXgEDTCH1iIe4\r\n' +
                      'YGw01wQ/AgMBAAECggEAdx1wjHfFNEQkHr25WbDDXU9SWhMrjoz6UlsCT6SuaXgh\r\n' +
                      '1zBLK/OnqcEks5+jl/QqCqunahY8OnJI1S/+uX84Fwh0az2tNXjAQPFqNJ8bVgxv\r\n' +
                      'mf6tTNeLEq04Gn856/4C1E6NEbWly+B5r7tUsHuNsuznYFKY4/DIN+wu/fPsJ17X\r\n' +
                      'vbZiev6+OID/XCKPYWNRYiszBcmktGM5L+JLcYYPpxFYGFtw+khhUlazx0OmIuDB\r\n' +
                      'AaePTtyXb1qQNKHv6wy7l+BTBKAlxoQQHMCw5qsnCr9RHed7LJr0kssUbVaseUOg\r\n' +
                      'KMWtRG0Ms3ovOPWsVFC509gbGal8q+NSwyKd07SlQQKBgQDZX6bwE1H+V7r5GJwz\r\n' +
                      'EGRLrMUDbbCb2qqZcSn+TCk9hsJ6jeSwz9KjZ2qONcmMl3WY6XAOdTjmJZl20wF9\r\n' +
                      'GV58pZAoPhLh6tByX9RlUffXz+1KKMP0/5cxmwV8N0RBWrHcmRc6yMwJGZE7qBUh\r\n' +
                      'JX/77xj9yPoDW+uOSGp+f0nZMQKBgQDMChqQF1cw7iIljzmtOhSnSEiCH7WYCJgp\r\n' +
                      'um7KEGfFXxbNX07g6pojdjVFFf9uA6tPaiTnwXLc8wI8yiuwt8yPh60QTrcW/E/0\r\n' +
                      '+iQQGkwrFvWybbEuI++K6rOXdNMq7FEU467qN26lzHpagSEn6bXdss8L7AOcGRif\r\n' +
                      '0E/rSXlYbwKBgQDHFAA6vScJzmUxvyVG6ws/90IT6sClbHVzxB1WhX/7llDElvFM\r\n' +
                      'MXlTJ+KBzacB+LC904VJ6Hes5+CN35/sZ3COrb7B7F+0wi4XocZO6OwYnZhPo9gb\r\n' +
                      'qH1a9APpCGCdjid4xkhtEPs0llLZlQ2M5uA45ng37Xlz3Bp2m8HUilUi8QKBgQCa\r\n' +
                      'RpV5F7zciWIWRipVGZJePeBdSz6SOwVan9V/QVJFQTXLiWHp3Fk5sPpsR0rAU1Pn\r\n' +
                      'kxlehr2j5LZvYmoQj5jDedHYf7weTB7k23IDHu8ysYSLKjeK7K8FuZqbTUERtmdE\r\n' +
                      'RTePbuRhxq9I2VRJioPxom680/KSx8L/q5GSFRcETwKBgDZhnBZ7+dIKlPAgfwPC\r\n' +
                      'OCA2kKE+5UxyeAUeojNrSfHGdzF891PX+90D7sPfJi7SJU4E/UOMG/u8wUv5i2/+\r\n' +
                      '/nKOI6NwKB/m0FqpvxamuNJapn9RQ9bC7oz0Rj2Tho90mohwQG4DHF2uO8364Wb+\r\n' +
                      '9Bu1FCWmILPGcJM5iw6TJPA0\r\n' +
                      '-----END PRIVATE KEY-----\r\n',
                    certificate: '-----BEGIN CERTIFICATE-----\r\n' +
                      'MIIDqjCCApKgAwIBAgIJAJvrXrdlRWTTMA0GCSqGSIb3DQEBCwUAMGgxCzAJBgNV\r\n' +
                      'BAYTAlVTMRAwDgYDVQQIDAdWaXJnaW5hMRMwEQYDVQQHDApCbGFja3NidXJnMQ0w\r\n' +
                      'CwYDVQQKDARUZXN0MQ0wCwYDVQQLDARUZXN0MRQwEgYDVQQDDAtleGFtcGxlLm9y\r\n' +
                      'ZzAiGA8yMDUwMDIwMTIzMDAyOVoYDzIwNTEwMjAxMjMwMDI5WjBoMQswCQYDVQQG\r\n' +
                      'EwJVUzEQMA4GA1UECAwHVmlyZ2luYTETMBEGA1UEBwwKQmxhY2tzYnVyZzENMAsG\r\n' +
                      'A1UECgwEVGVzdDENMAsGA1UECwwEVGVzdDEUMBIGA1UEAwwLZXhhbXBsZS5vcmcw\r\n' +
                      'ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtQM1R5VoB8HrrhdL514H+\r\n' +
                      'oQN/FSIiHXsdoZlQqUEQ7yUBgC2c7fbq4Wm9AUHBkc/KfUGb9+ZeX6xo6L06M57Q\r\n' +
                      'BD8nkSTStNHozlOwjnKu7DnlyW4j3ej9rBZzshLzAvWGZkx5sR1Eyz/22Ns9PL+S\r\n' +
                      '4h3eiRGpTw3g3geI1wxBv3CCb/LUF5Wa4NWwIU1GP9S6d8MrOb3WGhR364ZxajxS\r\n' +
                      'eX8R9WLsAo1Qx0dhsJ/UMwIibZ3hA9y1VBma2QyqQMzdY9OYC4oyE646WfyJzHsc\r\n' +
                      'pc6KNiVsWnYDP9+NStQlvaXMwhaPFpyVkLLB0vHho4oMXgEDTCH1iIe4YGw01wQ/\r\n' +
                      'AgMBAAGjUzBRMB0GA1UdDgQWBBRxifZwjEsDjYgbajBq+e1r4krdwjAfBgNVHSME\r\n' +
                      'GDAWgBRxifZwjEsDjYgbajBq+e1r4krdwjAPBgNVHRMBAf8EBTADAQH/MA0GCSqG\r\n' +
                      'SIb3DQEBCwUAA4IBAQB0V8zdJ1WebOvZNwl6WcbzNJRQePPnGp9pAbGuqpLZHvs6\r\n' +
                      'geAocgmEqleGOsU9GT30MV1vtkR1IY6CWkVPeSiXS43HT8enoYCJX3AZd6ItUrQH\r\n' +
                      '8UonY8UqAmzsGLO+ttO5o6kEY6K0e1QUdmFkOh9Z6M9U3s3DASwrKQ/xFlHQ2mNi\r\n' +
                      'h7pKaH2+XlDTrCjhO1ip0n4AwG5lgFJpJlVOZ9+Axzc146q/YZqrhXHYU152Wqo/\r\n' +
                      'mFlygydsKNwWdpK5fwGBZkBR8AsZvNZaQ9Rr3Rr3y5Xz7+aPfLfWF5hW+d11ghuy\r\n' +
                      'FDeZMUBehXXEJLXrirfmO2KFmy3iKrniJDDa35Lg\r\n' +
                      '-----END CERTIFICATE-----\r\n'
                  };

                  jwtToken = await new jose.SignJWT({ 
                    name: 'Aditya kumar',
                    iss: 'https://securetoken.google.com/typing-monkey',
                    aud: 'typing-monkey',
                    auth_time: 1724471969,
                    user_id: 'xagcOFWkPnWMLkKRc96kcxbc8uo1',
                    sub: 'xagcOFWkPnWMLkKRc96kcxbc8uo1',
                    email: 'raj68518@gmail.com',
                    email_verified: true,
                    firebase: { identities: { email: [Array] }, sign_in_provider: 'password' }}).setProtectedHeader({alg: "RS256",typ: "jwt",}).sign(await jose.importPKCS8(_pem.privateKey, "RSA"))
               
                  Sinon.stub(utils, "getPublicKey").returns(Promise.resolve(_pem.certificate))
                  Sinon.stub(utils, "getProjectUrl")
                  .onFirstCall().returns(`https://securetoken.google.com/${projectId}`)
                  .onSecondCall().returns("projectId-test")


            })
            
    
            it("should pass", async function(){
                const result = await nFbJwt.verify(jwtToken)                
                expect(result).to.be.an("object")
            })
    
            it("should fail if algo doesn't match", async function(){
                try {
                    await nFbJwt.verify(jwtToken)
                } catch (error) {
                    expect(typeof error).to.be.eq("object");
                }
            })
    
            it("should fail if project id doesn't match", async function(){
                try {
                    await nFbJwt.verify(jwtToken)
                } catch (error) {
                    expect(typeof error).to.be.eq("object");
                }
            })
    
            after(function(){
                Sinon.restore()
            })
    
        })
    
        describe("decode method Testing", function(){
            let jwtToken: string;
            before(function(){
               jwtToken = jwt.sign({ 
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
                firebase: { identities: { email: [Array] }, sign_in_provider: 'password' }}, "secret")
            })
    
            it("should pass", function(){
                const response = nFbJwt.decode(jwtToken)
                expect(response).to.be.an("object")
            })

            it("should fail", function(){
                try{
                    nFbJwt.decode(`${jwtToken}.abc`)
                }catch(e){
                    expect(typeof e).to.be.eq("object")
                }
            })

            after(function(){
                Sinon.restore()
            })
        })
    })
})