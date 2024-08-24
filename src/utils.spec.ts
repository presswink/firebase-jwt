import { expect } from "chai"
import utils from "./utils"
import Sinon from "sinon"
import axios from "axios"


describe("utils class testing", function(){

    
    describe("getProjectUrl method testing", function(){
        it("should pass", function(){
            const projectId = "firebase-jwt"
            const result = utils.getProjectUrl(projectId)
            expect(result).to.be.a('string')
            expect(result).to.be.eq(`https://securetoken.google.com/${projectId}`)
        })
    })

    describe("getPublicKey method testing", function(){
        before(function(){
            Sinon.stub(axios, "get")
            .onFirstCall().returns(Promise.resolve({
                data: {
                    key_1: "publickey",
                    key_2: "publickey"
                }
            }))
            .onSecondCall().returns(Promise.resolve(Promise.resolve({
                data: {
                    key_1: "publickey",
                    key_2: "publickey"
                }
            })))
            .onThirdCall().returns(Promise.resolve({}))
        })

        it("should pass", async function(){
            const result = await utils.getPublicKey("key_1")
            expect(result).to.be.a('string')
        })

        it("should fail with invalid keyId", async function(){
            try {
                await utils.getPublicKey("key_3")
            } catch (error: unknown) {
                expect(typeof error).to.be.eq("object")
            }
        })

        it("should fail with data is missing", async function(){
            try {
                await utils.getPublicKey("key_3")
            } catch (error: unknown) {
                expect(typeof error).to.be.eq("object")
            }
        })

        after(function(){
            Sinon.restore()
        })
    })
})