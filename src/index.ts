import jwt, { Jwt, JwtPayload } from "jsonwebtoken"
import utils from "./utils"


export interface IFirebaseJwt {
    verify(jwtString: string): Promise<JwtPayload | string | undefined>
    decode(jwtString: string):jwt.Jwt | null
}

export default class FirebaseJwt implements IFirebaseJwt {
   /**
    * you have to pass firebase projectId to class constructor
    * @param projectId - is an firebase project id
    */ 
    constructor(projectId: string){
        this.projectId = projectId
    }

    private projectId: string
    
    

    /**
     * this function is going to verify json web token (jwt) is valid or not if valid then it will return decoded data from token
     * @param jwtString - is a json web token string
     * @return {Promise<JwtPayload | string>} will return `JwtPayload` or `string`
     */
    async verify(jwtString: string): Promise<JwtPayload | string>{
        const decoded  = jwt.decode(jwtString, {complete: true})
        const projectIdUrl = utils.getProjectUrl(this.projectId)
        let payload: JwtPayload
        if(decoded?.payload &&  typeof decoded?.payload === "string"){
            payload = JSON.parse(decoded?.payload) as JwtPayload
        }else {
            payload = decoded?.payload as JwtPayload
        }
        if(projectIdUrl === payload?.iss && decoded?.header?.alg === "RS256"){
            const publicKey = await utils.getPublicKey(decoded?.header.kid as string)
            return jwt.verify(jwtString, Buffer.from(publicKey))
        }else {
            throw new Error("invalid jwt !")
        }
    }

    /**
     * 
     * @param jwtString - is a json web token string
     * @return {Jwt | null} will return `Jwt` or `null`
     */
    decode(jwtString: string):Jwt | null {
        return jwt.decode(jwtString, {complete: true})
    }
}
