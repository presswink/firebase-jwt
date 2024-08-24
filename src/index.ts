import jwt, { JwtPayload } from "jsonwebtoken"
import utils from "./utils"


export interface IFirebaseJwt {
    verify(jwtString: string): Promise<JwtPayload | string | undefined>
    decode(jwtString: string):jwt.Jwt | null
}

export class FirebaseJwt implements IFirebaseJwt {
    private projectId: string
    
    constructor(projectId: string){
        this.projectId = projectId
    }

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

    decode(jwtString: string):jwt.Jwt | null {
        return jwt.decode(jwtString, {complete: true})
    }
}
