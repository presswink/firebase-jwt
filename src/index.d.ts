import { Jwt, JwtPayload } from "jsonwebtoken";

export declare class FirebaseJwt {
    private projectId: string
    constructor(projectId: string)
    
    verify(jwtString: string): Promise<JwtPayload | string | undefined>
    decode(jwtString: string):Jwt | null
}

