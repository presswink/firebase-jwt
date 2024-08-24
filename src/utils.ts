import axios from "axios"

export interface IUtils {
    getProjectUrl(projectId: string): string
    getPublicKey(keyId: string): Promise<string>
}

class Utils implements IUtils {
    getProjectUrl(projectId: string): string{
        return `https://securetoken.google.com/${projectId}`
    }

    async getPublicKey(keyId: string): Promise<string> {
        const result = await axios.get("https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com", {headers: {"Content-Type": "application/json"}})
        if(result.data){
            const publicKey = result.data[keyId]
            if(publicKey){
                return publicKey
            }else {
                throw new Error("invalid jwt !")
            }
        }else {
            throw new Error("unable to featch public key certificate !")
        }
    }
}

const utils = new Utils()

export default utils

