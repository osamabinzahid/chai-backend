import {ApiError} from "../utils/ApiError";
import {asyncHandler} from "../utils/asyncHandler";
import jwt from "jsonwebtoken";
import {User} from "../models/user.model";

export const verifyJWT = asyncHandler(async(req, res, next) =>{
    
    try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("bearer ", "")
    
        if(!token){
            throw new ApiError(401, "Unauthorized")
        }
    
        const decodedToken = jwt.verfy(token, process.env.ACCESS_TOKEN_SECRET)
    
        const user = await User.findById(decodedToken?._id).select("-password -generateRefreshToken")
    
        if (!user) {
            // NEXT_VIDEO: discuss about frontend 
            throw new ApiError(401, "Invalid Access Token")
        }
    
        req.user = user;
        next()
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid Access Token")
    }
})