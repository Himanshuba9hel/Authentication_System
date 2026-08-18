import userModel from "../model/user.model.js"
import crypto from "crypto"
import jwt from "jsonwebtoken";
import config from "../config/config.js";
import { decode } from "punycode";

export async function register(req,res){
    const {username, email, password} = req.body;

    const isAlreadyRegistered = await userModel.findOne({
        $or: [
            { username },
            { email }
        ]
    })

    if (isAlreadyRegistered) {
        res.status(409).json({
            message: "Username or email already exists"
        })
    }

    const hashedPassword = crypto.createHash("sha256").update(password).digest("hex");

    const user = await userModel.create({
        username,
        email,
        password: hashedPassword
    });
    const token = jwt.sign(
        { id: user._id }, 
        config.JWT_SECRET,
        { expiresIn: "1d" }
    );
    
    const accessToken = jwt.sign({
        id: user._id
    }, config.JWT_SECRET,
        {
            expiresIn: "15m"
        }
    );

    const refreshToken = jwt.sign({
        id: user._id
    }, config.JWT_SECRET,
        {
            expiresIn: "7d"
        }
    );

    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production", // false for local HTTP, true for HTTPS
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });
    
    res.status(201).json({
        message: "User registered successfully",
        user: {
            username: user.usernamem,
            email: user.email,
        },
        accessToken
    })
    // if(!username || !email || !password){
    //     return res.status(400).json({
    //         success: false,
    //         message: "All fields are required"
    //     })
    // }

}

export async function getMe(req,res){
    const token = req.headers.authorization?.split(" ")[ 1 ];

    if(!token){
        return res.status(401).json({
            message: "token not found"
        });
    }

    const decoded = jwt.verify(token, config.JWT_SECRET);

    const user = await userModel.findById(decoded.id);
    
    res.status(200).json({
        message : "user fetched successfully",
        user : { 
            username:   user.username,
            email: user.email,
        }
    })
}

// export async function refreshToken(req, res) {
//     const refreshToken = req.cookies.refreshToken;

//     if(!refreshToken){
//         return res.status(401).json({
//             message: "Refresh token not found"
//         })
//     }

//     const decode = jwt.verify(refreshToken, config.JWT_SECRET);

//     const accessToken = jwt.sign(
//         { id: decode.id }, 
//         config.JWT_SECRET,
//         { expiresIn: "15m" }
//     );

//     res.status(200).json({
//         message: "Access token refreshed successfully",
//         accessToken
//     })
// }
export async function refreshToken(req, res) {
    // 1. Fixed: Use req.cookies (plural)
    const refreshToken = req.cookies?.refreshToken; 

    if(!refreshToken){
        return res.status(401).json({
            message: "Refresh token not found"
        });
    }

    const newRefreshToken = jwt.sign(
        { id: decode.id },
        config.JWT_SECRET,
        { expiresIn: "7d"}
    );

    res.cookie("refreshToken", newRefreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production", // false for local HTTP, true for HTTPS
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    // 2. Fixed: Add try...catch to handle invalid/expired tokens
    try {
        const decode = jwt.verify(refreshToken, config.JWT_SECRET);

        const accessToken = jwt.sign(
            { id: decode.id }, 
            config.JWT_SECRET,
            { expiresIn: "15m" }
        );

        res.status(200).json({
            message: "Access token refreshed successfully",
            accessToken
        });
    } catch (error) {
        // If the token is expired or tampered with, jwt.verify throws an error
        return res.status(403).json({
            message: "Invalid or expired refresh token"
        });
    }
}