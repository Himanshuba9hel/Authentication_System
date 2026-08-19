import userModel from "../model/user.model.js"
import crypto from "crypto"
import jwt from "jsonwebtoken";
import config from "../config/config.js";
import { decode } from "punycode";
import sessionModel  from "../model/session.model.js";

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
    
    const refreshToken = jwt.sign({
        id: user._id
    }, config.JWT_SECRET,
        {
            expiresIn: "7d"
        }
    );

    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

    const session = await sessionModel.create({
        user: user._id,
        refreshTokenHash,
        ip: req.ip,
        userAgent: req.headers[ "user-agent"]
    });
    
    const accessToken = jwt.sign({
        id: user._id,
        sessionId: session._id,
    }, config.JWT_SECRET,
        {
            expiresIn: "15m"
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
            username: user.username, // Fixed!
            email: user.email,
        },
        accessToken
    })

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

export async function refreshToken(req, res) {
    const refreshToken = req.cookies?.refreshToken; 

    if(!refreshToken){
        return res.status(401).json({
            message: "Refresh token not found"
        });
    }

    try {
        // 1. Verify the old token FIRST
        const decode = jwt.verify(refreshToken, config.JWT_SECRET);

        // 2. NOW you can safely use decode.id to make the new refresh token
        const newRefreshToken = jwt.sign(
            { id: decode.id },
            config.JWT_SECRET,
            { expiresIn: "7d"}
        );

        // 3. Set the new cookie
        res.cookie("refreshToken", newRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        // 4. Generate the new access token
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
        // If the old token is expired or invalid, this catches the error
        return res.status(403).json({
            message: "Invalid or expired refresh token"
        });
    }
}