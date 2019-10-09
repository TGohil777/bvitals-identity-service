const express = require('express');
const authRouter = express.Router();
const models = require('../models/index');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

//Verifying the logged in user from the database
authRouter.post("/verify-user", async (req, res) => {
    const {email, password} = req.body;
    try {
        const user = await models.auth.findOne({
            where:{
                email: email
            }
         })
        if (!user) {
            throw new Error(`User with email ${email} not found`);
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            throw new Error(`Invalid password`);   
        }

        const authrole = await models.authrole.findOne({
            where: {
                authid: user.authid
            }
        });

        if (!authrole) {
            throw new Error("Invalid user")
        } 
        const role = await models.role.findOne({
            where: {
                roleid: authrole.roleid
            }
        })

        if (!role) {
            throw new Error("Invalid user")
        }

        const userData = {
            email: user.email,
            role: role.name,
        }

        const token  = await jwt.sign(userData, process.env.SECRET, {
            expiresIn: '1h'
        })
        res.status(200).json({
            message: "User successfully signed in",
            token
        });
    } catch (error) {
        res.status(401).json({
            error: error.message
        });
    }
})

authRouter.post("/change-password", async (req, res) => {  //End point for a user to change their password
    const {email, password, newpassword} = req.body
    try{
        const user = await models.auth.findOne({  //Check for the  email in db
            where: {
                email: email
            }
            });
        if(!user)  
            throw new Error(`User with email ${email} not found`);
        const isMatch = await bcrypt.compare(password, user.password);  //Comparing the associated hashed pwd stored in db
            if (!isMatch) {
                throw new Error(`Invalid password`);   
            }
        const salt = await bcrypt.genSalt(10)     
        const hashedNewPassword = await bcrypt.hash(newpassword, salt);
        const pwd = await models.auth.update({ password:  hashedNewPassword },
            {
                where:{
                    email: email  
                }
            });
        if(pwd){
            res.status(200).json({
            message: "Password changed successfully"})
        }else{
            throw new Error('There was an error while changing the password')
        }
    }catch (error) {
        res.status(401).json({
        error: error.message
        });
    }
})

module.exports = authRouter