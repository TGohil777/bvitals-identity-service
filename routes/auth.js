const express = require('express');
const authRouter = express.Router();
const {changePassword} = require ('./components/auth');
const {changepwdvalidate} = require('./validations/changePasswordvaidation');
const models = require('../models/index');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

authRouter.post("/verify-user", async (req, res) => {
    const {email, password} = req.body;
    try {
        const user = await models.auth.findOne({
            where: {
                email: email
            }
        });
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
            role: role.name
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

authRouter.post("/change-password", async (req, res) => {
    const {errors, isValid} = changepwdvalidate(req.body)
    if (!isValid) {
        res.status(400).json(errors)
    } else {
        try {
            const {errors, data} = await changePassword(req.body);
            if (isEmpty(errors)) {
                res.status(200).json(data)
            }else{
                res.status(401).json(errors)
            }
        } catch(err) {
            res.status(401).json({
                message: err.message 
            })
        }
    }
})

module.exports = authRouter