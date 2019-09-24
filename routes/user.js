const express = require('express');
const authRouter = express.Router();
const jwt = require('jsonwebtoken')
const models = require('../models');
const bcrypt = require('bcryptjs');


authRouter.get('/current-user', async(req, res) => {
    try{
        const token = req.headers['authorization']
        const currentUser = await jwt.verify(token, process.env.SECRET);
        if (!currentUser) {
            throw new Error();
        }
        res.status(200).json({
            isValid: true
        });
    }catch(err){
        res.status(401).json({
            isValid: false
        });
    }
})

authRouter.post("/edit-user", async (req, res) => {
    try{
        const {email} = req.body
        const user = await models.auth.findOne({
            where: {
             email: email
            }
            });
        if(!user)  
            throw new Error(`User with email ${email} not found`);
           
            const {newfirstname,newlastname,newemail,newroleid,password,authid} = req.body
            const existingEmail = await models.auth.findOne({           //checking if email ID exists in auth table
             where: {
                 email: email
             }
         });
         if(existingEmail){
             const isMatch = await bcrypt.compare(password, existingEmail.password);
             if(isMatch){
                 const changeFirstName = await models.auth.update({
                     firstname  : newfirstname
                 },{
                     where:{
                         email: email 
                     }
                 })
                 const changeLastName = await models.auth.update({
                     lastname  : newlastname
                 },{
                     where:{
                         email: email 
                     }
                 })
                 const changeEmail = await models.auth.update({
                     email  : newemail
                 },{
                     where:{
                         email: email 
                     }
                 })
                 const changeRole = await models.authrole.update({
                     roleid:newroleid
                 },
                 {
                     where:{
                         authid:authid
                     }
                 })
                 if(changeFirstName || changeLastName || changeEmail || changeRole){
                    res.status(200).json({
                        message: "Changes has been saved successfully"})
                    }
                 else{
                     throw new Error(`There was an error while making an update, please try again later`)
                 }
             }else{
                throw new Error(`The entered password is invalid, please enter a valid password`) 
             }
         }   
    }catch (error) {
        res.status(401).json({
        error: error.message
        });
    }
})

authRouter.post("/delete-user", async (req, res) => {  //Deleting an existing user in db
    const {email} = req.body
    try{
        const user = await models.auth.findOne({
            where: {
                email: email
            }
        });
        if(!user)  
            throw new Error(`User with email ${email} not found`);
        
            const deleteUser = await models.auth.update({
                deleted:  true
            },
                {
                where:{
                    email: email  
                }
            })
        if(deleteUser){
            res.status(200).json({
            message: "User successfully deleted"})
        }else{
            throw new Error('There was an error while deleting')
        }
    }catch (error) {
        res.status(401).json({
        error: error.message
        });
    }
})

authRouter.post("/create-ClinicalAdmin", async (req, res) => {    //Create a new Clinical Admin when  a superAdmin logs-in    
    try{
        const {newUserFirstName, newUserLastName, newUserEmail, newUserPassword, email} = req.body
        const salt = await bcrypt.genSalt(10)     //else part
        const hashedPassword = await bcrypt.hash(newUserPassword, salt);
        const superAdmin = await models.auth.findOne({  
            where: {
                email: email
            }
            });
        if(!superAdmin)  
            throw new Error(`User with email ${email} not found`); 

            const existingEmail = await models.auth.findOne({           //checking if email ID exists in auth table
                where: {
                    email: newUserEmail
                }
            });
            if (existingEmail) {
                    throw new Error(`User with email ${newUserEmail} already exists`)
            }
            else{
                const added = await models.auth.create({
                    firstname: newUserFirstName,
                    lastname: newUserLastName,
                    email: newUserEmail,
                    password: hashedPassword
                });
                const roleAdded = await models.authrole.create({   //Associating auth and role table
                    authid: added.authid,
                    roleid: 10002
                });
                if(added && roleAdded){
                    res.status(200).json({
                        message: "User added successfully"})     
                } 
            }        
    }catch (error) {
        res.status(401).json({
        error: error.message
        });
    }
})

module.exports=authRouter