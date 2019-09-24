const express = require('express');
const authRouter = express.Router();
const jwt = require('jsonwebtoken')
const models = require('../models');
const bcrypt = require('bcryptjs');
const {getAuth} = require('./instance/authid')

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
//---------------------------------------------------------------------------------------------------------------------
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
//-----------------------------------------------------------------------------------------------------------------
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
//------------------------------------------------------------------------------------------------------------------------
authRouter.post("/create-ClinicalAdmin", async (req, res) => {    //Create a new Clinical Admin when  a superAdmin logs-in    
    try{
        const {newUserFirstName, newUserLastName, newUserEmail, newUserPassword, email} = req.body
        const salt = await bcrypt.genSalt(10)     //else part
        const hashedPassword = await bcrypt.hash(newUserPassword, salt);
        // const superAdmin = await models.auth.findOne({  
        //     where: {
        //         email: email
        //     }
        //     });
        // if(!superAdmin)  
        //     throw new Error(`User with email ${email} not found`); 

            const existingEmail = await models.auth.findOne({         //checking if email ID exists in auth table
                where: {
                    email: newUserEmail
                }
            });
            if (existingEmail) {
                    throw new Error(`User with email ${newUserEmail} already exists`)
            }
            else{                                        //if the user email does noot exist creating a new user
                const added = await models.auth.create({
                    firstname: newUserFirstName,
                    lastname: newUserLastName,
                    email: newUserEmail,
                    password: hashedPassword
                });
                const roleAdded = await models.authrole.create({   //Associating auth and role table with authid
                    authid: added.authid,
                    roleid: 10002
                });
                if(added && roleAdded){
                    res.status(200).json({
                        message: "User added successfully",
                        user:added
                })     
                } 
            }        
    }catch (error) {
        res.status(401).json({
        error: error.message
        });
    }
})
//----------------------------------------------------------------------------------------------------------------------

authRouter.route('/associated-users').get(async (req, res) => {
    const token = req.headers['authorization'];
    const {id} = req.query

    try{
        if (!token){throw new Error('User is unauthorized')  }
        else{
            const response = await getAuth(token, id)
            
            const auth = response.data;            
            const users = auth.map(async (authids) => {
                const ids = authids['authid']
                return models.role.findOne({
                    attributes:['name'],
                    include:[{
                        model:models.auth, as: 'users',
                        where:{
                            authid:ids
                        },
                        attributes:['firstname','lastname','email']
                    }]
                });
            });
            Promise.all(users).then(values => res.status(200).json(values));
            if(!response) throw new Error('There was an error while displaying the list!')
        }   
    }catch(err){
        return res.status(400).json({
            message : err.message
        })
    }
});


module.exports=authRouter