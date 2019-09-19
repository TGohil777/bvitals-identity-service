const express = require('express');
const authRouter = express.Router();
//const {creatingClinicalAdmin} = require ('./components/user')
const {editUser} = require ('./components/user')
const {deleteUser} = require('./components/user')
const {validation} = require('./validations/createUserValidation')
const isEmpty = require ('./validations/isEmpty')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs');
const models = require('../models');
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
authRouter.post("/create-clinicaladmin", async (req, res) => {
    const {errors, isValid} = validation(req.body)
    if(!isValid){
        return res.status(400).json(errors)
    } else {
        try{
      

            const {firstname, lastname, email, password} = req.body;
      
            const user = await models.auth.findOne({
                where: {
                    email: email
                }
            })
      
            if (user) throw new Error(`User with email ${email} already exists`);
      
            const salt  = await bcrypt.genSalt(10);
      
            const hashedPassword = await bcrypt.hash(password, salt);
      
            if (!hashedPassword) throw new Error("Unable to hash password");
      
            const addedUser = await models.auth.create({
                firstname,
                lastname,
                email,
                password: hashedPassword
            })
      
      
            if (!addedUser) throw new Error("Unable to add user");
            const role = await models.role.findOne({
                where: {
                    name: 'ClinicalAdmin'
                }
            });
      
      
            if (!role) throw new Error("No role found");
            const addAuthrole = await models.authrole.create({
              authid: addedUser.authid,
              roleid: role.roleid
            });
      
            if (!addAuthrole) throw new Error("Unable to add Auth role");
      
            res.status(200).json({
                message: "User added successfully",
                user: addedUser
            });
        
          }catch(err){
              res.status(400).json({
                  message: err.message
              });
          }
    }
})
authRouter.post("/edit-user", async (req, res) => {
    const {errors, data} = await editUser(req);
    if (!isEmpty(errors)) {
        return res.status(401).send(errors)
    } else if (errors.message) {
        return res.status(401).send(errors)
    } else { 
            return res.status(200).send(data)
    }
})
authRouter.post("/delete-user", async (req, res) => {
    const {errors, data} = await deleteUser(req);
    if (!isEmpty(errors)) {
        return res.status(401).send(errors)
    } else if (errors.message) {
        return res.status(401).send(errors)
    } else {
        return res.status(200).send(data)
    }
})

authRouter.post("/create-user", async (req, res) => {
    try{
      const {errors, isValid} = await validation(req.body)
      if(!isValid){
          return res.status(400).json(errors)
      }else{
          const {errors, data} = await editUser(req.body);
          if (isEmpty(errors)) {
              return res.status(200).json(data)
          }else{
              res.status(401).json(errors)
          }
      }   
    }catch(err){
      return res.status(400).json({
          message: err.message 
      })
    }
})


module.exports=authRouter