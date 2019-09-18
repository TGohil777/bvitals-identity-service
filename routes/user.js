const express = require('express');
const authRouter = express.Router();
const {creatingClininalAdmin} = require ('./components/user')
const {editUser} = require ('./components/user')
const {deleteUser} = require('./components/user')
const {validation} = require('./validations/createUserValidation')
const isEmpty = require ('./validations/isEmpty')
const jwt = require('jsonwebtoken')
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
authRouter.post("/create-ClinicalAdmin", async (req, res) => {
    try{
      const {errors, isValid} = await validation(req.body)
      if(!isValid){
          return res.status(400).json(errors)
      }else{
          const {errors, data} = await creatingClininalAdmin(req.body);
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