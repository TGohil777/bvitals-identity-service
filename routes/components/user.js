const models = require('../../models');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const urlEncoded = bodyParser.urlencoded({
    extended: true
});

const creatingClinicalAdmin = (async (requestData) => {
let data ={}
let errors ={}
    try {
    const {firstname, lastname, password, email, roleid } = requestData
    const salt = await bcrypt.genSalt(10)     
    const hashedPassword = await bcrypt.hash(password, salt);
    const existingEmail = await models.auth.findOne({           //checking if email ID exists in auth table
        where: {
            email: email
        }
    });
    if (existingEmail) {
            errors.message = "User with email already exists"
    } else{
        const added = await models.auth.create({       //Adding a new record in auth table
            firstname,
            lastname,
            email,
            password: hashedPassword
        });
        
        const roleAdded = await models.authrole.create({   //Associating auth and role table
            authid: added.authid,
            roleid: 1002
        });
        if(added && roleAdded){
            data.message = "User succesfully added"
        }
    }
}catch (err) {                                               
         errors.message = err.message
}
    return {
        errors,
        data
    }
})

const editUser = async (req) =>{
    let errors ={}
    let data= {}
   try{
       const {newfirstname,newlastname,newemail,newroleid,email,password,authid} = req.body
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
            const changeLastname = await models.auth.update({
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
            if(changeFirstName || changeLastname || changeEmail || changeRole){
                data = "Changes have been saved sucessfully"
            }
            else{
                data ="There was an error while making an update, please try again later"
            }
        }else{
            errors.message ="The entered password is invalid, please enter a valid password"
        }
    } else{
        errors.message ="The entered email does not exist, please enter a valid Email ID"
    }

   }catch(err){
       errors.message = err.message
   }
   return{
       data, 
       errors
   } 
}

const deleteUser = async (req) =>{
    let data = {}
    let errors = {}
    const {authid} = req.body
        try{
            const user = await models.auth.findOne({  //finding orgID from organization table to delete it
                authid: authid
            })
            if(user){
                const deleted = await models.auth.update({
                    deleted: true},
                    {
                        where:{
                            authid: authid
                        }
                })
                if(deleted){
                    data ="User deleted sucessfully"
                }
            }
    }catch(err){
    errors.message = err.message
    }
    return {
        data,
        errors
    }    
}



module.exports = {
    editUser,
    deleteUser,
}

