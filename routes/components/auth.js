const models = require('../../models');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const urlEncoded = bodyParser.urlencoded({
    extended: true
});
const jwt = require('jsonwebtoken');
const changePassword = ( urlEncoded, async  (requestData) => {   //End point to change password of the user
    let data = {};
    let errors = {};
    const {email, password, newpassword} = requestData;
    try{
        const user = await models.auth.findOne({
            where: {
                email: email
            }
        });
        if (user) {
            const isMatch = await bcrypt.compare(password, user.password);
            if (isMatch){
                const salt = await bcrypt.genSalt(10)     
                const hashedNewPassword = await bcrypt.hash(newpassword, salt);
                const pwd = await models.auth.update({
                    password:  hashedNewPassword
                    },
                    {
                        where:{
                            email: email  
                        }
                    })
                if(pwd){
                    data.message = "Password changed sucessfully"
                }
            }else{
                errors.message ="Please enter your old pssword"  
            }
        }else{
            errors.message ="Please enter a valid Email iD"
        }
    }catch(err){
        errors.message = err.message
    }
return {
    data,
    errors
}
})
module.exports ={
    changePassword
}
