
const getauthid = '/api/v1/dataStorage/associated-users'
const dataStorageInstance = require('./instance')
async function getAuth(token,data){
  const authorizedInstance = dataStorageInstance(token);
  authorizedInstance.interceptors.response.use((response) => {
      return response;
    }, function (error) {
      if (error.response.status === 401) {
        return Promise.reject(error.response.data);
      }
    
      if (error.response.status === 400) {
        return Promise.reject(error.response.data);
      }
    });
  return authorizedInstance.get(getauthid,{
    params: {
        id: data
      },
      headers: {
        Authorization: token
      }
  });
}




module.exports ={
  getAuth
}