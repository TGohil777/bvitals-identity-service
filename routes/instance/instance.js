const axios = require('axios');
const dataStorageInstance = (token) =>axios.create({
  baseURL: process.env.DATA_STORAGE_URL,
  timeout: 20000,
  headers: {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Authorization' : token
  }
})

module.exports = dataStorageInstance;


