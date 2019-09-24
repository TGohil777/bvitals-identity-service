const express = require('express');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const uuid = require('node-uuid')
const chalk = require('chalk');
const models = require('./models');
const fs = require('fs');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const cors = require('cors');
const app = express();

morgan.token('id', function getId(req) {
  return req.id;
})

app.use(bodyParser.json());

var corsOptions = {
  origin: '*',
  preflightContinue: true 
};

app.use(cors(corsOptions));

app.use(assignId);

if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

app.use(morgan(':id :method :url :response-time', {
  stream: fs.createWriteStream('./access.log',{flags: 'a'})
}));

function assignId (req, res, next) {
  req.id = uuid.v4()
  next()
}

app.use('/api/v1/identity-service', require('./routes/auth'));

app.use(async (req, res, next) => {
  const token = req.headers['authorization'];
  if (token !== null) {
    req.headers['authorization'] = token;
  }
  next();
});
 
app.use('/api/v1/identity-service', require('./routes/user'));

models.sequelize.sync().then(() => {
  app.listen(process.env.PORT, () => {
    console.log(chalk.green(`Express server listening on port ${process.env.PORT}`));
  });
});