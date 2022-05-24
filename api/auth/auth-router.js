const bc = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Users = require('../users/users-model');

const router = require("express").Router();

const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!

router.post("/register", validateRoleName, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
    try{
      const {username, password, role_name} = req.body;
      const hash = bc.hashSync(password, 8);
      const user = {username, password: hash, role_name};

      let savedUser = await Users.add(user);
      res.status(201).json({message: 'Registered!', savedUser});

    }
    catch(err){
      next(err);
    }
});


router.post("/login", checkUsernameExists, async (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */

    try{
      let {password} = req.body;
      let user = req.body.user;
    
      if(user && bc.compareSync(password, user.password)) {
        res.status(200).json({
          message: `Welcome, ${user.username}`,
          token: generateToken(user)
        })
      } else {
        next({ status: 401, message: 'invalid credentials'})
      }
     }
     catch(err){
      next(err)
     }

    
});

function generateToken(user){
  const payload = {
    subject: user.id,
    username: user.username
  };
  const options = { expiresIn: '1d'};
  return jwt.sign(payload, JWT_SECRET, options);
}

module.exports = router;
