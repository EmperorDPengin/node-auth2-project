const jwt = require('jsonwebtoken');
const Users = require('../users/users-model');

const { JWT_SECRET } = require("../secrets"); // use this secret!

const restricted = async (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
    // const token = req.headers.authorization;
  
    // if (token == null) {
    //   next({ status: 401, message: 'token required'})
    //   return;
    // }
  
    // jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
    //   if (err) {
    //     next({ status: 401, message: 'token invalid'});
    //     return;
    //   }
  
    //   req.decodedJwt = decodedToken;
    //   console.log(req.decodedJwt);
    //   next()
    // })
    if (req.headers.authorization == null) {
      next({status: 401, message: "token required!"})
      return;
    }

    try {
      req.decodedJWT = await jwt.verify(req.headers.authorization, JWT_SECRET);
    } catch(err) {
      next({ status: 401, message: "token invalid"})
      return;
    }

    next()

}

const only = role_name => (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */

    if (!req.decodedJWT == null) {
      next({ status: 500, message: "internal server error"});
      return;
    }


    if (req.decodedJWT.role_name != 'admin') {
      next({ status: 403, message: 'this is not for you'})
      return;
    }

    next();

}


const checkUsernameExists = (req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
    const {username} = req.body;

    Users.findBy({username}).first()
        .then( userFound => {
            if (!userFound) {
                next({status: 401, message: 'invalid credentials'})
                return;
            }
            req.body.user = userFound;
            next();
        })
        .catch(next)
}


const validateRoleName = (req, res, next) => {
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */

    
  if (!req.body.role_name || req.body.role_name == null) {
      req.body.role_name = 'student';
      // next();
      // return;
  }

  req.body.role_name = req.body.role_name.trim();

  let role = req.body.role_name;

  console.log(role)

  if (role == "admin") {
    console.log(role)
    next({ status: 422, message: 'Role name can not be admin'});
    return;
  }

  if (role.length > 32) {
    console.log(role)
    next({ status: 422, message: 'can not be longer than 32 chars'});
    return;
  }

  if (role == "") {
    console.log(role)
    role = "student";
    next()
    return;
    
  }

  console.log(role)
  req.body.role_name = role;
  next();
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
