const jwt = require('jsonwebtoken')
const { JWT_SECRET } = require("../secrets"); // use this secret!
const User = require("../users/users-model")

const restricted = (req, res, next) => {
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
 const token = req.headers.authorization
 if (!token) {
   return next({ status: 401, message: 'Token required!'})
 }
 jwt.verify(token, JWT_SECRET, (err, decoded) => {
   if (err) {
     next({ status: 401, message: "Token invalid"})
   } else {
     req.decodedJwt = decoded
     next() 
   }
 })
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
  if (req.decodedJwt !== role_name) {
    return next({ status: 403, message: 'This is not for you'})
  } else {
    next() 
  }
}


const checkUsernameExists = (req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
    const userWithUsername = User.findBy({username: req.body.username})
    const {user_id, username, role_name } = userWithUsername
    if (user_id === undefined) {
      return next({ status: 401, message: 'Invalid credentials'})
    } else {
      req.user = {user_id, username, role_name }
      next() 
    }
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
    const {role_name } = req.body
    if (role_name.trim().toLowerCase() === 'admin') {
      return next({ status: 422, message: 'Role name can not be admin'})
    }
    if (role_name.length > 32) {
      return next({ status: 422, message: 'Role name can not be longer than 32 char'})
    } else {
      next()
    }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
