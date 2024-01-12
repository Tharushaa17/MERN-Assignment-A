import User from "../models/user.model.js";
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { errorHandler } from '../utils/errorhandler.js'

export const singup = async (req, res, next ) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) return res.status(400).json({ message: 'Username and password are required.', success: false });

    const existingUser = await User.findOne({ $or: [{ username }, { email }] });

    if (existingUser) return res.status(400).json({ message: 'Username or email already exists', success: false });

    try {
        const hashedPasssword = bcrypt.hashSync(password, 10);
        const newUser = new User({
           username, 
           email, 
           hashedPasssword,
           roles: 2001
        });
        await newUser.save();

        const { password: pass, ...rest } = newUser._doc;
        res.status(201).json({ message: 'User Created Successfully!', user: rest });
    } catch (error) {
        next(error);
    }
}

export const signin = async (req, res, next) => {
  const { username, password } = req.body;

  if (!username || !password) return next({ status: 400, message: 'Username and password are required.' });

  try {
    const validUser = await User.findOne({ username });  

    if (!validUser) return next({ status: 404, message: 'User not found!' });
    
    const validPassword = bcrypt.compareSync(password, validUser.password);
    if (!validPassword) return next({ status: 401, message: 'Wrong credentials!' });
    
    if(validPassword){
      const { username, roles } = validUser;
     
      const accessToken = jwt.sign(
        { 
          "UserInfo": {
            username,
            roles,
        }
      }, 
      process.env.ACCESS_TOKEN_SECRET, 
      { expiresIn: '30s' }
      );
      
      const refreshToken = jwt.sign(
        { "username": validUser.username, "roles": validUser.roles },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: '1d' }
        );
  
      res.cookie('token', refreshToken, {
        httpOnly: true,
        sameSite: 'None', 
        secure: true, 
        maxAge: 24 * 60 * 60 * 1000
      });
  
      res.json({ accessToken, roles, username });
    }
  } catch (error) {
    next(error);
  }
};

const refresh = (req, res) => {
  const cookies = req.cookies

  if (!cookies?.jwt) return res.status(401).json({ message: 'Unauthorized' })

  const refreshToken = cookies.jwt

  jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET,
      asyncHandler(async (err, decoded) => {
          if (err) return res.status(403).json({ message: 'Forbidden' })

          const foundUser = await User.findOne({ username: decoded.username }).exec()

          if (!foundUser) return res.status(401).json({ message: 'Unauthorized' })

          const accessToken = jwt.sign(
              {
                  "UserInfo": {
                      "username": foundUser.username,
                      "roles": foundUser.roles
                  }
              },
              process.env.ACCESS_TOKEN_SECRET,
              { expiresIn: '15m' }
          )

          res.json({ accessToken })
      })
  )
}

export const singOut = async (req, res, next) => {
    try {
        res.clearCookie('access_token');
        res.status(200).json({ message:'User has been Logged Out!' });
    } catch (error) {
        next(error)
    }
}