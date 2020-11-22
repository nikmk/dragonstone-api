require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwtDecode = require('jwt-decode');
const mongoose = require('mongoose');
const jwt = require('express-jwt')
const dashboardData = require('./data/dashboard');
const User = require('./data/User');
const InventoryItem = require('./data/InventoryItem');
// const paymentRoutes = require('./paymentapi/paymentService');
const paymentData = require('./data/paymentData');
const cookieParser = require('cookie-parser')
const Razorpay = require('razorpay')
const request = require('request')

const instance = new Razorpay({
  key_id: process.env.key_id,
  key_secret: process.env.key_secret
})


const csrf = require('csurf')
const csrfProtection = csrf(
  {
    cookie: true
  }
)


const {
  createToken,
  hashPassword,
  verifyPassword
} = require('./util');



const app = express();



app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser())



app.post('/api/authenticate', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({
      email
    }).lean();

    if (!user) {
      return res.status(403).json({
        message: 'Wrong email or password.'
      });
    }

    const passwordValid = await verifyPassword(
      password,
      user.password
    );

    if (passwordValid) {
      const { password, bio, ...rest } = user;
      const userInfo = Object.assign({}, { ...rest });

      const token = createToken(userInfo);

      const decodedToken = jwtDecode(token);
      const expiresAt = decodedToken.exp;

      res.cookie('token',token,{
        maxAge:10000000,
        httpOnly: true
      })

      res.json({
        message: 'Authentication successful!',
        token,
        userInfo,
        expiresAt
      });
    } else {
      res.status(403).json({
        message: 'Wrong email or password.'
      });
    }
  } catch (err) {
    console.log(err);
    return res
      .status(400)
      .json({ message: 'Something went wrong.' });
  }
});

app.post('/api/signup', async (req, res) => {
  try {
    const { email, firstName, lastName } = req.body;

    const hashedPassword = await hashPassword(
      req.body.password
    );

    const userData = {
      email: email.toLowerCase(),
      firstName,
      lastName,
      password: hashedPassword,
      role: 'user'
    };

    const existingEmail = await User.findOne({
      email: userData.email
    }).lean();

    if (existingEmail) {
      return res
        .status(400)
        .json({ message: 'Email already exists' });
    }

    const newUser = new User(userData);
    const savedUser = await newUser.save();

    if (savedUser) {
      const token = createToken(savedUser);
      const decodedToken = jwtDecode(token);
      const expiresAt = decodedToken.exp;

      const {
        firstName,
        lastName,
        email,
        role
      } = savedUser;

      const userInfo = {
        firstName,
        lastName,
        email,
        role
      };
      res.cookie('token',token,{
        maxAge:10000000,
        httpOnly: true
      })

      return res.json({
        message: 'User created!',
        token,
        userInfo,
        expiresAt
      });
    } else {
      return res.status(400).json({
        message: 'There was a problem creating your account'
      });
    }
  } catch (err) {
    return res.status(400).json({
      message: 'There was a problem creating your account'
    });
  }
});

const attachUser = (req,res,next) => {
  const token = req.cookies.token
  if(!token){
    return res.status(401).json({message:'Authentication invalid'})
  }

  const decodedToken = jwtDecode(token)

  if(!decodedToken){
    return res.status(401).json({message:'There was aproblem authorizing'})
  }else{
    req.user = decodedToken
    next();
  }
}

app.use(attachUser)

const checkJwt = jwt({
  secret: process.env.JWT_SECRET ,
  issue: 'api.dragonstone',
  audience: 'api.dragonstone',
  getToken: req => req.cookies.token
})

app.use(csrfProtection)
app.get('/api/csrf-token',(req,res)=>{
  res.json({csrfToken : req.csrfToken()})
})

// app.use('/api/payment', checkJwt,paymentRoutes)

const requireAdmin = (req,res,next) => {
  const {role} = req.user
  if (role !== 'admin'){
    res.status(401).json({message:"Insufficient role"})
  }
  next();
}

app.get('/api/dashboard-data', checkJwt, (req, res) =>
  {
    //console.log(req.user)
    return res.json(dashboardData)
  }
  
);  

app.patch('/api/user-role', async (req, res) => {
  try {
    const { role } = req.body;
    const allowedRoles = ['user', 'admin'];

    if (!allowedRoles.includes(role)) {
      return res
        .status(400)
        .json({ message: 'Role not allowed' });
    }
    await User.findOneAndUpdate(
      { _id: req.user.sub },
      { role }
    );
    res.json({
      message:
        'User role updated. You must log in again for the changes to take effect.'
    });
  } catch (err) {
    return res.status(400).json({ error: err });
  }
});

app.get('/api/inventory',checkJwt,requireAdmin, async (req, res) => {
  try {
    const { sub } = req.user;
    const inventoryItems = await InventoryItem.find({
      user: sub
    });
    res.json(inventoryItems);
  } catch (err) {
    return res.status(400).json({ error: err });
  }
});

app.post('/api/inventory',checkJwt,requireAdmin, async (req, res) => {
  try {
    const { sub } = req.user
    const input = Object.assign({},req.body,{
      user: sub 
    })
    const inventoryItem = new InventoryItem(input);
    await inventoryItem.save();
    res.status(201).json({
      message: 'Inventory item created!',
      inventoryItem
    });
  } catch (err) {
    console.log(err);
    return res.status(400).json({
      message: 'There was a problem creating the item'
    });
  }
});

app.delete('/api/inventory/:id',checkJwt, requireAdmin,async (req, res) => {
  try {
    const {sub} = req.user
    const deletedItem = await InventoryItem.findOneAndDelete(
      { _id: req.params.id, user: sub  }
    );
    res.status(201).json({
      message: 'Inventory item deleted!',
      deletedItem
    });
  } catch (err) {
    return res.status(400).json({
      message: 'There was a problem deleting the item.'
    });
  }
});

app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find()
      .lean()
      .select('_id firstName lastName avatar bio');

    res.json({
      users
    });
  } catch (err) {
    return res.status(400).json({
      message: 'There was a problem getting the users'
    });
  }
});

app.get('/api/issue', async (req, res) => {
  try {
    const { sub } = req.user;
    const user = await User.findOne({
      _id: sub
    })
      .lean()
      .select('issue');

    res.json({
      issue: user.issue
    });
  } catch (err) {
    return res.status(400).json({
      message: 'There was a problem sending your issue'
    });
  }
});

app.patch('/api/issue', async (req, res) => {
  try {
    const { sub } = req.user;
    const { issue } = req.body;
    const updatedUser = await User.findOneAndUpdate(
      {
        _id: sub
      },
      {
        issue
      },
      {
        new: true
      }
    );

    res.json({
      message: 'Issue Sent!',
      bio: updatedUser.bio
    });
  } catch (err) {
    return res.status(400).json({
      message: 'There was a problem sending your Issue'
    });
  }
});

app.get('/api/paymentdata', async (req, res) => {
  try {
    // const users = await User.find()
    //   .lean()
    //   .select('_id firstName lastName avatar bio');
    const payment = paymentData
    res.json({
      payment
    });
  } catch (err) {
    return res.status(400).json({
      message: 'There was a problem getting payment data'
    });
  }
});


// ------------- Razorpay ------------- //
const orderAmount = []
const orderID = []
app.post('/api/pay',checkJwt,requireAdmin, async (req, res) => {
  try {
    orderAmount.push(req.body.amount)
    const options = {
      amount: orderAmount[0] *100,  // amount in the smallest currency unit
      currency: "INR",
      receipt: "order_rcptid_11",
      payment: {
        capture: "automatic",
        capture_options: {
          automatic_expiry_period : 12,
          manual_expiry_period : 7200,
          refund_speed : "optimum"
        }}
    };
    instance.orders.create(options, function(err, order) {
      orderID.push(order)
      res.json(order)
    });
    
  } catch (err) {
    console.log(err);
    return res.status(400).json({
      message: 'There was a problem creating the item'
    });
  }
});


app.post("/api/capture", async (req, res) => {
  
  try {
    return request(
     {
     method: "POST",
     url: `https://${process.env.key_id}:${process.env.key_secret}@api.razorpay.com/v1/payments/${req.body.paymentId}/capture`,
     form: {
        amount: orderAmount[0] *100, // amount == Rs 10 // Same As Order amount
        currency: "INR" ,
      }, 
    }, 
   async function (err, response, body) {
     if (err) {
      return res.status(500).json({
         message: "Something Went Wrong",
       }); 
     }
      console.log("Status:", response.statusCode);
      console.log("Headers:", JSON.stringify(response.headers));
      console.log("Response:", body);
      return res.status(200).json(body);
    });


   } 
  catch (err) {
    return res.status(500).json({
      message: "Something Went Wrong",
   });
  }
});







// -------------------------------------//

const PORT = process.env.PORT || 3000;

async function connect() {
  try {
    mongoose.Promise = global.Promise;
    await mongoose.connect(process.env.ATLAS_URL, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      useFindAndModify: false
    });
  } catch (err) {
    console.log('Mongoose error', err);
  }
  app.listen(PORT);
  console.log(`API listening on localhost:${PORT}`);
}

connect();
