import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt, { hash } from "bcrypt"
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";
import GoogleStrategy from "passport-google-oauth2"



const app = express();
const port = 3000;
const saltRounds=10;
env.config();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
const db=new pg.Client({
 user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,

})
db.connect();
app.use(session({
  secret:process.env.SESSION_SECRET,
  resave:false,
  saveUninitialized:true,
  cookie:{
    maxAge:1000*60*60*24,
  }

}));
app.use(passport.initialize());
app.use(passport.session());


app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  const email=req.body.username;
  const password=req.body.password;
  bcrypt.hash(password,saltRounds,async(err,hash)=>{
    if(err){
      console.log("Error hashing password: ",err);
    }
    else{
      try{    
    const result=await db.query("insert into users (email,password) values ($1,$2) RETURNING *" ,[email,hash]);
    console.log(hash);
    const user=result.rows[0];
    req.login(user,(err)=>{
      console.log(err);
      res.redirect("/secrets")
    });
  }
  catch(err){
 
    console.log("Email already registered");
    res.redirect("/register");
   
  }

    }
  })

  

});

app.get("/secrets",async(req,res)=>{
  if(req.isAuthenticated())
  {
    try{

        const userEmail=req.user.email??req.user.rows[0].email;;
        const result=await db.query("select secret from users where email=$1",[userEmail]);
        const secret=result.rows[0].secret;
        if(secret){
          res.render("secrets.ejs",{secret:secret});
        }
        else {
          res.render("secrets.ejs",{secret:"No secret has been published yet"});
        }
        
    }
    catch(err){
      console.log(err);

    }
  }
  else{
    res.redirect("/login");
  }
  
})

app.get("/auth/google",passport.authenticate("google",{
scope:["profile","email"],
}));

app.get("/auth/google/secrets",passport.authenticate("google",{
  successRedirect:"/secrets",
  failureRedirect:"/login",
}))

app.get("/logout",(req,res)=>{
  req.logout((err)=>{
    if(err) console.log(err);
    res.redirect("/");
  })
})

//get submit form
app.get("/submit",(req,res)=>{
  if(req.isAuthenticated()){
    res.render("submit.ejs");
  }
  else {
    res.redirect("/login");
  }
})
//post secret
app.post("/submit",async(req,res)=>{
  const submittedSecret=req.body.secret;
  const userEmail=req.user.email??req.user.rows[0].email;
  try{
    await db.query("update users set secret=$1 where email=$2",[submittedSecret,userEmail]);

    res.redirect("/secrets");
  }
  catch(err){
    console.log(err);
  }


})


app.post("/login",passport.authenticate("local",{
  successRedirect:"/secrets",
  failureRedirect:"/login",
}));






passport.use("local",new Strategy (async function verify(username,password,cb) {

  const user=await db.query("select * from users where email=$1",[username]);
  if(user.rows.length>0){
   
   const storedHashedPassword=user.rows[0].password;

   bcrypt.compare(password,storedHashedPassword,(err,result)=>{
    if(err){
      console.log("Error comparing passwords: ",err);
    }
    else{
      if(result){
          cb(null,user);
      }
      else{
        cb(null,false);
      }
      
    }
  })
   
  


  }
  else{
    return cb("user not found");
  }

}))

passport.use("google",new GoogleStrategy({
clientID:process.env.GOOGLE_CLIENT_ID,
clientSecret:process.env.GOOGLE_CLIENT_SECRET,
callbackURL:"http://localhost:3000/auth/google/secrets",
userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo",

},async(accesToken,refreshToken,profile,cb)=>{
  console.log(profile);
  try{
    const result=await db.query("select * from users where email=$1",[profile.email]);
    if(result.rows.length==0){
      const newUser=await db.query("insert into users (email,password) values ($1,$2) RETURNING *",[profile.email,"google"])
     return cb(null,newUser.rows[0]);
    }
    else {
     return cb(null,result.rows[0]);
    }
    

  }catch (err){
    return cb(err);

  }

}))


passport.serializeUser((user,cb)=>{
  cb(null,user);
})

passport.deserializeUser((user,cb)=>{
  cb(null,user);
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
