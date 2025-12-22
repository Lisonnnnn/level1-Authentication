import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt, { hash } from "bcrypt"
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";


const app = express();
const port = 3000;
const saltRounds=10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
const db=new pg.Client({
  user:"postgres",
  host:"localhost",
  database:"secrets",
  password:"1435840",
  port:5432,

})
db.connect();
app.use(session({
  secret:"TOPSECRETWORD",
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

app.post("/login",passport.authenticate("local",{
  successRedirect:"/secrets",
  failureRedirect:"/login",
}));


app.get("/secrets",(req,res)=>{
  if(req.isAuthenticated())
  {
    res.render("secrets.ejs");
  }
  else{
    res.redirect("/login");
  }
  
})



passport.use(new Strategy (async function verify(username,password,cb) {

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

passport.serializeUser((user,cb)=>{
  cb(null,user);
})

passport.deserializeUser((user,cb)=>{
  cb(null,user);
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
