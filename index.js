import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt, { hash } from "bcrypt"

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
    await db.query("insert into users (email,password) values ($1,$2)",[email,hash]);
    console.log(hash);
    res.render("login.ejs");
  }
  catch(err){

    console.log("Email already registered");
    res.redirect("/register");
   
  }

    }
  })

  

});

app.post("/login", async (req, res) => {
  const email=req.body.username;
  const loginpassword=req.body.password;
  const result=await db.query("select * from users where email=$1",[email]);
  if(result.rows.length>0){
   const user=result.rows[0];
   const storedHashedPassword=result.rows[0].password;

   bcrypt.compare(loginpassword,storedHashedPassword,(err,result)=>{
    if(err){
      console.log("Error comparing passwords: ",err);
    }
    else{
      if(result){
          res.render("secrets.ejs");
      }
      else{
        res.send("Incorrect Password");
      }
      
    }
  })
   
  


  }
  else{
    res.send("User not found");
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
