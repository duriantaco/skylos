import express from 'express';
const app=express();
app.get('/profile',(req,res)=>{
res.redirect(process.env.BASE_PATH + '/profile');
});
