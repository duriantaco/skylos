import express from 'express';
const app=express();
app.get('/profile',(req,res)=>{
process.env.BASE_PATH=req.query.next;res.redirect(process.env.BASE_PATH + '/profile');
});
