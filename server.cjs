'use strict';
const http=require('node:http');
const {createHandler}=require('./server/router.cjs');
const server=http.createServer(createHandler());
server.requestTimeout=15000;server.headersTimeout=10000;
const onVercel=process.env.VERCEL==='1' || process.env.VERCEL==='true';
server.listen(Number(process.env.PORT||4173),onVercel?undefined:'127.0.0.1');
