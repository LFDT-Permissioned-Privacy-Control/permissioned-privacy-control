// Subprocess example tests inject HTTP responses through IPC, without opening
// a listening socket or changing the production example/client code.
const pending=new Map();let next=0;
process.on('message',message=>{
  const complete=pending.get(message.id);if(!complete)return;
  pending.delete(message.id);
  complete(new Response(JSON.stringify(message.body??{}),{status:message.status??200,headers:{'content-type':'application/json'}}));
  if(!pending.size)process.channel.unref();
});
process.channel.unref();
globalThis.fetch=(url,init)=>new Promise(resolve=>{
  const id=++next;pending.set(id,resolve);process.channel.ref();
  process.send({id,path:new URL(url).pathname,method:init.method,body:init.body??'',authorization:new Headers(init.headers).get('Authorization')});
});
