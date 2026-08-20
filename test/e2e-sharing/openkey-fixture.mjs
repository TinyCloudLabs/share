export const OPENKEY_TEST_SESSION_TOKEN = "tinycloud-sharing-e2e-session";

export function openKeyWidgetHtml(address) {
  return `<!doctype html><meta charset="utf-8"><script>
const target="*";
parent.postMessage({type:"openkey:ready"},target);
addEventListener("message",async(event)=>{
  const data=event.data;
  if(data?.type==="openkey:auth:request"){
    parent.postMessage({type:"openkey:auth:response",success:true,address:${JSON.stringify(address)},keyId:"tinycloud-e2e-key",keyType:"MANAGED",sessionToken:${JSON.stringify(OPENKEY_TEST_SESSION_TOKEN)}},target);
    return;
  }
  if(data?.type==="openkey:sign:request"){
    try{
      const response=await fetch("/sign",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({message:data.message})});
      const signed=await response.json();
      parent.postMessage({type:"openkey:sign:response",success:true,address:${JSON.stringify(address)},signature:signed.signature},target);
    }catch(error){
      parent.postMessage({type:"openkey:sign:response",success:false,error:{code:"UNKNOWN",message:"fixture signing failed"}},target);
    }
  }
});
</script>`;
}

export function openKeyApiCors(origin) {
  if (origin !== "https://share.tinycloud.xyz" && !/^http:\/\/127\.0\.0\.1(?::\d+)?$/.test(origin ?? "")) return {};
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-headers": "authorization, content-type, x-forwarded-proto",
    vary: "Origin",
  };
}
