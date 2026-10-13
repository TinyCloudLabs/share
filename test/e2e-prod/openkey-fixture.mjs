// Mirrors production OpenKey since TC-688: the auth response carries no
// session token, and every signature goes through the sign widget (TC-994).
export function openKeyWidgetHtml(address) {
  return `<!doctype html><meta charset="utf-8"><script>
const target="*";
parent.postMessage({type:"openkey:ready"},target);
addEventListener("message",async(event)=>{
  const data=event.data;
  if(data?.type==="openkey:auth:request"){
    parent.postMessage({type:"openkey:auth:response",success:true,address:${JSON.stringify(address)},keyId:"tinycloud-native-e2e-key",keyType:"MANAGED"},target);
    return;
  }
  if(data?.type==="openkey:sign:request"){
    try{
      const response=await fetch("/sign",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({message:data.message})});
      const signed=await response.json();
      parent.postMessage({type:"openkey:sign:response",success:true,address:${JSON.stringify(address)},signature:signed.signature},target);
    }catch{
      parent.postMessage({type:"openkey:sign:response",success:false,error:{code:"UNKNOWN",message:"fixture signing failed"}},target);
    }
  }
});
</script>`;
}
